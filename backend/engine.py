"""
engine.py — Core zero-trust policy engine for the IAM Policy Engine Dashboard.

Responsibilities
----------------
1. Ingest CloudTrail / EventBridge detail payloads and extract the identity,
   the API action executed, and its resource hints.
2. Normalize action names into AWS ARN-compliant `service:Action` pairs.
3. Build a *least-privilege* IAM policy scoped strictly to the actions that
   were actually observed (i.e. `s3:*` -> `s3:ListBuckets`, `s3:GetObject`).
4. Validate the candidate policy using the IAM Policy Simulator
   (`simulate_custom_policy`) before it is ever applied.
5. Apply remediation via `put_role_policy` (and detach a matching
   over-privileged managed policy when one is identified).
6. Expose `create_boto_session()` so the FastAPI layer can resolve real AWS
   account metadata for the dashboard header.

Design note
-----------
Every AWS call is wrapped so a missing/invalid credential set degrades to an
explicit "unavailable" state instead of crashing the dashboard. The calling
identity needs `iam:SimulateCustomPolicy`, `iam:SimulatePrincipalPolicy`,
`iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:GetRolePolicy`,
`iam:PutRolePolicy`, `iam:DetachRolePolicy` for full functionality.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
import botocore.exceptions

log = logging.getLogger("zt-engine")

# AWS service namespace -> console name used for dashboard labels.
SERVICE_LABELS: Dict[str, str] = {
    "s3": "S3",
    "iam": "IAM",
    "ec2": "EC2",
    "sts": "STS",
    "lambda": "Lambda",
    "dynamodb": "DynamoDB",
    "logs": "CloudWatch Logs",
    "cloudtrail": "CloudTrail",
    "kms": "KMS",
    "sns": "SNS",
    "sqs": "SQS",
    "ssm": "SSM",
    "secretsmanager": "Secrets Manager",
    "rds": "RDS",
    "cloudwatch": "CloudWatch",
    "events": "EventBridge",
}

# Verbs that read data without mutating anything (used for the risk note).
READ_VERBS = {
    "get", "list", "describe", "head", "batchget",
    "query", "scan", "lookup", "read", "search",
}

# Action -> resource ARN patterns for the well-known services the demo
# payloads exercise. Keys are lower-case `service:action`. `%s` is
# substituted with the observed bare resource name (bucket, table, ...).
ACTION_RESOURCE_HINTS: Dict[str, List[str]] = {
    "s3:listbuckets": ["arn:aws:s3:::*"],
    "s3:listbucket": ["arn:aws:s3:::%s", "arn:aws:s3:::*"],
    "s3:getobject": ["arn:aws:s3:::%s/*"],
    "s3:putobject": ["arn:aws:s3:::%s/*"],
    "s3:deleteobject": ["arn:aws:s3:::%s/*"],
    "dynamodb:getitem": ["arn:aws:dynamodb:*:*:table/%s"],
    "dynamodb:putitem": ["arn:aws:dynamodb:*:*:table/%s"],
    "dynamodb:query": ["arn:aws:dynamodb:*:*:table/%s"],
    "dynamodb:scan": ["arn:aws:dynamodb:*:*:table/%s"],
    "lambda:invokefunction": ["arn:aws:lambda:*:*:function:%s"],
    "lambda:getfunction": ["arn:aws:lambda:*:*:function:%s"],
    "logs:filterlogevents": ["arn:aws:logs:*:*:log-group:%s"],
    "logs:getlogevents": ["arn:aws:logs:*:*:log-group:%s"],
    "sns:publish": ["arn:aws:sns:*:*:%s"],
    "sqs:sendmessage": ["arn:aws:sqs:*:*:%s"],
    "kms:decrypt": ["arn:aws:kms:*:*:key/*"],
    "ssm:getparameter": ["arn:aws:ssm:*:*:parameter/%s"],
    "secretsmanager:getsecretvalue": ["arn:aws:secretsmanager:*:*:secret:%s"],
    "sts:assumerole": ["arn:aws:iam::*:role/%s"],
    "iam:listroles": ["*"],
    "iam:getrole": ["arn:aws:iam::*:role/%s"],
    "ec2:describeinstances": ["*"],
    "ec2:startinstances": ["arn:aws:ec2:*:*:instance/%s"],
    "ec2:runinstances": ["*"],
}


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def normalize_action(raw: str) -> Tuple[str, str]:
    """Split `raw` into (service, action); tolerant of a missing colon."""
    if not raw or not isinstance(raw, str):
        return ("unknown", "UnknownAction")
    if ":" in raw:
        svc, act = raw.split(":", 1)
    else:
        svc, act = "unknown", raw
    return (svc.strip().lower(), act.strip())


def service_label(service: str) -> str:
    return SERVICE_LABELS.get((service or "").lower(), (service or "unknown").upper())


def is_read_only(service: str, action: str) -> bool:
    verbs = READ_VERBS | ({"head"} if service == "s3" else set())
    return action.lower().startswith(tuple(verbs))


def action_resource_patterns(service: str, action: str, observed_resource: Optional[str]) -> List[str]:
    """Return plausible ARN resource patterns for a `service:action` pair."""
    key = f"{service}:{action}".lower()
    hints = ACTION_RESOURCE_HINTS.get(key)
    if hints:
        out: List[str] = []
        for h in hints:
            if "%s" in h and observed_resource:
                out.append(h % observed_resource)
            elif "%s" not in h:
                out.append(h)
        if out:
            return out
    if observed_resource and observed_resource.startswith("arn:"):
        return [observed_resource]
    return ["*"]


def _first_arn_resource(detail: Dict[str, Any]) -> Optional[str]:
    """Best-effort extraction of a target resource from CloudTrail
    requestParameters (`bucketName`, `roleArn`, `tableName`, ...)."""
    params = detail.get("requestParameters") or {}
    bare_keys = {"bucketName", "tableName", "functionName", "logGroupName",
                 "roleName", "instanceId", "parameterName", "topicName", "queueName"}
    for key in ("bucketName", "roleArn", "roleName", "tableName", "functionName",
                "resourceArn", "logGroupName", "secretId", "parameterName",
                "topicArn", "queueUrl", "keyId", "instanceId"):
        val = params.get(key)
        if isinstance(val, str) and val:
            if key in bare_keys and not val.startswith("arn:"):
                return val  # bare name; ARN patterns add the wrapper
            return val
    return None


def aws_error_code(exc: Exception) -> str:
    """Short AWS error code (AccessDenied, NoCredentialsError, ...)."""
    if isinstance(exc, botocore.exceptions.ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    if isinstance(exc, botocore.exceptions.NoCredentialsError):
        return "NoCredentialsError"
    if isinstance(exc, botocore.exceptions.PartialCredentialsError):
        return "PartialCredentialsError"
    return type(exc).__name__


def normalise_exc(exc: Exception) -> str:
    return f"{aws_error_code(exc)}: {exc}"


# ---------------------------------------------------------------------------
# AWS session / account helpers
# ---------------------------------------------------------------------------
def create_boto_session(region: Optional[str] = None) -> Optional[boto3.Session]:
    """Build a boto3 session from the ambient AWS CLI credential chain.

    Returns None when no resolvable credentials exist so callers can render an
    'AWS UNAVAILABLE' badge instead of raising.
    """
    try:
        region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        session = boto3.Session(region_name=region)
        creds = session.get_credentials()
        if creds is None:
            return None
        frozen = creds.get_frozen_credentials()
        if frozen is None or not frozen.access_key:
            return None
        return session
    except Exception as exc:
        log.warning("create_boto_session failed: %s", exc)
        return None


def get_account_identity(session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    """Resolve account id + caller identity via STS."""
    try:
        session = session or create_boto_session()
        if session is None:
            return {"connected": False, "account_id": None, "arn": None, "user_id": None}
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        return {
            "connected": True,
            "account_id": ident.get("Account"),
            "arn": ident.get("Arn"),
            "user_id": ident.get("UserId"),
        }
    except Exception as exc:
        log.warning("get_account_identity failed: %s", exc)
        return {"connected": False, "account_id": None, "arn": None, "user_id": None}


def get_account_alias(session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    """Account alias via iam.list_account_aliases (best-effort)."""
    try:
        session = session or create_boto_session()
        if session is None:
            return {"alias": None}
        resp = session.client("iam").list_account_aliases()
        aliases = resp.get("AccountAliases") or []
        return {"alias": aliases[0] if aliases else None}
    except Exception as exc:
        log.debug("get_account_alias failed: %s", exc)
        return {"alias": None}


# ---------------------------------------------------------------------------
# CloudTrail / EventBridge ingestion
# ---------------------------------------------------------------------------
def parse_cloudtrail_event(detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse a CloudTrail `detail` block (as delivered by EventBridge) into the
    normalized structure the engine + dashboard consume.

    Returns None when the payload does not look like an event we can act on.
    """
    if not isinstance(detail, dict):
        return None

    event_name = detail.get("eventName")
    event_source = detail.get("eventSource")
    if not event_name or not event_source:
        return None

    service, action = normalize_action(event_name)
    svc_from_source = event_source.split(".")[0].lower()
    if service == "unknown" and svc_from_source:
        service = svc_from_source
        action = event_name

    identity_arn = (detail.get("userIdentity") or {}).get("arn") or None
    username = (detail.get("userIdentity") or {}).get("userName") or None
    session_ctx = (detail.get("userIdentity") or {}).get("sessionContext") or {}
    session_issuer = ((session_ctx.get("sessionIssuer") or {}).get("arn")) or None

    role_arn = None
    if session_issuer and ":assumed-role/" in session_issuer:
        # arn:aws:sts::123:assumed-role/MyRole/MySession -> arn:aws:iam::123:role/MyRole
        m = re.match(r"arn:aws:sts::(\d+):assumed-role/([^/]+)", session_issuer)
        if m:
            role_arn = f"arn:aws:iam::{m.group(1)}:role/{m.group(2)}"
    elif identity_arn and ":assumed-role/" in identity_arn:
        m = re.match(r"arn:aws:sts::(\d+):assumed-role/([^/]+)", identity_arn)
        if m:
            role_arn = f"arn:aws:iam::{m.group(1)}:role/{m.group(2)}"
    elif username:
        role_arn = username  # bare user name; resolve_roles() maps to full ARN

    resource = _first_arn_resource(detail)

    return {
        "event_id": detail.get("eventID") or detail.get("eventId") or detail.get("requestID"),
        "event_name": event_name,
        "event_source": event_source,
        "service": service,
        "action": action,
        "role_arn": role_arn,
        "identity_arn": identity_arn,
        "username": username,
        "resource": resource,
        "error_code": detail.get("errorCode"),
        "request_id": detail.get("requestID"),
        "event_time": detail.get("eventTime") or utc_now_iso(),
        "source_ip": detail.get("sourceIPAddress"),
        "region": detail.get("awsRegion"),
        "raw": detail,
    }


# ---------------------------------------------------------------------------
# Current-policy inspection / risk metrics
# ---------------------------------------------------------------------------
def fetch_current_policy(session: boto3.Session, role_arn: str) -> Dict[str, Any]:
    """Collect attached + inline policies for a role and merge their statements.

    Returns {"role_arn", "role_name", "policies": [...], "document": {...},
    "statement_count", "wildcard_actions", "total_actions", "error"}.
    """
    result: Dict[str, Any] = {
        "role_arn": role_arn,
        "role_name": role_arn.split("/")[-1],
        "policies": [],
        "document": {"Version": "2012-10-17", "Statement": []},
        "statement_count": 0,
        "wildcard_actions": 0,
        "total_actions": 0,
        "error": None,
    }
    try:
        iam = session.client("iam")
        role_name = result["role_name"]
        statements: List[Dict[str, Any]] = []

        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        for ap in attached:
            arn, name = ap.get("PolicyArn"), ap.get("PolicyName")
            try:
                ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
                statements.extend(doc.get("Statement", []))
                result["policies"].append({"type": "attached", "name": name, "arn": arn})
            except Exception as exc:
                log.warning("could not read attached policy %s: %s", arn, exc)

        inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        for name in inline:
            try:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
                doc_statements = doc.get("Statement", [])
                if isinstance(doc_statements, dict):
                    doc_statements = [doc_statements]
                statements.extend(doc_statements)
                result["policies"].append({"type": "inline", "name": name, "arn": None})
            except Exception as exc:
                log.warning("could not read inline policy %s: %s", name, exc)

        # URL-decode any aws:SourceArn style encoded values boto returns.
        for st in statements:
            res = st.get("Resource")
            if isinstance(res, str):
                st["Resource"] = res.replace("%3A", ":").replace("%2F", "/")

        result["document"]["Statement"] = statements
        result["statement_count"] = len(statements)

        actions: List[str] = []
        for st in statements:
            if st.get("Effect") == "Allow":
                a = st.get("Action", [])
                actions.extend(a if isinstance(a, list) else [a])
        result["total_actions"] = len(actions)
        result["wildcard_actions"] = sum(1 for a in actions if "*" in a)

        # Identify a candidate managed policy to detach during remediation:
        # prefer an AWS-managed policy with explicit wildcard allowances.
        for ap in attached:
            if str(ap.get("PolicyArn", "")).startswith("arn:aws:iam::aws:policy/"):
                result["candidate_detach_arn"] = ap["PolicyArn"]
                result["candidate_detach_name"] = ap.get("PolicyName")
                break

        return result
    except Exception as exc:
        result["error"] = normalise_exc(exc)
        return result


def compute_risk_score(current: Dict[str, Any]) -> int:
    """0 (safe) .. 100 (critical), weighted on wildcards, admin flags, IAM exposure."""
    try:
        actions: List[str] = []
        for st in current.get("document", {}).get("Statement", []):
            if st.get("Effect") == "Allow":
                a = st.get("Action", [])
                actions.extend(a if isinstance(a, list) else [a])
        if not actions:
            return 0
        score = 0
        if any(a == "*" or a == "*:*" for a in actions):
            score += 60
        score += min(25, 5 * sum(1 for a in actions if "*" in a))
        if any(a.lower().startswith("iam:") for a in actions):
            score += 15
        if any(a.lower() in ("sts:assumerole", "kms:decrypt") for a in actions):
            score += 10
        if any(a.lower().startswith(("s3:put", "s3:delete", "ec2:run", "ec2:start")) for a in actions):
            score += 10
        return max(0, min(100, score))
    except Exception:
        return 0


def compute_wildcard_reduction(current: Dict[str, Any], least: Dict[str, Any]) -> int:
    """% reduction of wildcard actions between current and least-privilege docs."""
    def count(doc: Dict[str, Any]) -> Tuple[int, int]:
        total, wild = 0, 0
        for st in doc.get("Statement", []):
            a = st.get("Action", [])
            for act in (a if isinstance(a, list) else [a]):
                total += 1
                if "*" in act:
                    wild += 1
        return total, wild

    ct, cw = count(current.get("document", {}))
    _, lw = count(least)
    if ct == 0 or cw == 0:
        return 100 if (ct and cw == 0) else 0
    return int(round(100 * (cw - lw) / cw))


# ---------------------------------------------------------------------------
# Least-privilege synthesis
# ---------------------------------------------------------------------------
def build_least_privilege_policy(
    session: boto3.Session,
    role_arn: str,
    observed: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Construct a least-privilege policy document from ONLY the actions that
    were actually observed in CloudTrail events for this role.

    Each observed entry: {"service": "s3", "action": "GetObject",
    "resource": "my-bucket" (optional), "read_only": bool}
    """
    statements: List[Dict[str, Any]] = []
    seen: set = set()

    for obs in observed:
        service = (obs.get("service") or "unknown").lower()
        action = obs.get("action") or "UnknownAction"
        key = f"{service}:{action}".lower()
        if key in seen:
            continue
        seen.add(key)

        # Inject supporting List calls where the simulator/CLI needs them.
        if service == "s3" and not key.startswith("s3:list"):
            extra = "s3:ListBucket" if any(k in key for k in ("getobject", "putobject", "deleteobject")) else None
            if extra and extra.lower() not in seen:
                seen.add(extra.lower())
                statements.append({
                    "Sid": f"ZT{abs(hash(extra)) % 10000:04d}",
                    "Effect": "Allow",
                    "Action": extra,
                    "Resource": action_resource_patterns(service, "ListBucket", obs.get("resource")),
                })

        statements.append({
            "Sid": f"ZT{abs(hash(key)) % 10000:04d}",
            "Effect": "Allow",
            "Action": f"{service}:{action}",
            "Resource": action_resource_patterns(service, action, obs.get("resource")),
        })

    if not statements:
        statements.append({
            "Sid": "ZTNoAccess",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        })

    return {
        "Version": "2012-10-17",
        "Id": "ZeroTrustLeastPrivilege",
        "Statement": statements,
    }


def simulate_custom_policy(
    session: boto3.Session,
    policy_document: Dict[str, Any],
    action_names: List[str],
) -> Dict[str, Any]:
    """Dry-run `policy_document` against `action_names` via the IAM Policy
    Simulator (`simulate_custom_policy`)."""
    iam = session.client("iam")
    try:
        resp = iam.simulate_custom_policy(
            PolicyInputList=[json.dumps(policy_document)],
            ActionNames=action_names,
        )
        evals = resp.get("EvaluationResults", [])
        decisions = {e["EvalActionName"]: e["EvalDecision"] for e in evals}
        allowed = [a for a, d in decisions.items() if d == "allowed"]
        denied = [a for a, d in decisions.items() if d != "allowed"]
        return {
            "valid": len(denied) == 0,
            "allowed": allowed,
            "denied": denied,
            "evaluations": [
                {
                    "action": e["EvalActionName"],
                    "decision": e["EvalDecision"],
                    "matched_resource": (e.get("EvalResourceDecision") or {}).get("EvalResourceName"),
                }
                for e in evals
            ],
            "error": None,
        }
    except Exception as exc:
        return {"valid": False, "allowed": [], "denied": action_names,
                "evaluations": [], "error": normalise_exc(exc)}


def simulate_principal_policy(
    session: boto3.Session,
    principal_arn: str,
    action_names: List[str],
) -> Dict[str, Any]:
    """Check what the *current* attached policies allow for `principal_arn`."""
    iam = session.client("iam")
    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=action_names,
        )
        evals = resp.get("EvaluationResults", [])
        return {
            "allowed": [e["EvalActionName"] for e in evals if e["EvalDecision"] == "allowed"],
            "denied": [e["EvalActionName"] for e in evals if e["EvalDecision"] != "allowed"],
            "evaluations": [
                {"action": e["EvalActionName"], "decision": e["EvalDecision"]} for e in evals
            ],
            "error": None,
        }
    except Exception as exc:
        return {"allowed": [], "denied": action_names, "evaluations": [],
                "error": normalise_exc(exc)}


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------
def apply_remediation(
    session: boto3.Session,
    role_arn: str,
    least_privilege_document: Dict[str, Any],
    detach_arn: Optional[str] = None,
) -> Dict[str, Any]:
    """Enforce zero-trust: attach the new inline policy to the role and detach
    the over-privileged managed policy (when identified and requested)."""
    role_name = role_arn.split("/")[-1]
    iam = session.client("iam")
    policy_name = "ZeroTrustLeastPrivilege"
    steps: List[Dict[str, Any]] = []
    ok = True

    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(least_privilege_document),
        )
        steps.append({"step": "put_role_policy", "status": "ok", "detail": policy_name})
    except Exception as exc:
        ok = False
        steps.append({"step": "put_role_policy", "status": "error", "detail": normalise_exc(exc)})

    if detach_arn:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=detach_arn)
            steps.append({"step": "detach_role_policy", "status": "ok", "detail": detach_arn})
        except Exception as exc:
            ok = False
            steps.append({"step": "detach_role_policy", "status": "error", "detail": normalise_exc(exc)})

    return {"success": ok, "role_arn": role_arn, "policy_name": policy_name, "steps": steps}


# ---------------------------------------------------------------------------
# Role inventory
# ---------------------------------------------------------------------------
def resolve_roles(session: boto3.Session, role_arns_or_names: List[str]) -> List[Dict[str, Any]]:
    """Map a mix of role names / ARNs to full IAM role descriptors."""
    out: List[Dict[str, Any]] = []
    try:
        iam = session.client("iam")
        account_id = get_account_identity(session).get("account_id")
        for item in role_arns_or_names:
            name = item.split("/")[-1] if item.startswith("arn:") else item
            try:
                role = iam.get_role(RoleName=name)["Role"]
                out.append({
                    "role_name": role["RoleName"],
                    "arn": role["Arn"],
                    "account_id": account_id,
                    "description": role.get("Description"),
                })
            except Exception as exc:
                out.append({"role_name": name, "arn": None, "error": normalise_exc(exc)})
    except Exception as exc:
        out.append({"error": normalise_exc(exc)})
    return out


def list_auditable_roles(session: boto3.Session, limit: int = 25) -> List[Dict[str, Any]]:
    """List IAM roles available for auditing (paginated, capped)."""
    try:
        iam = session.client("iam")
        roles: List[Dict[str, Any]] = []
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate(PaginationConfig={"PageSize": limit}):
            for r in page.get("Roles", []):
                roles.append({
                    "role_name": r["RoleName"],
                    "arn": r["Arn"],
                    "path": r.get("Path", "/"),
                    "description": r.get("Description"),
                })
            if len(roles) >= limit:
                break
        return roles[:limit]
    except Exception as exc:
        log.warning("list_auditable_roles failed: %s", exc)
        return []


def match_wildcard(pattern: str, value: str) -> bool:
    """IAM-style wildcard match helper (also used by tests)."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())
