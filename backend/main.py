"""
main.py — FastAPI server for the Zero-Trust IAM Policy Engine Dashboard.

Endpoints
---------
GET  /api/v1/health               -> service + AWS connectivity status
GET  /api/v1/roles                -> auditable IAM roles (?demo=1 for offline seeds)
POST /api/v1/events/ingest        -> accept a CloudTrail detail block OR a full
                                     EventBridge envelope; run the engine, broadcast SSE
POST /api/v1/events/eventbridge   -> explicit EventBridge envelope alias
POST /api/v1/policy/simulate      -> dry-run a candidate policy (simulate_custom_policy)
POST /api/v1/policy/remediate     -> enforce the least-privilege policy (put_role_policy
                                     + optional detach_role_policy)
GET  /api/v1/telemetry/stream     -> Server-Sent Events with live event log lines

Run with:  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from collections import deque
from typing import Any, AsyncGenerator, Deque, Dict, List, Optional, Set, Tuple

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

import engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("zt-api")

START_TIME = time.monotonic()

app = FastAPI(
    title="Zero-Trust IAM Policy Engine",
    version="1.1.0",
    description="CloudTrail -> EventBridge -> IAM Policy Simulator -> Auto-Remediation",
)

# The Vite dev server runs on 5173; allow it plus common variants.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:4173", "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state (single-process demo; swap for Redis in production)
# ---------------------------------------------------------------------------
EVENT_BUFFER_MAX = 200
event_buffer: Deque[Dict[str, Any]] = deque(maxlen=EVENT_BUFFER_MAX)

# (event_loop, queue) pairs — put_nowait must be marshalled onto the SSE
# subscriber's loop because ingestion endpoints run in worker threads.
Subscribers = Set[Tuple[asyncio.AbstractEventLoop, asyncio.Queue]]
event_subscribers: Subscribers = set()

ROLE_SEEDS: List[Dict[str, Any]] = [
    {"role_name": "OverPrivilegedAppRole", "arn": "arn:aws:iam::123456789012:role/OverPrivilegedAppRole", "demo": True},
    {"role_name": "DataPipelineRole", "arn": "arn:aws:iam::123456789012:role/DataPipelineRole", "demo": True},
    {"role_name": "LambdaExecutionRole", "arn": "arn:aws:iam::123456789012:role/LambdaExecutionRole", "demo": True},
]

ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]+$")
ACTION_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9*?_]+$")
MAX_POLICY_BYTES = 10240  # IAM inline policy size limit
MAX_ACTIONS = 50


# ---------------------------------------------------------------------------
# Request models + validation
# ---------------------------------------------------------------------------
class SimulateRequest(BaseModel):
    role_arn: str = Field(..., description="Principal ARN to simulate against")
    policy_document: Dict[str, Any] = Field(..., description="Candidate IAM policy JSON")
    action_names: List[str] = Field(..., min_length=1, description="Actions to test, e.g. ['s3:GetObject']")

    @field_validator("role_arn")
    @classmethod
    def _valid_role_arn(cls, v: str) -> str:
        if not ROLE_ARN_RE.match(v):
            raise ValueError("role_arn must look like arn:aws:iam::<account>:role/<name>")
        return v

    @field_validator("policy_document")
    @classmethod
    def _valid_policy(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if "Statement" not in v:
            raise ValueError("policy_document must contain a 'Statement' key")
        stmt = v["Statement"]
        if not isinstance(stmt, (list, dict)):
            raise ValueError("'Statement' must be a list or a single statement object")
        if len(json.dumps(v)).__gt__(MAX_POLICY_BYTES):
            raise ValueError(f"policy_document exceeds IAM limit of {MAX_POLICY_BYTES} bytes")
        return v

    @field_validator("action_names")
    @classmethod
    def _valid_actions(cls, v: List[str]) -> List[str]:
        if len(v) > MAX_ACTIONS:
            raise ValueError(f"at most {MAX_ACTIONS} action names per request")
        for a in v:
            if not ACTION_NAME_RE.match(a):
                raise ValueError(f"invalid IAM action name: {a!r}")
        return v


class RemediateRequest(BaseModel):
    role_arn: str
    policy_document: Dict[str, Any]
    detach_arn: Optional[str] = Field(default=None, description="Over-privileged managed policy to detach")

    @field_validator("role_arn")
    @classmethod
    def _valid_role_arn(cls, v: str) -> str:
        if not ROLE_ARN_RE.match(v):
            raise ValueError("role_arn must look like arn:aws:iom::<account>:role/<name>")
        return v

    @field_validator("policy_document")
    @classmethod
    def _valid_policy(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if "Statement" not in v:
            raise ValueError("policy_document must contain a 'Statement' key")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _session():
    """Shared boto3 session or None (dashboard shows AWS UNAVAILABLE)."""
    return engine.create_boto_session()


def _unwrap_cloudtrail_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either a bare CloudTrail `detail` block or a full EventBridge
    envelope and return the inner detail block."""
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="Body must be a JSON object.")
    if "detail" in raw and ("detail-type" in raw or "version" in raw or "id" in raw):
        detail = raw.get("detail")
        if not isinstance(detail, dict):
            raise HTTPException(status_code=422, detail="EventBridge envelope 'detail' must be an object.")
        return detail
    if "eventName" in raw and "eventSource" in raw:
        return raw  # bare CloudTrail detail block
    raise HTTPException(
        status_code=422,
        detail="Payload must be a CloudTrail detail block (eventName+eventSource) "
               "or an EventBridge envelope with a 'detail' object.",
    )


def _aws_http_status(error_text: str) -> int:
    """Map an engine error string ('Code: msg') to an HTTP status."""
    code = error_text.split(":", 1)[0].strip()
    return {
        "AccessDenied": 403,
        "AccessDeniedException": 403,
        "UnauthorizedOperation": 403,
        "NoSuchEntity": 404,
        "EntityAlreadyExists": 409,
        "LimitExceeded": 409,
        "Throttling": 429,
        "ThrottlingException": 429,
        "ExpiredToken": 503,
        "ExpiredTokenException": 503,
        "InvalidClientTokenId": 503,
        "NoCredentialsError": 503,
        "PartialCredentialsError": 503,
        "EndpointConnectionError": 503,
        "ConnectTimeoutError": 503,
    }.get(code, 502)


def _fail_if_engine_error(scope: str, err: Optional[str]) -> None:
    """Convert an engine-reported AWS error into a structured HTTP error."""
    if not err:
        return
    raise HTTPException(
        status_code=_aws_http_status(err),
        detail={"scope": scope, "aws_error": err},
    )


def _safe_put(queue: asyncio.Queue, payload: str) -> None:
    try:
        queue.put_nowait(payload)
    except Exception:
        pass  # subscriber vanished between scheduling and delivery


def _broadcast(event: Dict[str, Any]) -> None:
    """Push an event to all SSE subscribers (thread-safe)."""
    event_buffer.append(event)
    payload = json.dumps(event, default=str)
    for loop, q in list(event_subscribers):
        try:
            loop.call_soon_threadsafe(_safe_put, q, payload)
        except RuntimeError:
            event_subscribers.discard((loop, q))  # loop closed


# ---------------------------------------------------------------------------
# Global error handling
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Strip non-serializable ctx objects (e.g. ValueError instances) from errors.
    errors = []
    for e in exc.errors():
        clean = {k: v for k, v in e.items() if k not in ("ctx", "url")}
        errors.append(clean)
    return JSONResponse(
        status_code=422,
        content={"detail": "request validation failed", "errors": errors},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    error_id = uuid.uuid4().hex[:8]
    log.exception("unhandled error id=%s", error_id)
    return JSONResponse(
        status_code=500,
        content={"detail": f"internal error (id={error_id})", "error": type(exc).__name__},
    )


# ---------------------------------------------------------------------------
# Health / inventory
# ---------------------------------------------------------------------------
@app.get("/api/v1/health", summary="Service + AWS connectivity status")
def health() -> Dict[str, Any]:
    session = _session()
    identity = engine.get_account_identity(session) if session else {"connected": False}
    alias = engine.get_account_alias(session) if session else {"alias": None}
    return {
        "status": "ok",
        "aws_connected": bool(identity.get("connected")),
        "account_id": identity.get("account_id"),
        "account_alias": alias.get("alias"),
        "caller_arn": identity.get("arn"),
        "region": os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1",
        "events_buffered": len(event_buffer),
        "stream_subscribers": len(event_subscribers),
        "uptime_seconds": round(time.monotonic() - START_TIME, 1),
    }


@app.get("/api/v1/roles", summary="Auditable IAM roles for this account")
def list_roles(
    limit: int = Query(default=25, ge=1, le=100),
    demo: bool = Query(default=False, description="Return offline demo roles when AWS is unavailable"),
) -> Dict[str, Any]:
    session = _session()
    if session is None:
        if demo:
            return {"roles": ROLE_SEEDS, "count": len(ROLE_SEEDS), "demo": True}
        raise HTTPException(
            status_code=503,
            detail="AWS credentials unavailable — configure AWS CLI (`aws configure`) or call with ?demo=1.",
        )
    roles = engine.list_auditable_roles(session, limit=limit)
    return {"roles": roles, "count": len(roles), "demo": False}


# ---------------------------------------------------------------------------
# Event ingestion (CloudTrail detail block OR EventBridge envelope)
# ---------------------------------------------------------------------------
def _process_ingest(raw: Dict[str, Any], source: str) -> Dict[str, Any]:
    detail = _unwrap_cloudtrail_payload(raw)
    parsed = engine.parse_cloudtrail_event(detail)
    if parsed is None:
        raise HTTPException(status_code=422, detail="Payload is not a recognizable CloudTrail detail block.")

    session = _session()
    result: Dict[str, Any] = {"parsed": {k: v for k, v in parsed.items() if k != "raw"}, "source": source}

    # What the role is *currently* allowed to do (simulator ground truth).
    if session and parsed.get("role_arn") and str(parsed["role_arn"]).startswith("arn:aws:iam::"):
        action_name = f"{parsed['service']}:{parsed['action']}"
        sim = engine.simulate_principal_policy(session, parsed["role_arn"], [action_name])
        _fail_if_engine_error("simulate_principal_policy", sim.get("error"))
        result["current_evaluation"] = sim

        current = engine.fetch_current_policy(session, parsed["role_arn"])
        _fail_if_engine_error("fetch_current_policy", current.get("error"))
        result["current_policy"] = current
        result["risk_score"] = engine.compute_risk_score(current)

        # Synthesize + validate the least-privilege replacement.
        least = engine.build_least_privilege_policy(
            session, parsed["role_arn"],
            [{"service": parsed["service"], "action": parsed["action"],
              "resource": parsed.get("resource"),
              "read_only": engine.is_read_only(parsed["service"], parsed["action"])}],
        )
        sim_custom = engine.simulate_custom_policy(session, least, [action_name])
        _fail_if_engine_error("simulate_custom_policy", sim_custom.get("error"))
        result["least_privilege_policy"] = least
        result["simulation"] = sim_custom
        result["wildcard_reduction"] = engine.compute_wildcard_reduction(current.get("document", {}), least)
    else:
        result["note"] = "AWS unavailable or no resolvable role ARN; engine ran in offline mode."

    _broadcast({
        "type": "event",
        "ts": engine.utc_now_iso(),
        "event_id": parsed.get("event_id"),
        "event_name": parsed.get("event_name"),
        "event_source": parsed.get("event_source"),
        "service": parsed.get("service"),
        "action": parsed.get("action"),
        "role_arn": parsed.get("role_arn"),
        "resource": parsed.get("resource"),
        "error_code": parsed.get("error_code"),
        "risk_score": result.get("risk_score"),
        "wildcard_reduction": result.get("wildcard_reduction"),
        "simulated": result.get("simulation", {}).get("valid") if isinstance(result.get("simulation"), dict) else None,
    })
    return result


@app.post("/api/v1/events/ingest", summary="Ingest a CloudTrail detail block or EventBridge envelope")
def ingest_event(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    return _process_ingest(payload, source="ingest")


@app.post("/api/v1/events/eventbridge", summary="Ingest a full EventBridge envelope")
def ingest_eventbridge(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    if not isinstance(payload, dict) or "detail" not in payload:
        raise HTTPException(status_code=422, detail="Expected an EventBridge envelope containing a 'detail' object.")
    return _process_ingest(payload, source="eventbridge")


# ---------------------------------------------------------------------------
# Policy simulator / remediation
# ---------------------------------------------------------------------------
@app.post("/api/v1/policy/simulate", summary="Dry-run a candidate policy via simulate_custom_policy")
def policy_simulate(req: SimulateRequest) -> Dict[str, Any]:
    session = _session()
    if session is None:
        raise HTTPException(status_code=503, detail="AWS credentials unavailable — configure AWS CLI (`aws configure`).")

    custom = engine.simulate_custom_policy(session, req.policy_document, req.action_names)
    _fail_if_engine_error("simulate_custom_policy", custom.get("error"))

    # Also report what the role's *current* policies decide for comparison.
    principal = None
    if req.role_arn.startswith("arn:aws:iam::"):
        principal = engine.simulate_principal_policy(session, req.role_arn, req.action_names)
        _fail_if_engine_error("simulate_principal_policy", principal.get("error"))

    return {
        "custom_policy_simulation": custom,
        "current_principal_simulation": principal,
        "role_arn": req.role_arn,
        "actions_tested": req.action_names,
    }


@app.post("/api/v1/policy/remediate", summary="Enforce the least-privilege policy on a role")
def policy_remediate(req: RemediateRequest) -> Dict[str, Any]:
    session = _session()
    if session is None:
        raise HTTPException(status_code=503, detail="AWS credentials unavailable — configure AWS CLI (`aws configure`).")

    # Safety net: re-validate through the simulator before touching live IAM.
    precheck = engine.simulate_custom_policy(session, req.policy_document, ["s3:ListBuckets"])
    _fail_if_engine_error("pre-flight simulate_custom_policy", precheck.get("error"))
    if not precheck.get("valid"):
        raise HTTPException(status_code=422, detail={
            "message": "Pre-flight simulation failed; refusing to modify live IAM.",
            "simulation": precheck,
        })

    result = engine.apply_remediation(session, req.role_arn, req.policy_document, req.detach_arn)
    _broadcast({
        "type": "remediation",
        "ts": engine.utc_now_iso(),
        "role_arn": req.role_arn,
        "success": result["success"],
        "steps": result["steps"],
    })
    if not result["success"]:
        failed = [s for s in result["steps"] if s["status"] == "error"]
        raise HTTPException(status_code=502, detail={"message": "remediation partially failed", "steps": failed})
    return result


# ---------------------------------------------------------------------------
# Server-Sent Events telemetry stream
# ---------------------------------------------------------------------------
@app.get("/api/v1/telemetry/stream", summary="SSE stream of live event logs")
async def telemetry_stream() -> StreamingResponse:
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    event_subscribers.add((loop, queue))
    log.info("SSE subscriber connected (total=%d)", len(event_subscribers))

    async def event_gen() -> AsyncGenerator[str, None]:
        try:
            # Replay the last few events so a fresh dashboard isn't empty.
            for past in list(event_buffer)[-10:]:
                yield f"data: {json.dumps(past, default=str)}\n\n"
            yield f"data: {json.dumps({'type': 'hello', 'ts': engine.utc_now_iso()})}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"  # SSE comment keeps the connection warm
        except asyncio.CancelledError:
            pass
        finally:
            event_subscribers.discard((loop, queue))
            log.info("SSE subscriber disconnected (total=%d)", len(event_subscribers))

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/")
def root() -> Dict[str, str]:
    return {"service": "Zero-Trust IAM Policy Engine", "docs": "/docs", "health": "/api/v1/health"}
