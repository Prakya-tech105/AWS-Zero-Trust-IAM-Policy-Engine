# Zero-Trust IAM Policy Engine 🛡️

An enterprise-grade security dashboard designed to ingest CloudTrail events, simulate least-privilege remediation, and visualize policy comparisons in real-time via a side-by-side Monaco Editor. 

![Dashboard Preview](https://img.shields.io/badge/Status-Production%20Ready-emerald) ![Hackathon Build](https://img.shields.io/badge/Build-Hackathon%20Winner-blue)

---

## 🏗️ Architecture & Workflow

The platform operates as an end-to-end telemetry and remediation pipeline:

```mermaid
flowchart TD
    subgraph group_ui["Dashboard UI (React/Vite)"]
        node_app["Dashboard App [App.tsx]"]
        node_role_selector["Role Selector"]
        node_telemetry["Telemetry Stream"]
        node_policy_diff["Policy Diff Viewer (Monaco)"]
    end

    subgraph group_api["API Service (FastAPI)"]
        node_fastapi["FastAPI Server [main.py]"]
        node_event_routes["Event Ingestion"]
        node_policy_routes["Policy Engine Dispatch"]
    end

    subgraph group_engine["Policy Engine (Python)"]
        node_event_parser["Event Parser"]
        node_policy_analysis["IAM Policy Analysis"]
        node_policy_simulator["Policy Simulator"]
        node_remediation["Automated Remediation"]
    end

    subgraph group_aws["AWS Integrations"]
        node_cloudtrail["CloudTrail Events"]
        node_eventbridge["EventBridge"]
        node_iam["AWS IAM"]
    end

    node_cloudtrail -->|Publishes| node_eventbridge
    node_eventbridge -->|Delivers| node_event_routes
    node_role_selector -->|Selects Target| node_app
    node_app -->|Requests Data| node_fastapi
    node_fastapi -->|Evaluates| node_policy_routes
    node_policy_routes -->|Analyzes State| node_policy_analysis
    node_policy_analysis -->|Validates| node_policy_simulator
    node_remediation -->|Enforces Zero-Trust| node_iam
