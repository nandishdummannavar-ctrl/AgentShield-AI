from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime


# -------------------------------------------------
# 1. DEFINE THE AGENT ACTION
# -------------------------------------------------

@dataclass
class AgentAction:
    agent_id: str
    action: str
    resource: str
    sensitive_data: bool = False
    external_destination: bool = False
    anomaly_score: float = 0.0


# -------------------------------------------------
# 2. DEFINE AGENT PERMISSIONS
# -------------------------------------------------

AGENT_PERMISSIONS = {
    "Email Agent": {
        "read_email",
        "draft_email",
        "send_email",
    },

    "Document Agent": {
        "read_document",
        "summarize_document",
    },

    "Data Agent": {
        "read_customer_data",
        "analyze_customer_data",
    },
}


# -------------------------------------------------
# 3. DEFINE PROHIBITED ACTIONS
# -------------------------------------------------

PROHIBITED_ACTIONS = {
    "export_all_customer_data",
    "disable_security_logging",
}


# -------------------------------------------------
# 4. SECURITY EVALUATION
# -------------------------------------------------

def evaluate_action(
    request: AgentAction,
    approved_external_destination: bool = False,
) -> dict:

    risk = 0

    # Check whether the agent exists.

    if request.agent_id not in AGENT_PERMISSIONS:
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reason": "Unknown agent",
        }

    # Mandatory prohibition rules.

    if request.action in PROHIBITED_ACTIONS:
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reason": "Action prohibited by security policy",
        }

    # Check explicit permissions.

    permissions = AGENT_PERMISSIONS[request.agent_id]

    if request.action not in permissions:
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reason": "Agent does not have permission",
        }

    # Calculate a demonstration risk score.

    if request.sensitive_data:
        risk += 45

    if request.external_destination:
        risk += 35

    risk += round(
        max(0, min(1, request.anomaly_score)) * 20
    )

    risk = min(risk, 100)

    # Enforce sensitive-data restrictions.

    if request.sensitive_data and request.external_destination:

        if not approved_external_destination:
            return {
                "decision": "BLOCK",
                "risk_score": risk,
                "reason": (
                    "Sensitive data cannot be sent "
                    "to an unapproved external destination"
                ),
            }

    # High-risk actions require review or blocking.

    if risk >= 70:
        return {
            "decision": "BLOCK",
            "risk_score": risk,
            "reason": "Risk exceeds blocking threshold",
        }

    if risk >= 30:
        return {
            "decision": "REVIEW",
            "risk_score": risk,
            "reason": "Human review required",
        }

    return {
        "decision": "ALLOW",
        "risk_score": risk,
        "reason": "Security checks passed",
    }


# -------------------------------------------------
# 5. SIMULATED TOOL EXECUTION
# -------------------------------------------------

def execute_action(
    request: AgentAction,
    decision: dict,
) -> dict:

    # Never execute a blocked or pending action.

    if decision["decision"] != "ALLOW":

        return {
            "status": "NOT_EXECUTED",
            "reason": decision["reason"],
        }

    # This is a safe simulation.
    # No real email, file, or customer data is accessed.

    return {
        "status": "SIMULATED_SUCCESS",
        "action": request.action,
        "resource": request.resource,
    }


# -------------------------------------------------
# 6. CREATE AUDIT EVENTS
# -------------------------------------------------

def create_audit_event(
    request: AgentAction,
    decision: dict,
    execution: dict,
) -> dict:

    return {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "agent": request.agent_id,
        "action": request.action,
        "resource": request.resource,
        "decision": decision["decision"],
        "risk_score": decision["risk_score"],
        "reason": decision["reason"],
        "execution_status": execution["status"],
    }