from security_engine import (
    AgentAction,
    evaluate_action,
    execute_action,
)


def test_authorized_action():
    request = AgentAction(
        agent_id="Email Agent",
        action="read_email",
        resource="mailbox_01",
    )

    decision = evaluate_action(request)

    assert decision["decision"] == "ALLOW"


def test_unauthorized_action():
    request = AgentAction(
        agent_id="Email Agent",
        action="read_customer_data",
        resource="customer_database",
    )

    decision = evaluate_action(request)

    assert decision["decision"] == "BLOCK"


def test_prohibited_action():
    request = AgentAction(
        agent_id="Data Agent",
        action="export_all_customer_data",
        resource="customer_database",
    )

    decision = evaluate_action(request)

    assert decision["decision"] == "BLOCK"


def test_blocked_action_is_not_executed():
    request = AgentAction(
        agent_id="Email Agent",
        action="read_customer_data",
        resource="customer_database",
    )

    decision = evaluate_action(request)
    result = execute_action(request, decision)

    assert result["status"] == "NOT_EXECUTED"