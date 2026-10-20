import streamlit as st
from security_engine import AgentAction, evaluate_action, execute_action

st.set_page_config(
    page_title="AgentShield AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AgentShield AI")
st.subheader("AI Agent Security & Control Center")

st.success("Security dashboard is running!")

st.markdown("---")

st.header("🔐 Evaluate an AI Agent Action")

agent_id = st.selectbox(
    "Select AI Agent",
    ["Email Agent", "Data Agent", "Browser Agent"]
)

action = st.selectbox(
    "Select Action",
    [
        "read_email",
        "read_customer_data",
        "export_all_customer_data"
    ]
)

resource = st.selectbox(
    "Select Resource",
    [
        "mailbox_01",
        "customer_database",
        "web_browser"
    ]
)

st.markdown("### Security Evaluation")

if st.button("Evaluate Action", type="primary"):

    try:
        request = AgentAction(
            agent_id=agent_id,
            action=action,
            resource=resource
        )

        decision = evaluate_action(request)

        st.write("### Decision")
        st.json(decision)

        if decision.get("decision") == "ALLOW":
            st.success("✅ Action allowed by the security engine.")

            result = execute_action(request, decision)

            st.write("### Execution Result")
            st.json(result)

        else:
            st.error("🚫 Action blocked by the security engine.")
            st.warning("The requested action must not be executed.")

    except Exception as error:
        st.error(f"Security evaluation failed: {error}")

st.markdown("---")

st.caption(
    "AgentShield AI | AI Agent Authorization & Security Prototype"
)