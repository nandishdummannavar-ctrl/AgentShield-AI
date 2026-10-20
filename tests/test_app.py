import streamlit as st

st.title("🛡️ AgentShield AI")

st.success("Streamlit is working!")

st.write("Welcome to your AI Agent Security Dashboard.")

if st.button("Test Security"):
    st.error("Unauthorized action blocked!")