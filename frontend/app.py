import json
import os

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = os.getenv("MASKING_API_URL", "http://localhost:8000").rstrip("/")
REQUEST_TIMEOUT_SECONDS = 5

st.set_page_config(page_title="Smart Data Masking", page_icon="🛡️", layout="wide")
st.title("🛡️ Smart Data Masking")
st.caption("Explore PII detection and role-based masking in query results.")


def api_get(path):
    return requests.get(f"{API_BASE_URL}{path}", timeout=REQUEST_TIMEOUT_SECONDS)


def show_api_error(error):
    if isinstance(error, requests.exceptions.Timeout):
        st.error("The backend request timed out. Check that the service is responsive and try again.")
    elif isinstance(error, requests.exceptions.ConnectionError):
        st.error(f"Backend unavailable at {API_BASE_URL}. Start the backend and try again.")
    elif isinstance(error, requests.exceptions.RequestException):
        st.error(f"Backend request failed: {error}")
    else:
        st.error(f"Unexpected backend response: {error}")


with st.sidebar:
    st.subheader("Backend")
    try:
        health_response = api_get("/health")
        health_response.raise_for_status()
        st.success("Connected · /health responded successfully")
    except requests.exceptions.RequestException as exc:
        st.error("Unavailable · could not reach /health")
        if isinstance(exc, requests.exceptions.Timeout):
            st.caption("Health check timed out.")
        elif isinstance(exc, requests.exceptions.ConnectionError):
            st.caption(f"Could not connect to {API_BASE_URL}.")
        else:
            st.caption(f"Health check failed: {exc}")
    st.caption(f"API: {API_BASE_URL}")

    role = st.selectbox("User role", ["Admin", "Support", "Analyst"])

st.subheader("Query workspace")
sql = st.text_area(
    "SQL query",
    value="SELECT name, card_number FROM customers",
    height=120,
    help="Queries are sent to the backend, which applies masking according to the selected role.",
)
scan_col, run_col = st.columns(2)

with scan_col:
    if st.button("Scan for PII", use_container_width=True):
        with st.spinner("Scanning through backend…"):
            try:
                response = api_get("/scan")
                response.raise_for_status()
                try:
                    scan_data = response.json()
                except ValueError:
                    scan_data = response.text
                st.session_state["scan_result"] = scan_data
                st.session_state.pop("scan_error", None)
            except requests.exceptions.RequestException as exc:
                st.session_state["scan_error"] = exc
                st.session_state.pop("scan_result", None)

with run_col:
    if st.button("Run query", type="primary", use_container_width=True):
        with st.spinner(f"Running query as {role}…"):
            try:
                response = requests.post(
                    f"{API_BASE_URL}/query",
                    json={"role": role, "sql": sql},
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
                response.raise_for_status()
                result = response.json()
                if not isinstance(result, dict) or not isinstance(result.get("columns"), list) or not isinstance(result.get("rows"), list):
                    raise ValueError("Expected a JSON response with columns and rows arrays.")
                st.session_state["query_result"] = result
                st.session_state.pop("query_error", None)
            except requests.exceptions.RequestException as exc:
                st.session_state["query_error"] = exc
                st.session_state.pop("query_result", None)
            except (ValueError, json.JSONDecodeError) as exc:
                st.session_state["query_error"] = exc
                st.session_state.pop("query_result", None)

if "scan_error" in st.session_state:
    show_api_error(st.session_state["scan_error"])
if "scan_result" in st.session_state:
    st.subheader("Scan response")
    st.info("Showing the backend response as-is because the /scan response schema has not yet been specified.")
    st.json(st.session_state["scan_result"])

if "query_error" in st.session_state:
    show_api_error(st.session_state["query_error"])
if "query_result" in st.session_state:
    st.subheader("Query results")
    result = st.session_state["query_result"]
    columns, rows = result["columns"], result["rows"]
    if any(not isinstance(row, list) or len(row) != len(columns) for row in rows):
        st.error("The backend returned rows that do not match the supplied columns.")
    else:
        st.dataframe(pd.DataFrame(rows, columns=columns), use_container_width=True, hide_index=True)
        st.caption(f"{len(rows)} row(s) · Role: {role}")

st.divider()
st.caption("PII detection is heuristic and may not identify every sensitive field. Masking applies only to queries routed through the backend.")
