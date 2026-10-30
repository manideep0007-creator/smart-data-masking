"""
Dedicated Test Suite for Real Google OAuth 2.0 / OpenID Connect Implementation
Includes SEC-OAUTH-01 Remediation: Server-Side Pending State Storage, Atomic Consumption,
PKCE Confidentiality, Replay Mitigation, and Concurrency Tests.
"""

import base64
import os
import secrets
import sqlite3
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi.testclient import TestClient

from backend.auth import create_access_token, generate_csrf_token
from backend.auth_db import (
    cleanup_expired_oauth_states,
    consume_pending_oauth_state,
    create_user,
    get_auth_connection,
    get_oauth_mapping_by_user_id,
    get_pending_oauth_state,
    get_user_by_oauth_sub,
    get_users_by_email,
    hash_password,
    init_auth_db,
    link_user_oauth,
    store_pending_oauth_state,
)
from backend.google_oauth import (
    compute_state_hash,
    create_oauth_handle_cookie_value,
    create_oauth_state_cookie_value,
    decode_and_verify_oauth_state,
    generate_pkce_pair,
    verify_oauth_handle_in_cookie,
)
from backend.main import app

CLIENT_ID = "test-client-id-12345.apps.googleusercontent.com"
CLIENT_SECRET = "test-client-secret-abcxyz6789"
REDIRECT_URI = "http://localhost:8000/auth/google/callback"


@pytest.fixture(autouse=True)
def setup_oauth_env(monkeypatch):
    """Ensure OAuth environment variables are set for tests."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", REDIRECT_URI)
    monkeypatch.setenv("FRONTEND_URL", "http://localhost:3000")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-google-oauth-suite-2026")
    monkeypatch.setenv("ENVIRONMENT", "development")


@pytest.fixture(autouse=True)
def clean_oauth_tables():
    """Ensure oauth_account_mappings and oauth_pending_states are clean before and after each test."""
    conn = get_auth_connection()
    try:
        conn.execute("DELETE FROM oauth_account_mappings")
        conn.execute("DELETE FROM oauth_pending_states")
        conn.commit()
    finally:
        conn.close()
    yield
    conn = get_auth_connection()
    try:
        conn.execute("DELETE FROM oauth_account_mappings")
        conn.execute("DELETE FROM oauth_pending_states")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def client():
    return TestClient(app)


def helper_setup_pending_state(client, state="test_state", nonce="test_nonce", verifier="test_verifier"):
    """Helper to store server-side pending state and set client handle cookie."""
    state_hash = compute_state_hash(state)
    exp = datetime.now(timezone.utc) + timedelta(minutes=10)
    store_pending_oauth_state(state_hash, nonce, verifier, exp)
    cookie_val = create_oauth_handle_cookie_value(state_hash)
    client.cookies.set("oauth_state", cookie_val)
    return state, nonce, verifier, state_hash


def test_oauth_status_when_credentials_missing(client, monkeypatch):
    """GET /auth/google/status returns disabled when credentials are not configured."""
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)

    resp = client.get("/auth/google/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["client_id"] is None
    assert "client_secret" not in data


def test_oauth_status_when_credentials_are_placeholders(client, monkeypatch):
    """GET /auth/google/status safely recognizes placeholder values and returns disabled."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "your-google-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "your-google-client-secret")

    resp = client.get("/auth/google/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["client_id"] is None
    assert "client_secret" not in data


def test_oauth_status_when_credentials_are_empty_strings(client, monkeypatch):
    """GET /auth/google/status returns disabled when env variables are empty strings."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "   ")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "")

    resp = client.get("/auth/google/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["client_id"] is None
    assert "client_secret" not in data


def test_oauth_status_when_only_one_credential_is_configured(client, monkeypatch):
    """GET /auth/google/status returns disabled when client_secret is missing."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "valid-id.apps.googleusercontent.com")
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)

    resp = client.get("/auth/google/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["client_id"] is None


def test_oauth_login_rejected_when_credentials_are_placeholders(client, monkeypatch):
    """GET /auth/google/login safely rejects initiation when env vars are placeholders."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "your-google-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "your-google-client-secret")

    resp = client.get("/auth/google/login", follow_redirects=False)
    assert resp.status_code == 302
    assert "auth_error=Google%20sign-in%20is%20not%20configured%20on%20this%20server." in resp.headers["location"]


def test_oauth_login_normalizes_ip_host_to_localhost(client, monkeypatch):
    """Ensure accessing login on 127.0.0.1 normalizes to localhost to match GOOGLE_REDIRECT_URI cookie domain."""
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
    resp = client.get("http://127.0.0.1:8000/auth/google/login", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "http://localhost:8000/auth/google/login"


def test_oauth_status_when_configured(client):
    """GET /auth/google/status returns enabled without exposing client secret."""
    resp = client.get("/auth/google/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["client_id"] == CLIENT_ID
    assert data["redirect_uri"] == REDIRECT_URI
    assert "client_secret" not in data


def test_oauth_initiation(client):
    """GET /auth/google/login initiates flow with PKCE S256, state, nonce, and HttpOnly cookie."""
    resp = client.get("/auth/google/login", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth")

    parsed = urllib.parse.urlparse(location)
    query = urllib.parse.parse_qs(parsed.query)

    assert query["client_id"][0] == CLIENT_ID
    assert query["redirect_uri"][0] == REDIRECT_URI
    assert query["response_type"][0] == "code"
    assert "openid" in query["scope"][0]
    assert "email" in query["scope"][0]
    assert "profile" in query["scope"][0]
    assert query["code_challenge_method"][0] == "S256"
    assert "code_challenge" in query
    assert "state" in query
    assert "nonce" in query

    raw_state = query["state"][0]
    state_hash = compute_state_hash(raw_state)

    # SEC-OAUTH-01 Verification: PKCE verifier stored server-side in SQLite
    record = get_pending_oauth_state(state_hash)
    assert record is not None
    assert record["nonce"] == query["nonce"][0]
    assert len(record["code_verifier"]) >= 43

    # Cookie contains only opaque lookup handle, NEVER code_verifier or nonce
    cookie_val = resp.cookies.get("oauth_state")
    assert cookie_val is not None
    payload = jwt.decode(cookie_val, options={"verify_signature": False})
    assert "code_verifier" not in payload
    assert "nonce" not in payload
    assert state_hash in payload["handles"]


def test_cookie_contains_no_pkce_verifier_or_nonce(client):
    """Ensure cookie payload is inspected and contains strictly opaque handles."""
    resp = client.get("/auth/google/login", follow_redirects=False)
    cookie_val = resp.cookies.get("oauth_state")
    assert cookie_val is not None

    payload = jwt.decode(cookie_val, options={"verify_signature": False})
    assert "code_verifier" not in payload
    assert "nonce" not in payload
    assert "handles" in payload
    assert isinstance(payload["handles"], list)


def test_serverside_pkce_verifier_storage(client):
    """Verify that PKCE code_verifier is persisted in oauth_pending_states table."""
    resp = client.get("/auth/google/login", follow_redirects=False)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(resp.headers["location"]).query)
    state = query["state"][0]
    state_hash = compute_state_hash(state)

    record = get_pending_oauth_state(state_hash)
    assert record is not None
    assert "code_verifier" in record
    assert "nonce" in record
    assert record["state_hash"] == state_hash


def test_correct_pkce_verifier_used_in_token_exchange(client):
    """Ensure the exact code_verifier retrieved from SQLite is passed to Google token exchange."""
    state = "state_pkce_test"
    nonce = "nonce_pkce_test"
    custom_verifier = "custom_pkce_verifier_secret_1234567890_abcdefghij"
    helper_setup_pending_state(client, state=state, nonce=nonce, verifier=custom_verifier)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "sub-pkce-user",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=mock_code&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        assert mock_exchange.called
        # First positional argument is code, second is code_verifier
        called_args = mock_exchange.call_args[0]
        assert called_args[0] == "mock_code"
        assert called_args[1] == custom_verifier


def test_multiple_simultaneous_oauth_initiations(client):
    """Verify that multiple browser tabs can initiate OAuth simultaneously without overwriting state."""
    # Tab 1 initiation
    resp1 = client.get("/auth/google/login", follow_redirects=False)
    q1 = urllib.parse.parse_qs(urllib.parse.urlparse(resp1.headers["location"]).query)
    state1 = q1["state"][0]
    state_hash1 = compute_state_hash(state1)

    # Tab 2 initiation (client preserves cookies across requests)
    resp2 = client.get("/auth/google/login", follow_redirects=False)
    q2 = urllib.parse.parse_qs(urllib.parse.urlparse(resp2.headers["location"]).query)
    state2 = q2["state"][0]
    state_hash2 = compute_state_hash(state2)

    # Both states must exist independently in SQLite
    rec1 = get_pending_oauth_state(state_hash1)
    rec2 = get_pending_oauth_state(state_hash2)
    assert rec1 is not None
    assert rec2 is not None
    assert rec1["code_verifier"] != rec2["code_verifier"]

    # Cookie must contain both handles
    cookie_val = resp2.cookies.get("oauth_state")
    payload = jwt.decode(cookie_val, options={"verify_signature": False})
    assert state_hash1 in payload["handles"]
    assert state_hash2 in payload["handles"]

    # Both callbacks can now complete independently
    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "sub-tab-user",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        # Tab 1 callback completes
        cb1 = client.get(f"/auth/google/callback?code=code1&state={state1}", follow_redirects=False)
        assert cb1.status_code == 302
        assert cb1.headers["location"] == "http://localhost:3000/"


def test_successful_callback_consumes_state(client):
    """Verify that completing a callback atomically consumes and removes the state from SQLite."""
    state = "state_consume_check"
    state, nonce, verifier, state_hash = helper_setup_pending_state(client, state=state)

    assert get_pending_oauth_state(state_hash) is not None

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "sub-consume-1",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "http://localhost:3000/"

        # Record must be consumed (deleted) from database
        assert get_pending_oauth_state(state_hash) is None


def test_replayed_callback_rejected(client):
    """Verify that replaying an already-consumed callback is immediately rejected."""
    state = "state_replay_test"
    state, nonce, verifier, state_hash = helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "sub-replay-user",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        # First request succeeds
        resp1 = client.get(f"/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert resp1.status_code == 302
        assert resp1.headers["location"] == "http://localhost:3000/"

        # Second request (replayed by client or attacker with cookie restored)
        cookie_val = create_oauth_handle_cookie_value(state_hash)
        client.cookies.set("oauth_state", cookie_val)
        resp2 = client.get(f"/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert resp2.status_code == 302
        loc = resp2.headers["location"]
        assert "auth_error" in loc
        assert "already-consumed" in urllib.parse.unquote(loc).lower() or "invalid" in urllib.parse.unquote(loc).lower()


def test_expired_state_rejected(client):
    """Verify that expired pending states are rejected by consume_pending_oauth_state."""
    state = "state_expired_test"
    state_hash = compute_state_hash(state)
    expired_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    store_pending_oauth_state(state_hash, "nonce", "verifier", expired_time)

    cookie_val = create_oauth_handle_cookie_value(state_hash)
    client.cookies.set("oauth_state", cookie_val)

    resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
    assert resp.status_code == 302
    assert "auth_error" in resp.headers["location"]


def test_concurrent_callback_attempts_cannot_both_succeed():
    """Verify atomic transaction: two concurrent consumption attempts on same state cannot both succeed."""
    state = "state_concurrent_race"
    state_hash = compute_state_hash(state)
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    store_pending_oauth_state(state_hash, "nonce_c", "verifier_c", exp)

    results = []

    def try_consume():
        res = consume_pending_oauth_state(state_hash)
        results.append(res)

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(try_consume)
        f2 = executor.submit(try_consume)
        f1.result()
        f2.result()

    successful = [r for r in results if r is not None]
    failed = [r for r in results if r is None]

    assert len(successful) == 1
    assert len(failed) == 1
    assert successful[0]["nonce"] == "nonce_c"


def test_state_mismatch(client):
    """Callback rejects request when state does not match oauth_state cookie."""
    helper_setup_pending_state(client, state="state_correct")
    resp = client.get("/auth/google/callback?code=mock_code&state=state_attacker", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "auth_error" in location
    assert "Invalid%20OAuth%20state" in location or "Invalid OAuth state" in urllib.parse.unquote(location)


def test_invalid_nonce(client):
    """Callback rejects token when nonce in ID token does not match nonce in session cookie."""
    state = "test_state_123"
    state, nonce, verifier, state_hash = helper_setup_pending_state(client, state=state, nonce="expected_nonce_456")

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "mock.id.token"}
        mock_verify.side_effect = ValueError("ID token nonce does not match expected OAuth session nonce.")

        resp = client.get(f"/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "nonce" in urllib.parse.unquote(location).lower()


def test_invalid_id_token_signature(client):
    """Callback rejects token with invalid cryptographic signature."""
    state = "state_sig"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "tampered.jwt.signature"}
        mock_verify.side_effect = ValueError("Invalid Google ID token: Signature verification failed")

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "Signature%20verification%20failed" in location or "Signature verification failed" in urllib.parse.unquote(location)


def test_wrong_audience(client):
    """Callback rejects token intended for a different client ID."""
    state = "state_aud"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "wrong.audience.token"}
        mock_verify.side_effect = ValueError("Invalid Google ID token: Token has wrong audience")

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "wrong%20audience" in location or "wrong audience" in urllib.parse.unquote(location)


def test_expired_token(client):
    """Callback rejects expired Google ID token."""
    state = "state_exp"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "expired.id.token"}
        mock_verify.side_effect = ValueError("Invalid Google ID token: Token has expired")

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "expired" in urllib.parse.unquote(location).lower()


def test_unverified_email(client):
    """Callback rejects token where email_verified is False."""
    state = "state_unv"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "unverified.email.token"}
        mock_verify.side_effect = ValueError("Google email address is not verified.")

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "not%20verified" in location or "not verified" in urllib.parse.unquote(location)


def test_unknown_account_rejection(client):
    """Callback rejects Google account with no matching existing PII Shield user."""
    state = "state_unknown"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "unknown.user.token"}
        mock_verify.return_value = {
            "sub": "google-sub-nonexistent-9999",
            "email": "unregistered.stranger@gmail.com",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        expected_msg = "Your Google account is not registered with PII Shield. Contact your administrator."
        assert expected_msg in urllib.parse.unquote(location)


def test_inactive_account_rejection(client):
    """Callback rejects Google login when existing matching account is deactivated."""
    state = "state_inactive"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "disabled.user.token"}
        mock_verify.return_value = {
            "sub": "google-sub-disabled-8888",
            "email": "disabled@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "disabled" in urllib.parse.unquote(location).lower()


def test_duplicate_email_collision_rejection(client):
    """Callback rejects login if ambiguous multiple accounts exist for the verified email."""
    state = "state_dup_email"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify, \
         patch("backend.main.get_users_by_email") as mock_get_users:
        mock_exchange.return_value = {"id_token": "dup.user.token"}
        mock_verify.return_value = {
            "sub": "google-sub-dup-777",
            "email": "collision@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }
        mock_get_users.return_value = [
            {"id": 101, "username": "user_one", "role": "Support", "is_active": 1},
            {"id": 102, "username": "user_two", "role": "Analyst", "is_active": 1},
        ]

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "Multiple accounts found" in urllib.parse.unquote(location)


def test_duplicate_google_subject_cross_linking_rejected(client):
    """Rejects attempt to cross-link a Google identity already bound to another local account."""
    state = "state_dup_sub"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify, \
         patch("backend.main.get_oauth_mapping_by_user_id") as mock_get_mapping, \
         patch("backend.main.get_user_by_oauth_sub") as mock_get_sub:
        mock_exchange.return_value = {"id_token": "dup.sub.token"}
        mock_verify.return_value = {
            "sub": "google-sub-already-bound-999",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }
        mock_get_sub.return_value = None
        mock_get_mapping.return_value = {"provider_sub": "different-sub-111"}

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "already linked to a different Google account" in urllib.parse.unquote(location)


def test_successful_login_support_account(client):
    """Successful Google OAuth login for an existing Support role account."""
    state = "state_support"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.support.token"}
        mock_verify.return_value = {
            "sub": "google-sub-ravi-12345",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "http://localhost:3000/"

        access_tok = resp.cookies.get("access_token")
        csrf_tok = resp.cookies.get("csrf_token")
        assert access_tok is not None
        assert csrf_tok is not None

        # Set cookie directly on client instance (prevents Starlette TestClient deprecation warning)
        client.cookies.set("access_token", access_tok)
        me_resp = client.get("/auth/me")
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["username"] == "support_ravi"
        assert me_data["role"] == "Support"


def test_successful_login_analyst_account(client):
    """Successful Google OAuth login for an existing Analyst role account."""
    state = "state_analyst"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.analyst.token"}
        mock_verify.return_value = {
            "sub": "google-sub-kavya-67890",
            "email": "kavya.iyer@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302

        access_tok = resp.cookies.get("access_token")
        client.cookies.set("access_token", access_tok)
        me_resp = client.get("/auth/me")
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["username"] == "analyst_kavya"
        assert me_data["role"] == "Analyst"


def test_successful_login_admin_account(client):
    """Successful Google OAuth login for an existing Admin role account."""
    state = "state_admin"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.admin.token"}
        mock_verify.return_value = {
            "sub": "google-sub-anita-99999",
            "email": "anita.sharma@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        assert resp.status_code == 302

        access_tok = resp.cookies.get("access_token")
        client.cookies.set("access_token", access_tok)
        me_resp = client.get("/auth/me")
        assert me_resp.status_code == 200
        assert me_resp.json()["username"] == "admin_anita"
        assert me_resp.json()["role"] == "Admin"

        users_resp = client.get("/auth/users")
        assert users_resp.status_code == 200
        assert len(users_resp.json()) > 0


def test_httponly_session_cookie_flags(client):
    """Verify HttpOnly, SameSite, and Path flags on the issued access_token cookie."""
    state = "state_flags"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "google-sub-flags-111",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        raw_cookie_headers = resp.headers.get_list("set-cookie")

        access_cookie_header = [h for h in raw_cookie_headers if h.startswith("access_token=")][0].lower()
        assert "httponly" in access_cookie_header
        assert "samesite=lax" in access_cookie_header
        assert "path=/" in access_cookie_header


def test_csrf_protection_after_oauth_login(client):
    """Ensure state-changing requests after OAuth login enforce CSRF double-submit validation."""
    state = "state_csrf"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "google-sub-csrf-222",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        access_tok = resp.cookies.get("access_token")
        csrf_tok = resp.cookies.get("csrf_token")

        client.cookies.set("access_token", access_tok)
        client.cookies.set("csrf_token", csrf_tok)

        req_payload = {"sql": "SELECT 1;", "role": "Support"}
        bad_post = client.post("/query", json=req_payload)
        assert bad_post.status_code == 403
        assert "CSRF" in bad_post.json()["detail"]

        good_post = client.post("/query", json=req_payload, headers={"X-CSRF-Token": csrf_tok})
        assert good_post.status_code == 200


def test_logout_and_session_revocation(client):
    """Verify that logging out revokes the session issued via OAuth and clears cookies."""
    state = "state_logout"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "valid.token"}
        mock_verify.return_value = {
            "sub": "google-sub-logout-333",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        access_tok = resp.cookies.get("access_token")
        csrf_tok = resp.cookies.get("csrf_token")

        client.cookies.set("access_token", access_tok)
        client.cookies.set("csrf_token", csrf_tok)

        logout_resp = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_tok})
        assert logout_resp.status_code == 200

        me_resp = client.get("/auth/me")
        assert me_resp.status_code == 401


def test_no_jwt_or_google_tokens_exposed_to_browser_url(client):
    """Ensure no JWT, Google access tokens, or ID tokens appear in redirect URL or query string."""
    state = "state_leak_check"
    helper_setup_pending_state(client, state=state)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {
            "access_token": "google_secret_access_token_123",
            "id_token": "google_raw_id_token_456",
            "token_type": "Bearer",
        }
        mock_verify.return_value = {
            "sub": "google-sub-leak-444",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp = client.get(f"/auth/google/callback?code=code123&state={state}", follow_redirects=False)
        redirect_url = resp.headers["location"]

        assert "google_secret_access_token_123" not in redirect_url
        assert "google_raw_id_token_456" not in redirect_url
        assert "access_token=" not in redirect_url
        assert "jwt=" not in redirect_url
        assert redirect_url == "http://localhost:3000/"


def test_subsequent_login_uses_stable_sub(client):
    """Once linked, subsequent logins resolve user account directly via Google sub."""
    state1 = "state_sub_test_1"
    helper_setup_pending_state(client, state=state1)

    with patch("backend.main.exchange_code_for_tokens") as mock_exchange, \
         patch("backend.main.verify_google_id_token") as mock_verify:
        mock_exchange.return_value = {"id_token": "sub.test.token"}
        mock_verify.return_value = {
            "sub": "stable-google-sub-55555",
            "email": "ravi.kumar@saffronbank.local",
            "email_verified": True,
            "iss": "https://accounts.google.com",
        }

        resp1 = client.get(f"/auth/google/callback?code=code1&state={state1}", follow_redirects=False)
        assert resp1.status_code == 302

        # Second login with new state
        state2 = "state_sub_test_2"
        helper_setup_pending_state(client, state=state2)

        resp2 = client.get(f"/auth/google/callback?code=code2&state={state2}", follow_redirects=False)
        assert resp2.status_code == 302
        access_tok = resp2.cookies.get("access_token")

        client.cookies.set("access_token", access_tok)
        me_resp = client.get("/auth/me")
        assert me_resp.status_code == 200
        assert me_resp.json()["username"] == "support_ravi"


def test_error_paths_clear_temporary_cookies(client):
    """Verify that OAuth error paths strictly clear the temporary oauth_state cookie."""
    # 1. State mismatch error
    helper_setup_pending_state(client, state="correct_state")
    err_resp1 = client.get("/auth/google/callback?code=code&state=wrong_state", follow_redirects=False)
    assert err_resp1.status_code == 302
    set_cookies1 = [c for c in err_resp1.headers.get_list("set-cookie") if "oauth_state" in c]
    assert len(set_cookies1) > 0
    # Must contain max-age=0 or expires in past
    assert any("max-age=0" in c.lower() or "expires=" in c.lower() for c in set_cookies1)

    # 2. Provider cancelled error
    err_resp2 = client.get("/auth/google/callback?error=access_denied", follow_redirects=False)
    assert err_resp2.status_code == 302
    set_cookies2 = [c for c in err_resp2.headers.get_list("set-cookie") if "oauth_state" in c]
    assert len(set_cookies2) > 0
