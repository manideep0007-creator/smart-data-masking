"""
PII Shield — Real Google OAuth 2.0 / OpenID Connect Implementation
Enforces PKCE (S256), cryptographic state/nonce verification, and server-side ID token validation.
"""

import base64
import hashlib
import logging
import os
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt
import requests
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

from backend.auth import JWT_ALGORITHM, JWT_SECRET_KEY

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")
if os.path.exists(_ENV_PATH):
    try:
        from dotenv import load_dotenv
        load_dotenv(_ENV_PATH)
    except ImportError:
        pass

logger = logging.getLogger("pii_shield.google_oauth")

# Google OIDC Discovery Endpoints
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

_PLACEHOLDER_MARKERS = (
    "your-google-client-id",
    "your-google-client-secret",
    "<your-client-id>",
    "<your-client-secret>",
    "enter-client-id-here",
    "enter-client-secret-here",
    "placeholder",
    "change-this",
)


def get_google_client_id() -> str:
    """Retrieve configured Google Client ID from environment."""
    return os.getenv("GOOGLE_CLIENT_ID", "").strip()


def get_google_client_secret() -> str:
    """Retrieve configured Google Client Secret from environment."""
    return os.getenv("GOOGLE_CLIENT_SECRET", "").strip()


def get_google_redirect_uri() -> str:
    """Retrieve configured Google OAuth Redirect URI (default: http://localhost:8000/auth/google/callback)."""
    return os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback").strip()


def get_frontend_url() -> str:
    """Retrieve frontend application root URL for OAuth redirects (default: http://localhost:3000)."""
    return os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")


def is_google_oauth_configured() -> bool:
    """
    Check if real Google OAuth 2.0 credentials are configured.
    Returns False if either credential is missing, empty, or contains a placeholder template string.
    """
    client_id = get_google_client_id()
    client_secret = get_google_client_secret()
    if not client_id or not client_secret:
        return False
    lower_id = client_id.lower()
    lower_secret = client_secret.lower()
    for marker in _PLACEHOLDER_MARKERS:
        if marker in lower_id or marker in lower_secret:
            return False
    return True


def generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate high-entropy PKCE code_verifier and code_challenge using S256.
    RFC 7636: code_verifier must be a cryptographically random string (43 to 128 characters).
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def compute_state_hash(state: str) -> str:
    """Calculate SHA-256 hex digest of raw state string for lookup."""
    return hashlib.sha256(state.strip().encode("utf-8")).hexdigest()


def create_oauth_handle_cookie_value(
    state_hash: str,
    existing_cookie: Optional[str] = None,
) -> str:
    """
    Package opaque random lookup handles into a signed JWT for cookie storage.
    Contains ONLY state hashes — NEVER the PKCE code_verifier or nonce (SEC-OAUTH-01 remediation).
    Supports multiple simultaneous browser-tab login attempts.
    """
    now_utc = datetime.now(timezone.utc)
    active_handles = []

    if existing_cookie:
        try:
            payload = jwt.decode(existing_cookie, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            handles = payload.get("handles", [])
            if isinstance(handles, list):
                active_handles = [h for h in handles if isinstance(h, str)]
            elif isinstance(payload.get("handle"), str):
                active_handles = [payload["handle"]]
        except Exception:
            pass

    if state_hash not in active_handles:
        active_handles.append(state_hash)

    # Retain at most the 5 most recent pending state handles
    active_handles = active_handles[-5:]

    payload = {
        "handles": active_handles,
        "exp": now_utc + timedelta(minutes=10),
        "iat": now_utc,
        "purpose": "google_oauth_handle",
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_oauth_handle_in_cookie(
    state_hash: str,
    cookie_val: Optional[str],
) -> bool:
    """
    Verify that the given state_hash is bound to the client's HttpOnly cookie.
    Protects against Login CSRF while allowing multiple concurrent tabs.
    """
    if not cookie_val:
        return False
    try:
        payload = jwt.decode(cookie_val, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        purpose = payload.get("purpose")
        if purpose == "google_oauth_handle":
            handles = payload.get("handles", [])
            return state_hash in handles
        # Legacy/fallback handling
        if payload.get("state") == state_hash or payload.get("handle") == state_hash:
            return True
        return False
    except Exception:
        if cookie_val == state_hash:
            return True
        return False


def create_oauth_state_cookie_value(state: str, nonce: str, code_verifier: str) -> str:
    """Deprecated legacy helper: retained for backward compatibility with older tests."""
    state_hash = compute_state_hash(state)
    return create_oauth_handle_cookie_value(state_hash)


def decode_and_verify_oauth_state(cookie_val: str) -> Dict[str, Any]:
    """Deprecated legacy helper: retained for backward compatibility with older tests."""
    try:
        payload = jwt.decode(cookie_val, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception as exc:
        raise ValueError(f"Invalid OAuth state cookie: {exc}")


def build_google_authorization_url(state: str, nonce: str, code_challenge: str) -> str:
    """
    Build official Google OAuth 2.0 authorization URL.
    Requests strictly openid, email, and profile scopes.
    """
    client_id = get_google_client_id()
    if not client_id:
        raise ValueError("Google Client ID is not configured.")

    params = {
        "client_id": client_id,
        "redirect_uri": get_google_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def exchange_code_for_tokens(
    code: str,
    code_verifier: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    redirect_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Exchange authorization code server-side for tokens at Google's token endpoint.
    Transmits PKCE code_verifier. Never logs client_secret or authorization code.
    """
    c_id = client_id or get_google_client_id()
    c_secret = client_secret or get_google_client_secret()
    r_uri = redirect_uri or get_google_redirect_uri()

    if not c_id or not c_secret:
        raise ValueError("Google OAuth credentials are not configured.")

    payload = {
        "code": code,
        "client_id": c_id,
        "client_secret": c_secret,
        "redirect_uri": r_uri,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }

    try:
        resp = requests.post(
            GOOGLE_TOKEN_ENDPOINT,
            data=payload,
            headers={"Accept": "application/json"},
            timeout=10.0,
        )
    except Exception as exc:
        logger.error(f"Network error during Google token exchange: {exc}")
        raise ValueError("Network error contacting Google token service.") from exc

    if resp.status_code != 200:
        logger.warning(f"Google token exchange failed: HTTP {resp.status_code}")
        raise ValueError(f"Google token exchange returned status {resp.status_code}")

    try:
        return resp.json()
    except Exception as exc:
        raise ValueError("Failed to parse Google token exchange response.") from exc


def verify_google_id_token(
    id_token_str: str,
    expected_nonce: Optional[str] = None,
    client_id: Optional[str] = None,
    request_adapter: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Verify and validate Google ID token cryptographically using google-auth library.
    Validates:
      - Cryptographic signature against Google's public certs
      - Token expiration
      - Audience matches configured GOOGLE_CLIENT_ID
      - Issuer is Google
      - Nonce matches expected OAuth session nonce
      - Email is verified (email_verified=true)
      - Sub (subject) and email claims exist
    """
    c_id = client_id or get_google_client_id()
    if not c_id:
        raise ValueError("Google Client ID is not configured.")

    req = request_adapter or google_requests.Request()
    try:
        # Allow up to 10 seconds of clock skew between local machine and Google's auth servers
        id_info = google_id_token.verify_oauth2_token(
            id_token_str,
            req,
            audience=c_id,
            clock_skew_in_seconds=10,
        )
    except (GoogleAuthError, ValueError) as exc:
        raise ValueError(f"Invalid Google ID token: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Google ID token verification failed: {exc}") from exc

    # 1. Validate issuer
    issuer = id_info.get("iss")
    if issuer not in ("accounts.google.com", "https://accounts.google.com"):
        raise ValueError(f"Invalid Google ID token issuer: {issuer}")

    # 2. Validate nonce
    if expected_nonce:
        token_nonce = id_info.get("nonce")
        if not token_nonce or not secrets.compare_digest(token_nonce, expected_nonce):
            raise ValueError("ID token nonce does not match expected OAuth session nonce.")

    # 3. Validate verified email
    email_verified = id_info.get("email_verified")
    if not (email_verified is True or str(email_verified).lower() == "true"):
        raise ValueError("Google email address is not verified.")

    # 4. Validate subject and email presence
    if not id_info.get("email"):
        raise ValueError("Google ID token missing email claim.")
    if not id_info.get("sub"):
        raise ValueError("Google ID token missing subject (sub) claim.")

    return id_info

