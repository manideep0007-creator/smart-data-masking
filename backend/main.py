import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse
from dotenv import load_dotenv

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")
if os.path.exists(_ENV_PATH):
    load_dotenv(_ENV_PATH)

from fastapi import Cookie, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from backend.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    DEMO_MODE,
    ENVIRONMENT,
    LoginRequest,
    SafeUserItem,
    TokenResponse,
    authenticate_user,
    create_access_token,
    decode_access_token,
    generate_csrf_token,
    get_client_ip,
    get_safe_user_list,
    is_cookie_secure,
    resolve_auth_context,
    verify_csrf_token,
)
from backend.auth_db import (
    consume_pending_oauth_state,
    get_oauth_mapping_by_user_id,
    get_user_by_oauth_sub,
    get_users_by_email,
    is_account_locked,
    is_ip_rate_limited,
    link_user_oauth,
    record_auth_audit,
    record_ip_attempt,
    revoke_token,
    store_pending_oauth_state,
    update_oauth_last_login,
)
from backend.google_oauth import (
    build_google_authorization_url,
    compute_state_hash,
    create_oauth_handle_cookie_value,
    create_oauth_state_cookie_value,
    decode_and_verify_oauth_state,
    exchange_code_for_tokens,
    generate_pkce_pair,
    get_frontend_url,
    get_google_client_id,
    get_google_redirect_uri,
    is_google_oauth_configured,
    verify_google_id_token,
    verify_oauth_handle_in_cookie,
)
from backend.database import get_database_adapter
from backend.db import DEFAULT_DB_PATH, init_db
from backend.detector import classify_column
from backend.masker import VALID_ROLES, mask_query_results
from backend.registry import registry
from backend.scanner import background_scanner
from backend.validator import MAX_QUERY_ROWS_DEFAULT, validate_sql

# Configure logging (ensuring raw PII is never logged)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("smart_masking_gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database with sample records upon startup
    init_db()
    logger.info("Customer database initialized with demo records.")
    # Run initial schema scan into registry in background
    try:
        background_scanner.start_scan("customers")
    except Exception as exc:
        logger.warning(f"Initial schema scan skipped: {exc}")
    yield


app = FastAPI(
    title="PII Shield – Smart Data Masking System",
    description="Role-based query masking gateway detecting PII and applying dynamic in-flight masking with database abstraction and JWT authentication.",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS Configuration (SEC-08)
raw_origins = [orig.strip() for orig in os.getenv("ALLOWED_ORIGINS", "").split(",") if orig.strip()]

if ENVIRONMENT == "production":
    if not raw_origins:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: Production mode requires explicit, non-empty ALLOWED_ORIGINS."
        )
    if "*" in raw_origins:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: Wildcard origin '*' is forbidden when credentials are enabled."
        )
    ALLOWED_ORIGINS = raw_origins
else:
    _LOCAL_ORIGINS = [
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]
    ALLOWED_ORIGINS = list(dict.fromkeys(_LOCAL_ORIGINS + raw_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Auth-Mode"],
)


# --- Schemas ---

class HealthResponse(BaseModel):
    status: str
    database: str
    engine: str
    version: str


class ColumnScanItem(BaseModel):
    name: str = Field(..., description="Column name")
    tag: str = Field(..., description="Classification tag (e.g. FINANCIAL_CONFIDENTIAL, PII_HIGH, PII_MEDIUM, PII_LOW, PUBLIC)")
    pii_type: str = Field(..., description="Category of PII detected (CREDIT_CARD, SSN, AADHAAR, PAN, EMAIL, PHONE, etc.)")
    confidence: str = Field(..., description="Detection confidence level (HIGH, MEDIUM, LOW)")
    sensitivity: str = Field(..., description="Risk sensitivity tier (HIGH, MEDIUM, LOW, NONE)")
    heuristic: str = Field(..., description="Rule or pattern that triggered classification")


class ScanResponse(BaseModel):
    table: str
    total_columns: int
    columns: List[ColumnScanItem]


class QueryRequest(BaseModel):
    role: Optional[str] = Field("Support", description="Requested role (Admin, Support, Analyst). In authenticated mode, verified JWT role overrides this.", examples=["Support"])
    sql: str = Field(..., description="Read-only SELECT query", examples=["SELECT name, card_number FROM customers"])
    mask_strategy: Optional[str] = Field("redact", description="Masking strategy for Analyst: 'redact' or 'hash'", examples=["redact"])
    max_rows: Optional[int] = Field(MAX_QUERY_ROWS_DEFAULT, description="Maximum rows to fetch safely", examples=[1000])


class QueryResponse(BaseModel):
    columns: List[str]
    rows: List[List[Any]]
    meta: Optional[Dict[str, Any]] = None


# --- Authentication Endpoints ---

@app.post("/auth/login", response_model=TokenResponse, summary="Sign in and obtain session cookie or API token")
def login(
    req: LoginRequest,
    response: Response,
    request: Request,
    x_auth_mode: Optional[str] = Header(None),
):
    """
    Authenticate user credentials against database and issue HttpOnly session cookie.
    Enforces IP-based failed login rate limiting and per-account lockout.
    Exposes access_token in JSON body only if explicit non-browser API mode is requested.
    """
    # 1. IP rate limiting check (SEC-05)
    client_ip = get_client_ip(request)
    is_limited, limit_msg = is_ip_rate_limited(client_ip, max_attempts=10, window_minutes=5)
    if is_limited:
        logger.warning(f"Login rate limit exceeded for client IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=limit_msg or "Too many failed login attempts from this network. Please try again later.",
        )

    # 2. Authenticate credentials
    user, err_msg = authenticate_user(req.username, req.password)
    if not user:
        record_ip_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err_msg or "Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {
        "sub": user["username"],
        "role": user["role"],
        "full_name": user["full_name"],
        "email": user.get("email"),
    }
    access_token = create_access_token(token_data)
    csrf_tok = generate_csrf_token()
    cookie_secure = is_cookie_secure()

    # 3. Set HttpOnly session cookie (SEC-01 & SEC-04)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=cookie_secure,
        path="/",
    )

    # 4. Set Double-Submit CSRF cookie (SEC-03)
    response.set_cookie(
        key="csrf_token",
        value=csrf_tok,
        httponly=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=cookie_secure,
        path="/",
    )

    logger.info(f"User '{user['username']}' authenticated successfully with role '{user['role']}' from IP {client_ip}")

    # Explicit non-browser API mode check (SEC-01)
    is_api_client = (x_auth_mode and x_auth_mode.lower() == "api") or (request.query_params.get("api_client") == "true")

    return TokenResponse(
        access_token=access_token if is_api_client else None,
        token_type="bearer",
        expires_in_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        csrf_token=csrf_tok,
        user={
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "email": user.get("email"),
        },
    )


@app.get("/auth/csrf", summary="Obtain a fresh CSRF token")
def get_csrf_token_endpoint(response: Response):
    """Issue a new CSRF token and set the csrf_token cookie (SEC-03)."""
    csrf_tok = generate_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=csrf_tok,
        httponly=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=is_cookie_secure(),
        path="/",
    )
    return {"csrf_token": csrf_tok}


@app.post("/auth/logout", summary="Sign out and revoke active session and access token")
def logout(
    response: Response,
    request: Request,
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """Revoke active JWT token server-side and clear session and CSRF cookies."""
    # Enforce CSRF if authenticating via cookie
    if access_token and not authorization:
        if not verify_csrf_token(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed on logout.",
            )

    token = None
    if authorization and authorization.strip().lower().startswith("bearer "):
        token = authorization.strip().split(" ", 1)[1]
    elif access_token:
        token = access_token

    if token:
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                revoke_token(jti, expires_at)
        except Exception:
            pass

    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="csrf_token", path="/")
    return {"status": "ok", "message": "Successfully logged out. Session revoked."}


# --- Google OAuth 2.0 / OpenID Connect Endpoints ---

@app.get("/auth/google/status", summary="Check Google OAuth 2.0 / OIDC status")
def google_oauth_status():
    """
    Returns whether Google OAuth 2.0 / OpenID Connect is configured.
    Never exposes client secret.
    """
    configured = is_google_oauth_configured()
    return {
        "enabled": configured,
        "client_id": get_google_client_id() if configured else None,
        "redirect_uri": get_google_redirect_uri() if configured else None,
    }


@app.get("/auth/google/login", summary="Initiate Google OAuth 2.0 authorization code flow")
def google_oauth_login(request: Request):
    """
    Initiate Google OpenID Connect flow:
    - Generates cryptographically secure state, nonce, and PKCE S256 verifier/challenge.
    - Stores state_hash, nonce, code_verifier in server-side SQLite (SEC-OAUTH-01 remediation).
    - Sets ONLY an opaque random lookup handle in short-lived HttpOnly cookie.
    - Supports multiple independent browser-tab login attempts.
    - Redirects user to Google's official authorization screen.
    """
    frontend_url = get_frontend_url()
    if not is_google_oauth_configured():
        err_msg = "Google sign-in is not configured on this server."
        return RedirectResponse(f"{frontend_url}/?auth_error={quote(err_msg)}", status_code=302)

    # Ensure browser is on the canonical hostname matching GOOGLE_REDIRECT_URI
    # so the oauth_state cookie is attached to the same domain as the OAuth callback.
    # (Prevents localhost vs 127.0.0.1 cookie partition / CSRF mismatch)
    redirect_uri = get_google_redirect_uri()
    parsed_redirect = urlparse(redirect_uri)
    expected_host = parsed_redirect.hostname
    current_host = request.url.hostname
    if (
        expected_host in ("localhost", "127.0.0.1")
        and current_host in ("localhost", "127.0.0.1")
        and expected_host != current_host
    ):
        target_port = parsed_redirect.port or request.url.port or 8000
        scheme = parsed_redirect.scheme or "http"
        canonical_url = f"{scheme}://{expected_host}:{target_port}/auth/google/login"
        return RedirectResponse(canonical_url, status_code=302)

    raw_state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    state_hash = compute_state_hash(raw_state)

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    store_pending_oauth_state(state_hash, nonce, code_verifier, expires_at)

    existing_cookie = request.cookies.get("oauth_state")
    cookie_val = create_oauth_handle_cookie_value(state_hash, existing_cookie=existing_cookie)
    google_url = build_google_authorization_url(raw_state, nonce, code_challenge)

    response = RedirectResponse(google_url, status_code=302)
    response.set_cookie(
        key="oauth_state",
        value=cookie_val,
        httponly=True,
        samesite="lax",
        secure=is_cookie_secure(),
        max_age=600,
        path="/",
    )
    return response


@app.get("/auth/google/callback", summary="Google OAuth 2.0 authorization code callback")
def google_oauth_callback(
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    oauth_state: Optional[str] = Cookie(None),
):
    """
    Process Google OAuth callback:
    - Validates state handle against client cookie and server-side pending record.
    - Atomically consumes pending record from database to prevent replay or concurrency races.
    - Server-side code exchange with Google token endpoint using retrieved verifier.
    - Verifies ID token signature, issuer, audience, expiry, and nonce.
    - Maps verified email / subject to exactly one existing PII Shield user.
    - Enforces role preservation and unique subject binding.
    - Issues HttpOnly session cookie and CSRF cookie.
    - Redirects to frontend authenticated dashboard.
    """
    frontend_url = get_frontend_url()
    client_ip = get_client_ip(request)

    def error_redirect(msg: str) -> RedirectResponse:
        record_auth_audit(
            event_type="OAUTH_LOGIN_FAILED",
            status="FAILED",
            provider="google",
            ip_address=client_ip,
            detail=msg,
        )
        safe_url = f"{frontend_url}/?auth_error={quote(msg)}"
        resp = RedirectResponse(safe_url, status_code=302)
        resp.delete_cookie("oauth_state", path="/")
        return resp

    # 1. Provider error check
    if error:
        logger.warning(f"Google OAuth error received from IP {client_ip}: {error} ({error_description})")
        return error_redirect("Google sign-in was cancelled or denied.")

    # 2. State & Code presence
    if not state:
        logger.warning(f"OAuth callback missing state parameter from IP {client_ip}")
        return error_redirect("State parameter missing from Google response.")

    if not code:
        logger.warning(f"OAuth callback missing authorization code from IP {client_ip}")
        return error_redirect("Authorization code missing from Google response.")

    state_hash = compute_state_hash(state)

    # 3. Client cookie verification (Login CSRF check)
    if not oauth_state or not verify_oauth_handle_in_cookie(state_hash, oauth_state):
        logger.warning(f"OAuth state handle missing or invalid in cookie from IP {client_ip}")
        return error_redirect("Invalid OAuth state parameter. Potential CSRF detected.")

    # 4. Atomically consume server-side pending record (Replay & concurrency mitigation)
    pending_record = consume_pending_oauth_state(state_hash)
    if not pending_record:
        logger.warning(f"OAuth state {state_hash[:8]}... not found, expired, or already consumed from IP {client_ip}")
        return error_redirect("Invalid, expired, or already-consumed OAuth state.")

    stored_nonce = pending_record["nonce"]
    stored_code_verifier = pending_record["code_verifier"]

    # 5. Server-side token exchange using retrieved verifier
    try:
        token_payload = exchange_code_for_tokens(code.strip(), stored_code_verifier)
    except ValueError as exc:
        logger.warning(f"Google token exchange failed from IP {client_ip}: {exc}")
        return error_redirect("Failed to exchange authorization code with Google.")

    id_token_raw = token_payload.get("id_token")
    if not id_token_raw:
        logger.warning(f"Token response missing id_token from IP {client_ip}")
        return error_redirect("Google response missing ID token.")

    # 6. ID token cryptographic validation
    try:
        id_info = verify_google_id_token(id_token_raw, expected_nonce=stored_nonce)
    except ValueError as exc:
        logger.warning(f"Google ID token verification failed from IP {client_ip}: {exc}")
        return error_redirect(str(exc))

    google_sub = str(id_info["sub"]).strip()
    google_email = str(id_info["email"]).strip().lower()

    # 7. Account resolution:
    # Rule 8: Once linked, use the Google sub as the stable provider identity.
    mapped_user = get_user_by_oauth_sub("google", google_sub)
    if mapped_user:
        if not mapped_user.get("is_active", 1):
            return error_redirect("User account is disabled. Please contact system administrator.")

        is_locked, lock_msg = is_account_locked(mapped_user)
        if is_locked:
            return error_redirect(lock_msg or "Account is temporarily locked. Please try again later.")

        update_oauth_last_login(mapped_user["id"], "google")
        user = mapped_user

        record_auth_audit(
            event_type="OAUTH_LOGIN_SUCCESS",
            status="SUCCESS",
            user_id=user["id"],
            username=user["username"],
            provider="google",
            provider_sub=google_sub,
            email=google_email,
            ip_address=client_ip,
            detail="Authenticated via previously linked Google identity",
        )
    else:
        # First-time linking: find existing active PII Shield user by normalized verified email
        matching_users = get_users_by_email(google_email)
        if len(matching_users) == 0:
            logger.info(f"Unregistered Google login attempt for email {google_email} from IP {client_ip}")
            # Exact required text from Section 3, Rule 3
            return error_redirect("Your Google account is not registered with PII Shield. Contact your administrator.")

        if len(matching_users) > 1:
            logger.error(f"Ambiguous account collision: {len(matching_users)} accounts for email {google_email}")
            return error_redirect("Multiple accounts found for this email address. Please contact your administrator.")

        target_user = matching_users[0]
        if not target_user.get("is_active", 1):
            return error_redirect("User account is disabled. Please contact system administrator.")

        is_locked, lock_msg = is_account_locked(target_user)
        if is_locked:
            return error_redirect(lock_msg or "Account is temporarily locked. Please try again later.")

        # Check if local user is already linked to a DIFFERENT Google sub (Rule 9)
        existing_mapping = get_oauth_mapping_by_user_id(target_user["id"], "google")
        if existing_mapping and existing_mapping["provider_sub"] != google_sub:
            logger.warning(f"User {target_user['username']} already linked to a different Google sub")
            return error_redirect("Local account is already linked to a different Google account.")

        # Link account
        try:
            link_user_oauth(
                user_id=target_user["id"],
                provider="google",
                provider_sub=google_sub,
                email=google_email,
            )
        except Exception as exc:
            logger.error(f"Failed to link Google account to local profile: {exc}")
            return error_redirect("Failed to link Google account to local profile.")

        user = target_user
        record_auth_audit(
            event_type="OAUTH_ACCOUNT_LINKED",
            status="SUCCESS",
            user_id=user["id"],
            username=user["username"],
            provider="google",
            provider_sub=google_sub,
            email=google_email,
            ip_address=client_ip,
            detail=f"Linked Google identity (sub={google_sub}) to user {user['username']}",
        )
        record_auth_audit(
            event_type="OAUTH_LOGIN_SUCCESS",
            status="SUCCESS",
            user_id=user["id"],
            username=user["username"],
            provider="google",
            provider_sub=google_sub,
            email=google_email,
            ip_address=client_ip,
            detail="Authenticated and established session",
        )

    # 8. Create standard PII Shield session
    token_data = {
        "sub": user["username"],
        "role": user["role"],
        "full_name": user["full_name"],
        "email": user.get("email"),
    }
    session_jwt = create_access_token(token_data)
    csrf_tok = generate_csrf_token()
    cookie_secure = is_cookie_secure()

    redirect_resp = RedirectResponse(f"{frontend_url}/", status_code=302)
    redirect_resp.set_cookie(
        key="access_token",
        value=session_jwt,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=cookie_secure,
        path="/",
    )
    redirect_resp.set_cookie(
        key="csrf_token",
        value=csrf_tok,
        httponly=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=cookie_secure,
        path="/",
    )
    # Delete temporary OAuth state cookie (callback replay prevention)
    redirect_resp.delete_cookie("oauth_state", path="/")
    logger.info(f"User '{user['username']}' authenticated via Google OAuth successfully from IP {client_ip}")
    return redirect_resp


@app.get("/auth/me", summary="Get authenticated user profile from verified JWT")
def get_current_user_profile(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """Extract authenticated identity and verified role from Bearer JWT token or cookie."""
    auth_ctx = resolve_auth_context(authorization=authorization, cookie_token=access_token)
    return {
        "username": auth_ctx.get("username"),
        "role": auth_ctx.get("role"),
        "full_name": auth_ctx.get("full_name"),
        "email": auth_ctx.get("email"),
        "authenticated": True,
    }


@app.get("/auth/users", summary="List user accounts (Admin only)")
def list_demo_users(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """
    Return configured user accounts without exposing passwords or hashes.
    Strictly requires Admin role (SEC-02).
    """
    auth_ctx = resolve_auth_context(authorization=authorization, cookie_token=access_token)
    if auth_ctx.get("role") != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin privileges required to inspect user accounts.",
        )
    return {
        "demo_mode_active": DEMO_MODE,
        "users": get_safe_user_list(),
    }


# --- Database & Health Endpoints ---

@app.get("/", summary="Root index")
def root():
    return {
        "service": "PII Shield – Smart Data Masking System",
        "version": "2.0.0",
        "status": "online",
        "demo_mode": DEMO_MODE,
        "environment": ENVIRONMENT,
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "database_info": "/database/info",
            "scan": "/scan (Admin only)",
            "scan_summary": "/scan/summary",
            "background_scan_start": "/scan/start (POST, Admin only)",
            "background_scan_status": "/scan/status",
            "background_scan_history": "/scan/history",
            "csrf": "/auth/csrf",
            "login": "/auth/login (POST)",
            "logout": "/auth/logout (POST)",
            "auth_me": "/auth/me",
            "auth_users": "/auth/users (Admin only)",
            "google_oauth_status": "/auth/google/status",
            "google_oauth_login": "/auth/google/login",
            "google_oauth_callback": "/auth/google/callback",
            "query": "/query (POST)",
        },
    }


@app.get("/health", response_model=HealthResponse, summary="Service health check")
def health_check():
    """Verify that the API is active and the database adapter is operational."""
    adapter = get_database_adapter()
    conn_info = adapter.test_connection()
    is_ok = conn_info.get("status") == "connected"

    return HealthResponse(
        status="ok" if is_ok else "degraded",
        database="connected" if is_ok else "error",
        engine=conn_info.get("engine", "unknown"),
        version="2.0.0",
    )


@app.get("/database/info", summary="Inspect active database connection and engine metadata")
def database_info(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """Return database engine status, available tables, and read-only safeguards. Requires authentication."""
    resolve_auth_context(authorization=authorization, cookie_token=access_token)
    adapter = get_database_adapter()
    status_info = adapter.test_connection()
    tables = []
    table_details = []
    if status_info.get("status") == "connected":
        try:
            tables = adapter.get_tables()
            for t in tables:
                cols = adapter.get_table_columns(t)
                try:
                    _, r, _ = adapter.execute_read_query(f"SELECT COUNT(*) FROM {t}")
                    row_count = r[0][0] if r else 0
                except Exception:
                    row_count = 0
                table_details.append({
                    "name": t,
                    "columns_count": len(cols),
                    "row_count": row_count,
                })
        except Exception:
            pass
    return {
        "connection": status_info,
        "tables": tables,
        "table_details": table_details,
        "total_tables": len(tables),
    }


# --- Scanning Endpoints ---

@app.get("/scan", response_model=ScanResponse, summary="Scan database columns for PII (Admin only)")
def scan_schema(
    table: str = "customers",
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """
    Inspect the schema of the specified table, heuristically detecting
    potential PII and returning classified tags and sensitivity levels.
    Strictly restricted to Admin role (SEC-07).
    """
    auth_ctx = resolve_auth_context(authorization=authorization, cookie_token=access_token)
    if auth_ctx.get("role") != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Detailed schema classification scan is restricted to Admin role.",
        )

    adapter = get_database_adapter()
    tables = adapter.get_tables()

    matched_tables = [t for t in tables if t.lower() == table.lower()]
    if not matched_tables:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Table '{table}' not found in database. Available tables: {', '.join(tables)}",
        )
    actual_table = matched_tables[0]

    col_names = adapter.get_table_columns(actual_table)
    sample_rows = adapter.get_sample_rows(actual_table, limit=10)

    scan_items: List[ColumnScanItem] = []
    tag_to_sensitivity = {
        "FINANCIAL_CONFIDENTIAL": "HIGH",
        "PII_HIGH": "HIGH",
        "PII_MEDIUM": "MEDIUM",
        "PII_LOW": "LOW",
        "PUBLIC": "NONE",
    }

    for idx, col_name in enumerate(col_names):
        samples = [r[idx] for r in sample_rows if idx < len(r)]
        res = classify_column(col_name, samples)
        scan_items.append(
            ColumnScanItem(
                name=col_name,
                tag=res["tag"],
                pii_type=res["pii_type"],
                confidence=res["confidence"],
                sensitivity=tag_to_sensitivity.get(res["tag"], "LOW"),
                heuristic=res["heuristic"],
            )
        )

    # Register into metadata registry
    registry.register_table_scan(actual_table, [item.model_dump() for item in scan_items])

    return ScanResponse(
        table=actual_table,
        total_columns=len(scan_items),
        columns=scan_items,
    )


@app.get("/scan/summary", summary="Sanitized database schema summary for dashboards")
def scan_summary(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """
    Return high-level table names and column counts without exposing sensitive PII
    taxonomies, tags, or classification heuristics. Accessible to all authenticated roles (SEC-07).
    """
    resolve_auth_context(authorization=authorization, cookie_token=access_token)
    adapter = get_database_adapter()
    tables = adapter.get_tables()
    summary_list = []
    for t in tables:
        cols = adapter.get_table_columns(t)
        summary_list.append({
            "table": t,
            "column_count": len(cols),
        })
    return {"tables": summary_list, "total_tables": len(tables)}


@app.post("/scan/start", summary="Trigger an asynchronous background PII discovery scan (Admin only)")
def trigger_background_scan(
    request: Request,
    table: Optional[str] = Query(None, description="Optional specific table name to scan"),
    sample_limit: Optional[int] = Query(10, description="Sample rows per table for heuristic evaluation"),
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """
    Trigger background scan without blocking ordinary queries.
    Strictly requires Admin authorization and CSRF validation for cookie sessions (SEC-03 & SEC-07).
    """
    auth_ctx = resolve_auth_context(
        authorization=authorization,
        cookie_token=access_token,
        request=request,
    )
    if auth_ctx.get("role") != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators may trigger background schema scans.",
        )

    try:
        result = background_scanner.start_scan(
            table_name=table, sample_limit=sample_limit or 10
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@app.get("/scan/status", summary="Get status and progress of the background PII scanner")
def get_scan_status(
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """Retrieve current background scanner task status. Requires authentication."""
    resolve_auth_context(authorization=authorization, cookie_token=access_token)
    return background_scanner.get_status()


@app.get("/scan/history", summary="Get audit log of recent background scans")
def get_scan_history(
    limit: int = 10,
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """Retrieve history of past background scans. Requires authentication."""
    resolve_auth_context(authorization=authorization, cookie_token=access_token)
    return {"history": background_scanner.get_history(limit=limit)}


# --- Query Operations Gateway ---

@app.post("/query", response_model=QueryResponse, summary="Execute query with role-based masking")
def execute_query(
    req: QueryRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Cookie(None),
):
    """
    Execute a read-only SELECT query through the gateway.
    Derives role from verified JWT or cookie, preventing frontend tampering.
    Enforces CSRF token validation when cookie authentication is utilized.
    Results are dynamically masked in memory without mutating stored records.
    """
    # Validate requested role parameter format if supplied (case-insensitive)
    if req.role and req.role.strip().capitalize() not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{req.role}'. Allowed roles are: {', '.join(sorted(VALID_ROLES))}."
        )

    # 1. Resolve role from verified JWT or cookie strictly, validating CSRF if cookie-based
    auth_ctx = resolve_auth_context(
        authorization=authorization,
        cookie_token=access_token,
        request=request,
    )
    effective_role = auth_ctx["role"]

    if effective_role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{effective_role}'. Allowed roles are: {', '.join(sorted(VALID_ROLES))}."
        )

    # 2. Validate SQL query (read-only SELECT/WITH, single statement, no comments)
    is_valid, err_msg = validate_sql(req.sql)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query rejected: {err_msg}"
        )

    # 3. Log query metadata without logging raw PII
    logger.info(
        f"Processing query for user='{auth_ctx.get('username')}' role='{effective_role}' "
        f"(source={auth_ctx.get('source')}, auth_mode={auth_ctx.get('auth_mode')}) | query_len={len(req.sql)}"
    )

    # 4. Execute query using database adapter with safety safeguards
    adapter = get_database_adapter()
    try:
        max_rows = min(req.max_rows or MAX_QUERY_ROWS_DEFAULT, 5000)
        columns, raw_rows, query_meta = adapter.execute_read_query(
            sql=req.sql, max_rows=max_rows, timeout_seconds=10
        )
    except sqlite3.DatabaseError as exc:
        logger.warning(f"Database error executing query: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database execution error: query was rejected by database engine or authorizer."
        )
    except Exception as exc:
        err_str = str(exc)
        if "syntax" in err_str.lower() or "no such table" in err_str.lower() or "no such column" in err_str.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Database execution error: {exc}"
            )
        logger.error(f"Unexpected error executing query: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while executing the query."
        )

    # 5. Apply role-based dynamic masking in-memory
    mask_strategy = req.mask_strategy or "redact"
    masked_rows = mask_query_results(
        role=effective_role,
        columns=columns,
        rows=raw_rows,
        mask_strategy=mask_strategy,
    )

    execution_meta = {
        "role_applied": effective_role,
        "auth_source": auth_ctx.get("source"),
        "auth_mode": auth_ctx.get("auth_mode"),
        "mask_strategy": mask_strategy,
        "rows_returned": len(masked_rows),
        "execution_ms": query_meta.get("execution_ms", 0.0),
        "truncated": query_meta.get("truncated", False),
    }

    logger.info(
        f"Query executed for role '{effective_role}': returned_columns={len(columns)} "
        f"returned_rows={len(masked_rows)} execution_ms={query_meta.get('execution_ms')}"
    )

    return QueryResponse(columns=columns, rows=masked_rows, meta=execution_meta)
