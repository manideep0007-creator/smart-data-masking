import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import jwt
from fastapi import Cookie, Header, HTTPException, Request, status
from pydantic import BaseModel

from backend.auth_db import (
    _DUMMY_BCRYPT_HASH,
    get_auth_connection,
    get_user_by_username,
    hash_password,
    init_auth_db,
    is_account_locked,
    is_token_revoked,
    record_login_failure,
    record_login_success,
    revoke_token,
    verify_password,
)

# Configuration & Environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
FORCE_HTTPS_COOKIE = os.getenv("FORCE_HTTPS_COOKIE", "false").lower() in ("true", "1", "yes")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

_DEFAULT_DEV_SECRET = "dev-insecure-secret-key-change-in-production-bfsi-2026"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", _DEFAULT_DEV_SECRET)

if ENVIRONMENT == "production" and (not JWT_SECRET_KEY or JWT_SECRET_KEY == _DEFAULT_DEV_SECRET):
    raise RuntimeError(
        "CRITICAL SECURITY CONFIGURATION ERROR: Production mode requires an explicit, secure JWT_SECRET_KEY environment variable."
    )

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
TRUSTED_PROXIES = [p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()]

# Initialize the auth DB schema on startup
init_auth_db()


def is_cookie_secure() -> bool:
    """
    Return whether session and CSRF cookies must have the Secure flag enabled.
    Strictly true in production to prevent cookie leakage over unencrypted channels.
    """
    env = os.getenv("ENVIRONMENT", ENVIRONMENT).lower()
    if env == "production":
        return True
    return os.getenv("FORCE_HTTPS_COOKIE", str(FORCE_HTTPS_COOKIE)).lower() in ("true", "1", "yes")


def generate_csrf_token() -> str:
    """Generate a cryptographically secure, URL-safe random CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(request: Request, cookie_csrf: Optional[str] = None) -> bool:
    """
    Verify double-submit CSRF token on state-changing requests.
    Compares the header X-CSRF-Token against the csrf_token cookie in constant time.
    """
    header_csrf = request.headers.get("X-CSRF-Token")
    cookie_val = cookie_csrf or request.cookies.get("csrf_token")
    if not header_csrf or not cookie_val:
        return False
    return secrets.compare_digest(header_csrf.strip(), cookie_val.strip())


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address safely.
    Only trusts X-Forwarded-For if request.client.host is in TRUSTED_PROXIES.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"
    if TRUSTED_PROXIES and peer_ip in TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer_ip


class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in_minutes: int
    csrf_token: Optional[str] = None
    user: Dict[str, Any]


class LoginRequest(BaseModel):
    username: str
    password: str


class SafeUserItem(BaseModel):
    username: str
    full_name: str
    role: str
    email: Optional[str] = None
    is_active: int = 1


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT token with unique jti, expiry, and authoritative role claim."""
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    expire = now_utc + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = to_encode.get("jti") or uuid.uuid4().hex

    to_encode.update({
        "jti": jti,
        "exp": expire,
        "iat": now_utc,
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token, verifying signature, expiry, and revocation status."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed token: missing unique token identifier (jti).",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check server-side token revocation table
        if is_token_revoked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked. Please sign in again.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if "sub" not in payload or "role" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed token claims: missing subject or role.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def authenticate_user(username: str, password: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Authenticate username and password against database-backed user store.
    Mitigates timing attacks and enforces account lockout.
    Returns (user_dict, error_message).
    """
    clean_username = username.strip().lower()
    user = get_user_by_username(clean_username)

    if not user:
        # Perform dummy bcrypt calculation to prevent timing attack enumeration
        verify_password("dummy_password", _DUMMY_BCRYPT_HASH)
        return None, "Invalid username or password."

    if not user.get("is_active", 1):
        return None, "User account is disabled. Please contact system administrator."

    is_locked, lock_msg = is_account_locked(user)
    if is_locked:
        return None, lock_msg or "Account is temporarily locked. Please try again later."

    if not verify_password(password, user["password_hash"]):
        is_now_locked = record_login_failure(clean_username)
        if is_now_locked:
            return None, "Too many failed attempts. Account has been temporarily locked."
        return None, "Invalid username or password."

    # Login succeeded: reset failed attempts
    record_login_success(user["id"])
    return user, None


def get_safe_user_list() -> List[Dict[str, Any]]:
    """Return user accounts from database WITHOUT exposing password hashes or sensitive auth internals."""
    conn = get_auth_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, email, full_name, role, is_active, last_login
            FROM users
            ORDER BY id ASC
        """)
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def resolve_auth_context(
    authorization: Optional[str] = Header(None),
    cookie_token: Optional[str] = None,
    requested_role: Optional[str] = None,
    request: Optional[Request] = None,
) -> Dict[str, Any]:
    """
    Resolve identity and role strictly from authenticated token (Bearer header or HttpOnly cookie).
    Validates that user account exists and remains active in database.
    Enforces CSRF token validation for cookie-authenticated state-changing requests.
    """
    token = None
    auth_mode = None

    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
            auth_mode = "bearer"
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header. Format must be 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif cookie_token:
        token = cookie_token
        auth_mode = "cookie"

    if token:
        # Enforce CSRF protection on cookie-authenticated state-changing operations
        if auth_mode == "cookie" and request is not None:
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                if not verify_csrf_token(request):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="CSRF token validation failed. Please provide a valid X-CSRF-Token header.",
                    )

        payload = decode_access_token(token)
        username = payload.get("sub")

        # Validate that user still exists and is active in database
        db_user = get_user_by_username(username)
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account no longer exists in authentication database.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not db_user.get("is_active", 1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is deactivated. Access revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Enforce authoritative role stored in database
        db_role = db_user.get("role", payload.get("role", "Support")).strip().capitalize()

        return {
            "authenticated": True,
            "user_id": db_user.get("id"),
            "username": db_user.get("username"),
            "email": db_user.get("email"),
            "role": db_role,
            "source": "jwt_verified",
            "auth_mode": auth_mode,
            "full_name": db_user.get("full_name", payload.get("full_name")),
            "jti": payload.get("jti"),
        }

    # Strict enterprise enforcement: missing authentication rejected with HTTP 401
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please sign in with valid credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
