import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import bcrypt
import jwt
from fastapi import Header, HTTPException, status
from pydantic import BaseModel

# Configuration (defaults to secure dev key if not provided via environment)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "pii-shield-hackathon-secret-key-bfsi-2026-xyz987")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

# Password hashing utilities
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# In-memory user database seeded with benchmark personas
_INITIAL_USERS: Dict[str, Dict[str, Any]] = {
    # Official Saffron Bank benchmark personas
    "admin_anita": {
        "username": "admin_anita",
        "full_name": "Anita Sharma (Data Platform Lead)",
        "role": "Admin",
        "password_hash": hash_password("password123"),
    },
    "support_ravi": {
        "username": "support_ravi",
        "full_name": "Ravi Kumar (Customer Support Tier 2)",
        "role": "Support",
        "password_hash": hash_password("password123"),
    },
    "analyst_kavya": {
        "username": "analyst_kavya",
        "full_name": "Kavya Iyer (BI & Risk Analyst)",
        "role": "Analyst",
        "password_hash": hash_password("password123"),
    },
    # Convenience short usernames
    "admin": {
        "username": "admin",
        "full_name": "Administrator",
        "role": "Admin",
        "password_hash": hash_password("admin123"),
    },
    "support": {
        "username": "support",
        "full_name": "Support Representative",
        "role": "Support",
        "password_hash": hash_password("support123"),
    },
    "analyst": {
        "username": "analyst",
        "full_name": "Data Analyst",
        "role": "Analyst",
        "password_hash": hash_password("analyst123"),
    },
}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in_minutes: int
    user: Dict[str, Any]


class LoginRequest(BaseModel):
    username: str
    password: str


class UserProfile(BaseModel):
    username: str
    full_name: str
    role: str


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT token with expiry and role claims."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token, raising HTTPException if invalid or expired."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
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


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate username and password against verified user store."""
    user = _INITIAL_USERS.get(username.lower().strip())
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def resolve_auth_context(
    authorization: Optional[str] = Header(None),
    requested_role: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resolve identity and role:
    1. If Authorization header is provided, decode and verify JWT. The role from JWT is strictly authoritative.
    2. If no Authorization header is provided and DEMO_MODE is True, allow requested_role or default to Support.
    3. If DEMO_MODE is False and no valid token is provided, reject with 401 Unauthorized.
    """
    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
            payload = decode_access_token(token)
            verified_role = payload.get("role")
            if verified_role:
                return {
                    "authenticated": True,
                    "username": payload.get("sub"),
                    "role": verified_role.strip().capitalize(),
                    "source": "jwt_verified",
                    "full_name": payload.get("full_name", payload.get("sub")),
                }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header. Format must be 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if DEMO_MODE:
        role = (requested_role or "Support").strip().capitalize()
        return {
            "authenticated": False,
            "username": f"demo_{role.lower()}",
            "role": role,
            "source": "demo_unauthenticated",
            "full_name": f"Demo {role} Persona",
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a valid Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

