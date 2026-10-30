import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")
if os.path.exists(_ENV_PATH):
    load_dotenv(_ENV_PATH)

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.auth import (
    DEMO_MODE,
    LoginRequest,
    SafeUserItem,
    TokenResponse,
    authenticate_user,
    create_access_token,
    decode_access_token,
    get_safe_user_list,
    resolve_auth_context,
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

# CORS: Restricted strictly to local demonstration frontend origins
_LOCAL_ORIGINS = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]
_EXTRA_ORIGINS = [
    orig.strip()
    for orig in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if orig.strip()
]
ALLOWED_ORIGINS = _LOCAL_ORIGINS + _EXTRA_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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

@app.post("/auth/login", response_model=TokenResponse, summary="Sign in and obtain JWT access token")
def login(req: LoginRequest):
    """
    Authenticate user credentials and issue signed JWT access token.
    Verified role is embedded in the token payload.
    """
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {
        "sub": user["username"],
        "role": user["role"],
        "full_name": user["full_name"],
    }
    access_token = create_access_token(token_data)

    logger.info(f"User '{user['username']}' authenticated successfully with role '{user['role']}'")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=480,
        user={
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
        },
    )


@app.get("/auth/me", summary="Get authenticated user profile from verified JWT")
def get_current_user_profile(authorization: Optional[str] = Header(None)):
    """Extract authenticated identity and verified role from Bearer JWT token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer token in Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1]
    payload = decode_access_token(token)
    return {
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "full_name": payload.get("full_name"),
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
    }


@app.get("/auth/users", summary="List available demo user personas for evaluation (passwords omitted)")
def list_demo_users():
    """Return configured demo accounts without exposing passwords or hashes."""
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
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "database_info": "/database/info",
            "scan": "/scan",
            "background_scan_start": "/scan/start (POST)",
            "background_scan_status": "/scan/status",
            "background_scan_history": "/scan/history",
            "login": "/auth/login (POST)",
            "auth_me": "/auth/me",
            "auth_users": "/auth/users",
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
def database_info():
    """Return database engine status, available tables, and read-only safeguards."""
    adapter = get_database_adapter()
    status_info = adapter.test_connection()
    tables = []
    if status_info.get("status") == "connected":
        try:
            tables = adapter.get_tables()
        except Exception:
            pass
    return {
        "connection": status_info,
        "tables": tables,
        "total_tables": len(tables),
    }


# --- Scanning Endpoints ---

@app.get("/scan", response_model=ScanResponse, summary="Scan database columns for PII (Synchronous)")
def scan_schema(table: str = "customers"):
    """
    Inspect the schema of the specified table, heuristically detecting
    potential PII and returning classified tags and sensitivity levels.
    """
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


@app.post("/scan/start", summary="Trigger an asynchronous background PII discovery scan")
def trigger_background_scan(
    table: Optional[str] = Query(None, description="Optional specific table name to scan"),
    sample_limit: Optional[int] = Query(10, description="Sample rows per table for heuristic evaluation"),
    authorization: Optional[str] = Header(None),
):
    """
    Trigger background scan without blocking ordinary queries.
    Admin authorization required (or allowed in DEMO_MODE).
    """
    auth_ctx = resolve_auth_context(authorization, requested_role="Admin")
    # Verify role permissions
    if auth_ctx.get("authenticated") and auth_ctx.get("role") != "Admin":
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
def get_scan_status():
    """Retrieve current background scanner task status, progress percentage, and statistics."""
    return background_scanner.get_status()


@app.get("/scan/history", summary="Get audit log of recent background scans")
def get_scan_history(limit: int = 10):
    """Retrieve history of past background scans with timestamps and detected columns."""
    return {"history": background_scanner.get_history(limit=limit)}


# --- Query Operations Gateway ---

@app.post("/query", response_model=QueryResponse, summary="Execute query with role-based masking")
def execute_query(
    req: QueryRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Execute a read-only SELECT query through the gateway.
    Derives role from verified JWT when provided, preventing frontend tampering.
    Results are dynamically masked in memory without mutating stored records.
    """
    # 1. Resolve role from verified JWT (if present) or fallback to demo request
    auth_ctx = resolve_auth_context(authorization, requested_role=req.role)
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
        f"(source={auth_ctx.get('source')}) | query_len={len(req.sql)}"
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
