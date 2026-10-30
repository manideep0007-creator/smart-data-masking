import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import Any, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.db import DEFAULT_DB_PATH, get_read_only_connection, init_db
from backend.detector import classify_column
from backend.masker import VALID_ROLES, mask_query_results
from backend.validator import validate_sql

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
    yield


app = FastAPI(
    title="Smart Data Masking API",
    description="Role-based query masking gateway detecting likely PII and applying selective masking in-flight.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Schemas ---

class HealthResponse(BaseModel):
    status: str
    database: str
    version: str


class ColumnScanItem(BaseModel):
    name: str = Field(..., description="Column name")
    tag: str = Field(..., description="Classification tag (e.g. FINANCIAL_CONFIDENTIAL, PII_HIGH, PII_MEDIUM, PII_LOW, PUBLIC)")
    pii_type: str = Field(..., description="Category of PII detected (CREDIT_CARD, SSN, EMAIL, PHONE, etc.)")
    confidence: str = Field(..., description="Detection confidence level (HIGH, MEDIUM, LOW)")
    sensitivity: str = Field(..., description="Risk sensitivity tier (HIGH, MEDIUM, LOW, NONE)")
    heuristic: str = Field(..., description="Rule or pattern that triggered classification")


class ScanResponse(BaseModel):
    table: str
    total_columns: int
    columns: List[ColumnScanItem]


class QueryRequest(BaseModel):
    role: str = Field(..., description="User role: Admin, Support, or Analyst", examples=["Support"])
    sql: str = Field(..., description="Read-only SELECT query", examples=["SELECT name, card_number FROM customers"])


class QueryResponse(BaseModel):
    columns: List[str]
    rows: List[List[Any]]


# --- Endpoints ---

@app.get("/", summary="Root index")
def root():
    """Welcome index directing users to documentation and endpoints."""
    return {
        "service": "Smart Data Masking API",
        "status": "online",
        "documentation": "/docs",
        "health": "/health",
        "scan": "/scan",
        "query": "/query (POST)",
        "frontend_dashboard": "http://localhost:8501"
    }


@app.get("/health", response_model=HealthResponse, summary="Service health check")
def health_check():
    """Verify that the API is active and the database connection is operational."""
    try:
        conn = get_read_only_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
        db_status = "connected"
    except Exception as exc:
        logger.error(f"Health check database failure: {exc}")
        db_status = "error"

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        database=db_status,
        version="1.0.0",
    )


@app.get("/scan", response_model=ScanResponse, summary="Scan database columns for PII")
def scan_schema(table: str = "customers"):
    """
    Inspect the schema of the specified table, heuristically detecting
    potential PII and returning classified tags and sensitivity levels.
    """
    try:
        conn = get_read_only_connection()
        cur = conn.cursor()

        # Verify table exists in database
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table,))
        if not cur.fetchone():
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Table '{table}' not found in database."
            )

        # Retrieve table columns using read-only SELECT
        cur.execute(f"SELECT * FROM {table} LIMIT 5")
        description = cur.description
        col_names = [col[0] for col in description] if description else []
        sample_rows = cur.fetchall()
        conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error scanning table schema: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to scan table schema."
        )

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

    return ScanResponse(
        table=table,
        total_columns=len(scan_items),
        columns=scan_items,
    )


@app.post("/query", response_model=QueryResponse, summary="Execute query with role-based masking")
def execute_query(req: QueryRequest):
    """
    Execute a read-only SELECT query through the gateway.
    Results are dynamically masked based on the user's role without mutating stored records.
    """
    # 1. Normalize and validate role
    normalized_role = req.role.strip().capitalize()
    if normalized_role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{req.role}'. Allowed roles are: {', '.join(sorted(VALID_ROLES))}."
        )

    # 2. Validate SQL query (read-only SELECT, single statement)
    is_valid, err_msg = validate_sql(req.sql)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query rejected: {err_msg}"
        )

    # 3. Log query metadata without logging raw PII
    logger.info(
        f"Processing query for role '{normalized_role}' | query_length={len(req.sql)}"
    )

    # 4. Execute query using read-only database connection
    try:
        conn = get_read_only_connection()
        cur = conn.cursor()
        cur.execute(req.sql)
        description = cur.description
        if not description:
            conn.close()
            return QueryResponse(columns=[], rows=[])

        columns = [col[0] for col in description]
        raw_rows = [list(r) for r in cur.fetchall()]
        conn.close()
    except sqlite3.DatabaseError as exc:
        logger.warning(f"Database error executing query: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Database execution error: {exc}"
        )
    except Exception as exc:
        logger.error(f"Unexpected error executing query: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while executing the query."
        )

    # 5. Apply role-based masking to in-memory rows
    masked_rows = mask_query_results(normalized_role, columns, raw_rows)

    logger.info(
        f"Completed query for role '{normalized_role}' | returned_columns={len(columns)} | returned_rows={len(masked_rows)}"
    )

    return QueryResponse(columns=columns, rows=masked_rows)
