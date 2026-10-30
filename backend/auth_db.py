import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import bcrypt

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_AUTH_DB_PATH = os.path.join(_PROJECT_ROOT, "data", "auth.db")
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", _DEFAULT_AUTH_DB_PATH)

MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))

# Dummy bcrypt hash for timing-attack mitigation when username does not exist
_DUMMY_BCRYPT_HASH = "$2b$10$e8w6qL5kG7X8n9k0v1u2t.7e7k8q9w0e1r2t3y4u5i6o7p8a9s0d1"


def get_auth_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return an isolated read-write connection to the authentication database."""
    target_path = db_path or AUTH_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    conn = sqlite3.connect(target_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """Hash password securely using bcrypt."""
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password securely against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def init_auth_db(db_path: Optional[str] = None, seed_demo: Optional[bool] = None) -> str:
    """
    Initialize the authentication database schema.
    Isolated completely from Saffron Bank read-only query database.
    """
    path = db_path or AUTH_DB_PATH
    conn = get_auth_connection(path)
    try:
        cur = conn.cursor()
        # 1. Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('Admin', 'Support', 'Analyst')),
                is_active INTEGER NOT NULL DEFAULT 1,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            );
        """)

        # 2. Revoked tokens table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 3. IP Login Attempts table for network-level throttling
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ip_login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                attempt_time DATETIME NOT NULL
            );
        """)

        # 4. OAuth Account Mappings table for 3rd-party identity federation
        cur.execute("""
            CREATE TABLE IF NOT EXISTS oauth_account_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                provider_sub TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE,
                linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (provider, provider_sub)
            );
        """)

        # 5. Authentication Audit Log table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                username TEXT,
                provider TEXT,
                provider_sub TEXT,
                email TEXT,
                ip_address TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 6. Temporary OAuth pending states (SEC-OAUTH-01 remediation)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS oauth_pending_states (
                state_hash TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                code_verifier TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Optional migration: ensure google_sub column exists on users table
        try:
            cur.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        except Exception:
            pass

        # Indexes for fast lookup
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_attempts ON ip_login_attempts(ip_address, attempt_time);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_mappings_sub ON oauth_account_mappings(provider, provider_sub);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_mappings_user ON oauth_account_mappings(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_audit_created ON auth_audit_log(created_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_pending_expires ON oauth_pending_states(expires_at);")

        conn.commit()

        # Check if seed should occur (STRICT DEFAULT: false for production security)
        should_seed = seed_demo
        if should_seed is None:
            should_seed = os.getenv("SEED_DEMO_USERS", "false").lower() in ("true", "1", "yes")

        if should_seed:
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
            if user_count == 0:
                _seed_initial_accounts(conn)

    finally:
        conn.close()

    return path


def _seed_initial_accounts(conn: sqlite3.Connection):
    """Seed initial demonstration accounts if table is currently empty."""
    admin_pw = os.getenv("SEED_ADMIN_PASSWORD", "password123")
    support_pw = os.getenv("SEED_SUPPORT_PASSWORD", "password123")
    analyst_pw = os.getenv("SEED_ANALYST_PASSWORD", "password123")

    initial_users = [
        ("admin_anita", "anita.sharma@saffronbank.local", "Anita Sharma (Data Platform Lead)", hash_password(admin_pw), "Admin"),
        ("support_ravi", "ravi.kumar@saffronbank.local", "Ravi Kumar (Customer Support Tier 2)", hash_password(support_pw), "Support"),
        ("analyst_kavya", "kavya.iyer@saffronbank.local", "Kavya Iyer (BI & Risk Analyst)", hash_password(analyst_pw), "Analyst"),
        ("admin", "admin@saffronbank.local", "Administrator", hash_password(admin_pw), "Admin"),
        ("support", "support@saffronbank.local", "Support Representative", hash_password(support_pw), "Support"),
        ("analyst", "analyst@saffronbank.local", "Data Analyst", hash_password(analyst_pw), "Analyst"),
    ]

    cur = conn.cursor()
    for username, email, full_name, pw_hash, role in initial_users:
        cur.execute("""
            INSERT OR IGNORE INTO users (username, email, full_name, password_hash, role, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (username, email, full_name, pw_hash, role))
    conn.commit()


def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve user record by username (case-insensitive)."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, email, full_name, password_hash, role, is_active,
                   failed_login_attempts, locked_until, created_at, updated_at, last_login
            FROM users
            WHERE username = ?
        """, (username.strip().lower(),))
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve user record by ID."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, email, full_name, password_hash, role, is_active,
                   failed_login_attempts, locked_until, created_at, updated_at, last_login
            FROM users
            WHERE id = ?
        """, (user_id,))
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def create_user(
    username: str,
    email: str,
    full_name: str,
    password_hash: str,
    role: str,
    is_active: int = 1,
    db_path: Optional[str] = None,
) -> int:
    """Create a new user account with enforced constraints."""
    if role not in ("Admin", "Support", "Analyst"):
        raise ValueError(f"Invalid role '{role}'. Allowed roles are Admin, Support, Analyst.")
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, email, full_name, password_hash, role, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username.strip().lower(), email.strip().lower(), full_name.strip(), password_hash, role, is_active))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def set_user_active_status(user_id: int, is_active: int, db_path: Optional[str] = None):
    """Enable or disable a user account."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (is_active, user_id))
        conn.commit()
    finally:
        conn.close()


def is_account_locked(user: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Check if account is temporarily locked due to repeated failed login attempts."""
    locked_until_str = user.get("locked_until")
    if not locked_until_str:
        return False, None

    try:
        if "T" in locked_until_str:
            locked_dt = datetime.fromisoformat(locked_until_str.replace("Z", "+00:00"))
        else:
            locked_dt = datetime.strptime(locked_until_str[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        now_utc = datetime.now(timezone.utc)
        if locked_dt > now_utc:
            remaining_mins = max(1, int((locked_dt - now_utc).total_seconds() / 60))
            return True, f"Account is temporarily locked. Please try again in {remaining_mins} minute(s)."
    except Exception:
        pass

    return False, None


def record_login_failure(username: str, db_path: Optional[str] = None) -> bool:
    """
    Record failed login attempt atomically and apply lockout if threshold exceeded.
    Returns True if account has become locked.
    """
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        clean_user = username.strip().lower()

        cur.execute("""
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1, updated_at = CURRENT_TIMESTAMP
            WHERE username = ?
        """, (clean_user,))
        conn.commit()

        cur.execute("SELECT id, failed_login_attempts FROM users WHERE username = ?", (clean_user,))
        row = cur.fetchone()
        if not row:
            return False

        user_id = row["id"]
        attempts = row["failed_login_attempts"]

        if attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
            cur.execute("""
                UPDATE users
                SET locked_until = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (locked_until, user_id))
            conn.commit()
            return True
        return False
    finally:
        conn.close()


def record_ip_attempt(ip_address: str, db_path: Optional[str] = None):
    """Record a failed login attempt for an IP address."""
    if not ip_address:
        return
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO ip_login_attempts (ip_address, attempt_time)
            VALUES (?, ?)
        """, (ip_address.strip(), now_iso))
        conn.commit()
    finally:
        conn.close()


def is_ip_rate_limited(
    ip_address: str,
    max_attempts: int = 10,
    window_minutes: int = 5,
    db_path: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Check if an IP address has exceeded the allowed failed login threshold."""
    if not ip_address:
        return False, None
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        window_start = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        cur.execute("""
            SELECT COUNT(*) FROM ip_login_attempts
            WHERE ip_address = ? AND attempt_time >= ?
        """, (ip_address.strip(), window_start))
        count = cur.fetchone()[0]
        if count >= max_attempts:
            return True, f"Too many failed login attempts from this network. Please try again in {window_minutes} minutes."
        return False, None
    finally:
        conn.close()


def cleanup_old_ip_attempts(hours: int = 1, db_path: Optional[str] = None):
    """Clean up old IP attempt records."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        cur.execute("DELETE FROM ip_login_attempts WHERE attempt_time < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()


def record_login_success(user_id: int, db_path: Optional[str] = None):
    """Reset failed attempts and update last_login timestamp."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            UPDATE users
            SET failed_login_attempts = 0, locked_until = NULL, last_login = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (now_str, user_id))
        conn.commit()
    finally:
        conn.close()


def revoke_token(jti: str, expires_at: datetime, db_path: Optional[str] = None):
    """Add a token's unique jti to the server-side revocation list."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        exp_iso = expires_at.isoformat() if isinstance(expires_at, datetime) else str(expires_at)
        cur.execute("""
            INSERT OR REPLACE INTO revoked_tokens (jti, expires_at)
            VALUES (?, ?)
        """, (jti, exp_iso))
        conn.commit()
    finally:
        conn.close()


def is_token_revoked(jti: str, db_path: Optional[str] = None) -> bool:
    """Check if token jti exists in revoked list."""
    if not jti:
        return True
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
        return cur.fetchone() is not None
    finally:
        conn.close()


def cleanup_expired_revocations(db_path: Optional[str] = None):
    """Remove expired tokens from revoked_tokens to prevent table bloat."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cur.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_iso,))
        conn.commit()
    finally:
        conn.close()


def get_user_by_oauth_sub(provider: str, provider_sub: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve user record mapped to a provider's stable subject identifier."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT u.id, u.username, u.email, u.full_name, u.password_hash, u.role, u.is_active,
                   u.failed_login_attempts, u.locked_until, u.created_at, u.updated_at, u.last_login,
                   m.provider, m.provider_sub, m.linked_at, m.last_login_at as oauth_last_login
            FROM users u
            JOIN oauth_account_mappings m ON u.id = m.user_id
            WHERE m.provider = ? AND m.provider_sub = ?
        """, (provider.strip().lower(), provider_sub.strip()))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_users_by_email(email: str, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all user accounts matching an email address (case-insensitive)."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, email, full_name, password_hash, role, is_active,
                   failed_login_attempts, locked_until, created_at, updated_at, last_login
            FROM users
            WHERE email = ? COLLATE NOCASE
        """, (email.strip().lower(),))
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_oauth_mapping_by_user_id(user_id: int, provider: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Check if a specific local user is already mapped to an OAuth identity."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, user_id, provider, provider_sub, email, linked_at, last_login_at
            FROM oauth_account_mappings
            WHERE user_id = ? AND provider = ?
        """, (user_id, provider.strip().lower()))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def link_user_oauth(
    user_id: int,
    provider: str,
    provider_sub: str,
    email: str,
    db_path: Optional[str] = None,
) -> int:
    """
    Atomically link an existing local user account to a verified OAuth identity.
    Enforces uniqueness on provider_sub and user_id.
    """
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO oauth_account_mappings (user_id, provider, provider_sub, email, linked_at, last_login_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (user_id, provider.strip().lower(), provider_sub.strip(), email.strip().lower()))
        mapping_id = cur.lastrowid
        try:
            if provider.strip().lower() == "google":
                cur.execute("UPDATE users SET google_sub = ? WHERE id = ?", (provider_sub.strip(), user_id))
        except Exception:
            pass
        conn.commit()
        return mapping_id
    finally:
        conn.close()


def update_oauth_last_login(user_id: int, provider: str, db_path: Optional[str] = None):
    """Update last login timestamp for both oauth mapping and core user record."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            UPDATE oauth_account_mappings
            SET last_login_at = ?
            WHERE user_id = ? AND provider = ?
        """, (now_iso, user_id, provider.strip().lower()))
        cur.execute("""
            UPDATE users
            SET last_login = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (now_iso, user_id))
        conn.commit()
    finally:
        conn.close()


def record_auth_audit(
    event_type: str,
    status: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    provider: Optional[str] = None,
    provider_sub: Optional[str] = None,
    email: Optional[str] = None,
    ip_address: Optional[str] = None,
    detail: Optional[str] = None,
    db_path: Optional[str] = None,
):
    """Record an audit trail entry for authentication and identity events."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO auth_audit_log (
                event_type, user_id, username, provider, provider_sub, email, ip_address, status, detail
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_type,
            user_id,
            username,
            provider,
            provider_sub,
            email,
            ip_address,
            status,
            detail,
        ))
        conn.commit()
    finally:
        conn.close()


# --- SEC-OAUTH-01 Remediation: Server-Side Pending OAuth State Management ---

def store_pending_oauth_state(
    state_hash: str,
    nonce: str,
    code_verifier: str,
    expires_at: datetime,
    db_path: Optional[str] = None,
):
    """
    Store temporary OAuth state in database for atomic server-side validation.
    Stores ONLY the state_hash, never the raw state.
    PKCE code_verifier and nonce are kept strictly on the server.
    """
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        exp_iso = expires_at.isoformat() if isinstance(expires_at, datetime) else str(expires_at)
        cur.execute("""
            INSERT OR REPLACE INTO oauth_pending_states (state_hash, nonce, code_verifier, expires_at)
            VALUES (?, ?, ?, ?)
        """, (state_hash.strip(), nonce.strip(), code_verifier.strip(), exp_iso))
        conn.commit()
    finally:
        conn.close()


def consume_pending_oauth_state(
    state_hash: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Atomically retrieve and consume a pending OAuth state in a single transaction.
    Guarantees that an authorization code / state can only be consumed once.
    Rejects missing, expired, or already-consumed states.
    Prevents concurrent callback race conditions via BEGIN IMMEDIATE.
    """
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")

        cur.execute("""
            SELECT state_hash, nonce, code_verifier, expires_at
            FROM oauth_pending_states
            WHERE state_hash = ?
        """, (state_hash.strip(),))
        row = cur.fetchone()

        if not row:
            conn.commit()
            return None

        record = dict(row)

        # Atomically delete to prevent replay or concurrent duplicate consumption
        cur.execute("""
            DELETE FROM oauth_pending_states
            WHERE state_hash = ?
        """, (state_hash.strip(),))
        conn.commit()

        # Verify expiration
        expires_at_str = record["expires_at"]
        if "T" in expires_at_str:
            exp_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        else:
            exp_dt = datetime.strptime(expires_at_str[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        if exp_dt < datetime.now(timezone.utc):
            return None  # State has expired

        return record
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_pending_oauth_state(state_hash: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Non-destructive inspection of pending state (for testing/diagnostics)."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT state_hash, nonce, code_verifier, expires_at
            FROM oauth_pending_states
            WHERE state_hash = ?
        """, (state_hash.strip(),))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def cleanup_expired_oauth_states(db_path: Optional[str] = None):
    """Purge expired pending OAuth state records from database."""
    conn = get_auth_connection(db_path)
    try:
        cur = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cur.execute("DELETE FROM oauth_pending_states WHERE expires_at < ?", (now_iso,))
        conn.commit()
    finally:
        conn.close()
