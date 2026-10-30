import hashlib
import hmac
import os
import re
from typing import Any, Dict, List, Optional

from backend.detector import classify_column
from backend.registry import registry

VALID_ROLES = {"Admin", "Support", "Analyst"}
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

_DEFAULT_DEV_SALT = "pii-shield-dev-salt-2026"
_RAW_SALT = os.getenv("HASH_SALT") or os.getenv("MASKING_HASH_SALT") or _DEFAULT_DEV_SALT

if not DEMO_MODE and (not _RAW_SALT or _RAW_SALT == _DEFAULT_DEV_SALT):
    raise RuntimeError(
        "CRITICAL SECURITY CONFIGURATION ERROR: Production mode (DEMO_MODE=false) requires an explicit, secure HASH_SALT environment variable."
    )

HASH_SALT = _RAW_SALT.encode("utf-8")


def deterministic_hash(val: Any, prefix: str = "sha256:") -> str:
    """
    Generate a deterministic, salted SHA-256 HMAC pseudonymized representation of a value.
    Preserves joinability and cardinality for analysts without exposing raw PII.
    NOTE: This is pseudonymization, NOT irreversible anonymization.
    """
    if val is None:
        return ""
    str_val = str(val).strip().encode("utf-8")
    digest = hmac.new(HASH_SALT, str_val, hashlib.sha256).hexdigest()
    # Return compact 12-char hex token e.g. 'sha256:7f83b1657ff1'
    return f"{prefix}{digest[:12]}"


def mask_credit_card_support(val: Any) -> str:
    """Mask credit card for Support role, e.g. 4111-XXXX-XXXX-1111."""
    if val is None:
        return ""
    s = str(val).strip()
    match = re.match(r"^(\d{4})[- ]?\d{4}[- ]?\d{4}[- ]?(\d{4})$", s)
    if match:
        return f"{match.group(1)}-XXXX-XXXX-{match.group(2)}"
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 8:
        return f"{digits[:4]}-XXXX-XXXX-{digits[-4:]}"
    return "XXXX-XXXX-XXXX-XXXX"


def mask_ssn_support(val: Any) -> str:
    """Mask SSN for Support role, e.g. XXX-XX-6789."""
    if val is None:
        return ""
    s = str(val).strip()
    match = re.match(r"^\d{3}[- ]?\d{2}[- ]?(\d{4})$", s)
    if match:
        return f"XXX-XX-{match.group(1)}"
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 4:
        return f"XXX-XX-{digits[-4:]}"
    return "XXX-XX-XXXX"


def mask_aadhaar_support(val: Any) -> str:
    """Mask 12-digit Indian Aadhaar for Support, e.g. XXXX-XXXX-1234."""
    if val is None:
        return ""
    s = str(val).strip()
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 4:
        return f"XXXX-XXXX-{digits[-4:]}"
    return "XXXX-XXXX-XXXX"


def mask_pan_support(val: Any) -> str:
    """Mask Indian PAN card for Support, e.g. XXXXX1234X."""
    if val is None:
        return ""
    s = str(val).strip().upper()
    if len(s) == 10:
        return f"XXXXX{s[5:9]}{s[9]}"
    return "XXXXXXXXXX"


def mask_email_support(val: Any) -> str:
    """Mask email for Support role, e.g. a***@example.com."""
    if val is None:
        return ""
    s = str(val).strip()
    if "@" in s:
        local, domain = s.split("@", 1)
        if len(local) > 0:
            return f"{local[0]}***@{domain}"
        return f"***@{domain}"
    return "***@***.***"


def mask_phone_support(val: Any) -> str:
    """Mask phone for Support role, e.g. ***-***-2834."""
    if val is None:
        return ""
    s = str(val).strip()
    match = re.search(r"(\d{4})$", s)
    if match:
        return f"***-***-{match.group(1)}"
    return "***-***-XXXX"


def mask_address_support(val: Any) -> str:
    """Mask address for Support role, preserving city/region if available."""
    if val is None:
        return ""
    s = str(val).strip()
    if "," in s:
        city = s.split(",")[-1].strip()
        return f"***, {city}"
    return "[PARTIALLY MASKED]"


def mask_value_for_role(
    role: str,
    classification: Dict[str, Any],
    raw_value: Any,
    mask_strategy: str = "redact",
) -> Any:
    """Apply masking logic to an individual cell value based on role, classification, and strategy."""
    if raw_value is None:
        return None

    # Admin sees everything unmasked
    if role == "Admin":
        return raw_value

    tag = classification.get("tag", "PUBLIC")
    pii_type = classification.get("pii_type", "NONE")

    # If column is public / non-sensitive, no masking needed
    if tag == "PUBLIC":
        return raw_value

    # Analyst role: either [REDACTED] or deterministic pseudonymized hash
    if role == "Analyst":
        if mask_strategy == "hash":
            return deterministic_hash(raw_value)
        return "[REDACTED]"

    # Support role: targeted partial masking
    if role == "Support":
        if pii_type == "CREDIT_CARD":
            return mask_credit_card_support(raw_value)
        elif pii_type == "SSN":
            return mask_ssn_support(raw_value)
        elif pii_type == "AADHAAR":
            return mask_aadhaar_support(raw_value)
        elif pii_type == "PAN":
            return mask_pan_support(raw_value)
        elif pii_type == "EMAIL":
            return mask_email_support(raw_value)
        elif pii_type == "PHONE":
            return mask_phone_support(raw_value)
        elif pii_type == "FINANCIAL":
            return "[CONFIDENTIAL]"
        elif pii_type == "ADDRESS":
            return mask_address_support(raw_value)
        elif pii_type == "NAME":
            # Support agents need customer name unmasked for customer service
            return raw_value
        else:
            return "[PROTECTED]"

    return raw_value


def mask_query_results(
    role: str,
    columns: List[str],
    rows: List[List[Any]],
    mask_strategy: str = "redact",
    table_context: Optional[str] = None,
) -> List[List[Any]]:
    """
    Mask raw database rows in-memory according to the specified role.
    Checks the PII metadata registry for pre-discovered classifications,
    falling back seamlessly to dynamic heuristic inspection for aliases/expressions.
    Does not modify database records.
    """
    if role == "Admin":
        return rows

    # Resolve column classifications (combining registry cache + heuristic detector)
    column_classes = []
    for col_idx, col_name in enumerate(columns):
        sample_vals = [r[col_idx] for r in rows[:10] if col_idx < len(r)]

        # Check registry first if table context is available or column is uniquely known
        cached_meta = None
        if table_context:
            cached_meta = registry.get_column_classification(table_context, col_name)
        if not cached_meta:
            cached_meta = registry.find_column_classification(col_name)

        if cached_meta and cached_meta.get("tag") != "PUBLIC":
            column_classes.append(cached_meta)
        else:
            # Fall back to live heuristic analysis (detects aliases and expression outputs)
            col_info = classify_column(col_name, sample_vals)
            column_classes.append(col_info)

    masked_rows = []
    for row in rows:
        new_row = []
        for col_idx, val in enumerate(row):
            col_info = column_classes[col_idx]
            masked_val = mask_value_for_role(role, col_info, val, mask_strategy=mask_strategy)
            new_row.append(masked_val)
        masked_rows.append(new_row)

    return masked_rows
