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


class MaskedToken(str):
    """
    Explicit internal typed representation indicating a value has already undergone masking.
    Inherits from str for seamless serialization, comparison, and formatting,
    while enabling safe idempotence guards without relying on fragile string pattern heuristics.
    """
    pass


def deterministic_hash(val: Any, prefix: str = "sha256:") -> MaskedToken:
    """
    Generate a deterministic, salted SHA-256 HMAC pseudonymized representation of a value.
    Preserves joinability and cardinality for analysts without exposing raw PII.
    Employs an explicit typed internal representation (MaskedToken) to prevent accidental re-hashing.
    Outputs a 128-bit (32 hexadecimal character) secure HMAC token.
    NOTE: This is pseudonymization, NOT irreversible anonymization.
    """
    if val is None:
        return MaskedToken("")
    if isinstance(val, MaskedToken):
        return val
    str_val = str(val).strip()
    if not str_val:
        return MaskedToken("")
    digest = hmac.new(HASH_SALT, str_val.encode("utf-8"), hashlib.sha256).hexdigest()
    # 32 hexadecimal characters = 128 bits of entropy
    return MaskedToken(f"{prefix}{digest[:32]}")


def mask_account_support(val: Any) -> str:
    """
    Mask bank account number for Support role, preserving the last four digits.
    e.g. 123456789012 -> ********9012
         987654321098 -> ********1098
    """
    if val is None:
        return ""
    s = str(val).strip()
    if not s:
        return ""
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 4:
        prefix_len = max(4, len(digits) - 4)
        return f"{'*' * prefix_len}{digits[-4:]}"
    return "********"


def mask_dob_support(val: Any) -> str:
    """
    Mask date of birth for Support role, preserving only the year and masking month/day.
    e.g. 1995-08-14 -> 1995-**-**
    """
    if val is None:
        return ""
    s = str(val).strip()
    if not s:
        return ""
    match_iso = re.match(r"^(\d{4})[-/.]\d{2}[-/.]\d{2}$", s)
    if match_iso:
        return f"{match_iso.group(1)}-**-**"
    match_year = re.match(r"^(\d{4})", s)
    if match_year:
        return f"{match_year.group(1)}-**-**"
    return "****-**-**"


def mask_pincode_support(val: Any) -> str:
    """
    Mask postal code / pincode for Support role.
    e.g. 560083 -> 560***
         781004 -> 781***
         10001  -> 10***
    """
    if val is None:
        return ""
    s = str(val).strip()
    if not s:
        return ""
    digits = re.sub(r"\D", "", s)
    if len(digits) == 6:
        # Standard 6-digit Indian PIN code: preserve first 3 digits
        return f"{digits[:3]}***"
    elif len(digits) == 5:
        # Standard 5-digit US ZIP code: preserve first 2 digits
        return f"{digits[:2]}***"
    elif len(digits) > 3:
        prefix_len = min(3, len(digits) // 2)
        return f"{digits[:prefix_len]}{'*' * (len(digits) - prefix_len)}"
    return "******"


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
    if not s:
        return ""
    if "," in s:
        parts = [p.strip() for p in s.split(",") if p.strip()]
        if len(parts) > 1:
            return f"***, {parts[-1]}"
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

    # Idempotence protection: if value has already been processed into a MaskedToken, pass through
    if isinstance(raw_value, MaskedToken):
        return raw_value

    # Admin sees everything unmasked
    if role == "Admin":
        return raw_value

    tag = classification.get("tag", "PUBLIC")
    pii_type = classification.get("pii_type", "NONE")
    col_name = classification.get("name", "").lower()

    # If column is public / non-sensitive, no masking needed
    if tag == "PUBLIC":
        return raw_value

    # Analyst role: either [REDACTED] or deterministic pseudonymized hash
    if role == "Analyst":
        if mask_strategy == "hash":
            return deterministic_hash(raw_value)
        return MaskedToken("[REDACTED]")

    # Support role: targeted partial masking
    if role == "Support":
        if pii_type == "CREDIT_CARD":
            return MaskedToken(mask_credit_card_support(raw_value))
        elif pii_type == "SSN":
            return MaskedToken(mask_ssn_support(raw_value))
        elif pii_type == "AADHAAR":
            return MaskedToken(mask_aadhaar_support(raw_value))
        elif pii_type == "PAN":
            return MaskedToken(mask_pan_support(raw_value))
        elif pii_type == "EMAIL":
            return MaskedToken(mask_email_support(raw_value))
        elif pii_type == "PHONE":
            return MaskedToken(mask_phone_support(raw_value))
        elif pii_type == "DATE_OF_BIRTH":
            return MaskedToken(mask_dob_support(raw_value))
        elif pii_type == "ADDRESS":
            if re.search(r"(pincode|pin_code|zip|zipcode|postal)", col_name):
                return MaskedToken(mask_pincode_support(raw_value))
            return MaskedToken(mask_address_support(raw_value))
        elif pii_type in ("BANK_ACCOUNT", "ACCOUNT") or (pii_type == "FINANCIAL" and re.search(r"(account|acct)", col_name)):
            return MaskedToken(mask_account_support(raw_value))
        elif pii_type == "FINANCIAL":
            return MaskedToken("[CONFIDENTIAL]")
        elif pii_type == "NAME":
            # Support agents need customer name unmasked for customer service
            return raw_value
        else:
            return MaskedToken("[PROTECTED]")

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
