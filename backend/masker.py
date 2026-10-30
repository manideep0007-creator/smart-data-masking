import re
from typing import Any, Dict, List
from backend.detector import classify_column

VALID_ROLES = {"Admin", "Support", "Analyst"}


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


def mask_value_for_role(role: str, classification: Dict[str, Any], raw_value: Any) -> Any:
    """Apply masking logic to an individual cell value based on role and classification."""
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

    # Analyst redacts all sensitive fields
    if role == "Analyst":
        return "[REDACTED]"

    # Support role applies targeted partial masking
    if role == "Support":
        if pii_type == "CREDIT_CARD":
            return mask_credit_card_support(raw_value)
        elif pii_type == "SSN":
            return mask_ssn_support(raw_value)
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


def mask_query_results(role: str, columns: List[str], rows: List[List[Any]]) -> List[List[Any]]:
    """
    Mask raw database rows according to the specified role.
    Does not modify database or original row instances.
    """
    if role == "Admin":
        return rows

    # Classify each column
    column_classes = []
    for col_idx, col_name in enumerate(columns):
        sample_vals = [r[col_idx] for r in rows[:5] if col_idx < len(r)]
        col_info = classify_column(col_name, sample_vals)
        column_classes.append(col_info)

    masked_rows = []
    for row in rows:
        new_row = []
        for col_idx, val in enumerate(row):
            col_info = column_classes[col_idx]
            masked_val = mask_value_for_role(role, col_info, val)
            new_row.append(masked_val)
        masked_rows.append(new_row)

    return masked_rows

