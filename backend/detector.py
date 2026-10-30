import re
from typing import Any, Dict, List, Optional, Tuple

# Regex heuristics for column names (evaluated in order)
COLUMN_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    # Payment Cards & Financial Confidential
    (
        r"(card_number|credit_card|debit_card|card_no|card|cc_num|cc_number)",
        "FINANCIAL_CONFIDENTIAL",
        "CREDIT_CARD",
        "HIGH",
        "Column name matches payment card identifier",
    ),
    (
        r"(salary|wage|compensation|income|balance|account_num|bank_account|account_no|acc_no|iban|routing_number)",
        "FINANCIAL_CONFIDENTIAL",
        "FINANCIAL",
        "HIGH",
        "Column name matches financial/account/salary data",
    ),
    # High Risk National/Government IDs
    (
        r"(ssn|social_security)",
        "PII_HIGH",
        "SSN",
        "HIGH",
        "Column name matches US Social Security Number",
    ),
    (
        r"(aadhaar_no|aadhaar|uidai)",
        "PII_HIGH",
        "AADHAAR",
        "HIGH",
        "Column name matches Indian Aadhaar / UIDAI identifier",
    ),
    (
        r"(pan_no|pan_card|\bpan\b)",
        "PII_HIGH",
        "PAN",
        "HIGH",
        "Column name matches Indian Permanent Account Number (PAN)",
    ),
    (
        r"(national_id|tax_id|passport|passport_no|driving_license|dl_no)",
        "PII_HIGH",
        "GOVERNMENT_ID",
        "HIGH",
        "Column name matches government-issued personal identifier",
    ),
    # Medium Risk Contact & Identity
    (
        r"(email|mail_addr|e_mail)",
        "PII_MEDIUM",
        "EMAIL",
        "HIGH",
        "Column name matches email address pattern",
    ),
    (
        r"(phone|mobile|cell|telephone|fax|contact_no)",
        "PII_MEDIUM",
        "PHONE",
        "HIGH",
        "Column name matches telephone or mobile number pattern",
    ),
    (
        r"(address|street|city|postal|zipcode|zip_code|pin_code|residential_addr)",
        "PII_MEDIUM",
        "ADDRESS",
        "HIGH",
        "Column name matches physical or postal address pattern",
    ),
    (
        r"(dob|date_of_birth|dob_dt|birth_date|birthdate)",
        "PII_MEDIUM",
        "DATE_OF_BIRTH",
        "HIGH",
        "Column name matches date of birth",
    ),
    # Low Risk PII / Identifying
    (
        r"(name|full_name|first_name|last_name|customer_name|cust_name|holder_name)",
        "PII_LOW",
        "NAME",
        "HIGH",
        "Column name matches customer/person name pattern",
    ),
]

# Regex heuristics for sample data values (content-based classification)
VALUE_PATTERNS: List[Tuple[re.Pattern, str, str, str, str]] = [
    # Credit cards (16 digits or 4x4 groups)
    (
        re.compile(r"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})$"),
        "FINANCIAL_CONFIDENTIAL",
        "CREDIT_CARD",
        "HIGH",
        "Sample value matches payment card formatting or issuer ranges",
    ),
    # US SSN (3-2-4 format)
    (
        re.compile(r"^\d{3}-\d{2}-\d{4}$"),
        "PII_HIGH",
        "SSN",
        "HIGH",
        "Sample value matches US Social Security Number format (NNN-NN-NNNN)",
    ),
    # Indian Aadhaar (12 digits, optional dashes/spaces)
    (
        re.compile(r"^\d{4}[- ]\d{4}[- ]\d{4}$"),
        "PII_HIGH",
        "AADHAAR",
        "HIGH",
        "Sample value matches 12-digit Indian Aadhaar format (XXXX-XXXX-XXXX)",
    ),
    # Indian PAN (5 letters, 4 digits, 1 letter)
    (
        re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$"),
        "PII_HIGH",
        "PAN",
        "HIGH",
        "Sample value matches 10-character Indian PAN format (AAAAA9999A)",
    ),
    # Email
    (
        re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),
        "PII_MEDIUM",
        "EMAIL",
        "HIGH",
        "Sample value matches RFC-compliant email address structure",
    ),
    # Phone number
    (
        re.compile(r"^(\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}$"),
        "PII_MEDIUM",
        "PHONE",
        "HIGH",
        "Sample value matches telephone dialing pattern",
    ),
]


def classify_column(
    column_name: str,
    sample_values: Optional[List[Any]] = None,
    original_column: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Classify a database column into PII sensitivity tags using heuristic analysis
    on the column name (or underlying alias origin) and sample data values.
    """
    names_to_check = [column_name]
    if original_column and original_column != column_name:
        names_to_check.append(original_column)

    # 1. Match column name or original column name against patterns
    for name in names_to_check:
        col_normalized = name.lower().strip()
        for regex_pattern, tag, pii_type, confidence, heuristic in COLUMN_PATTERNS:
            if re.search(regex_pattern, col_normalized):
                origin_note = f" (detected from original column '{original_column}')" if name != column_name else ""
                return {
                    "name": column_name,
                    "tag": tag,
                    "pii_type": pii_type,
                    "confidence": confidence,
                    "heuristic": heuristic + origin_note,
                }

    # 2. Check sample values if available
    if sample_values:
        for val in sample_values:
            if val is None:
                continue
            str_val = str(val).strip()
            for pattern_re, tag, pii_type, confidence, heuristic in VALUE_PATTERNS:
                if pattern_re.match(str_val):
                    return {
                        "name": column_name,
                        "tag": tag,
                        "pii_type": pii_type,
                        "confidence": confidence,
                        "heuristic": f"Sample value heuristic: {heuristic}",
                    }

    # 3. Default to public / non-sensitive
    return {
        "name": column_name,
        "tag": "PUBLIC",
        "pii_type": "NONE",
        "confidence": "HIGH",
        "heuristic": "Column has no sensitive PII indicators",
    }
