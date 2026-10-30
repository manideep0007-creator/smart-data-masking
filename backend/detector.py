import re
from typing import Any, Dict, List, Optional

# Regex heuristics for column names
COLUMN_PATTERNS = [
    # Financial Confidential
    (r"(card_number|credit_card|card_no|card|cc_num|pan)", "FINANCIAL_CONFIDENTIAL", "CREDIT_CARD", "HIGH", "Column name matches payment card identifier"),
    (r"(salary|wage|compensation|income|balance|account_num|bank_account|iban)", "FINANCIAL_CONFIDENTIAL", "FINANCIAL", "HIGH", "Column name matches financial/salary data"),
    # High Risk PII
    (r"(ssn|social_security|national_id|tax_id|passport)", "PII_HIGH", "SSN", "HIGH", "Column name matches government/national ID pattern"),
    # Medium Risk PII
    (r"(email|mail_addr)", "PII_MEDIUM", "EMAIL", "HIGH", "Column name matches email address pattern"),
    (r"(phone|mobile|cell|telephone|fax)", "PII_MEDIUM", "PHONE", "HIGH", "Column name matches telephone number pattern"),
    (r"(address|street|city|postal|zipcode)", "PII_MEDIUM", "ADDRESS", "HIGH", "Column name matches physical address pattern"),
    # Low Risk PII / Identifying
    (r"(name|full_name|first_name|last_name|customer_name)", "PII_LOW", "NAME", "HIGH", "Column name matches customer name pattern"),
]

# Regex heuristics for data values (fallback or content-based verification)
VALUE_PATTERNS = [
    (re.compile(r"^\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}$"), "FINANCIAL_CONFIDENTIAL", "CREDIT_CARD", "HIGH", "Value matches credit card number format"),
    (re.compile(r"^\d{3}-\d{2}-\d{4}$"), "PII_HIGH", "SSN", "HIGH", "Value matches US Social Security Number format"),
    (re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"), "PII_MEDIUM", "EMAIL", "HIGH", "Value matches email pattern"),
    (re.compile(r"^(\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}$"), "PII_MEDIUM", "PHONE", "HIGH", "Value matches phone number format"),
]


def classify_column(column_name: str, sample_values: Optional[List[Any]] = None) -> Dict[str, Any]:
    """
    Classify a column into PII sensitivity tags using heuristic analysis
    on the column name and optionally sample values.
    """
    col_normalized = column_name.lower().strip()

    # 1. Match against column name patterns
    for regex_pattern, tag, pii_type, confidence, heuristic in COLUMN_PATTERNS:
        if re.search(regex_pattern, col_normalized):
            return {
                "name": column_name,
                "tag": tag,
                "pii_type": pii_type,
                "confidence": confidence,
                "heuristic": heuristic,
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

