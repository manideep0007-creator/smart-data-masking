import re
from typing import Any, Dict, List, Optional, Tuple

import re
from typing import Any, Dict, List, Optional, Tuple

# Explicit non-PII identifiers, system metadata, and public audit attributes
# Prevents false-positive over-matching on technical IDs, status codes, and non-sensitive numbers
NON_PII_EXCLUSIONS = {
    # System and transaction references
    "txn_id", "transaction_id", "ref_no", "rrn", "branch_code", "card_ref",
    "ticket_id", "app_id", "kyc_id", "customer_id", "cif", "cust_id", "id",
    # Card and account technical status/type metadata
    "card_network", "card_type", "card_variant", "card_status", "acct_status",
    "kyc_status", "txn_status", "acct_type", "loan_type", "ovd_type", "status",
    # Operational and banking metadata
    "gender", "occupation", "segment", "risk_cat", "preferred_lang", "priority",
    "channel", "decision", "emp_type", "residency_status", "fatca_flag",
    "tax_form", "tin_country", "region", "nominee_rel", "category",
    # Audit and timestamp fields (excluding personal date of birth)
    "open_dt", "last_txn_dt", "applied_on", "created_ts", "resolved_ts",
    "issued_on", "verified_on", "next_review_dt", "opened_on", "customer_since",
    "last_login_ts", "txn_ts", "fatca_reported_on", "exp_mm", "exp_yyyy",
    # Financial terms/rates and organizational names/contacts (Public/Commercial)
    "tenure_mths", "roi_pct", "int_rate_pct", "ifsc", "branch_nm", "dr_cr",
    "branch_phone", "branch_email", "employer_nm", "counterparty",
    "verified_by", "assigned_to",
}

# Regex heuristics for column names (evaluated in priority order)
COLUMN_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    # 1. Payment Card Numbers (High Risk / Financial Confidential)
    (
        r"^(card_no|card_number|credit_card_no|debit_card_no|credit_card|debit_card|cc_num|cc_number)$|(_card_no|_card_number)$",
        "FINANCIAL_CONFIDENTIAL",
        "CREDIT_CARD",
        "HIGH",
        "Column name matches payment card identifier",
    ),
    # 2. High-Risk National / Government IDs
    (
        r"(^ssn$|social_security|_ssn$)",
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
    # 3. Financial Accounts, Incomes, Balances, and Limits
    (
        r"(salary|wage|compensation|income|curr_bal|bal_after|balance|account_no|account_num|bank_account|linked_acct|acc_no|iban|routing_number|credit_limit|outstanding_amt|od_limit|sanctioned_amt|amt_requested|amount_inr|credit_score)",
        "FINANCIAL_CONFIDENTIAL",
        "FINANCIAL",
        "HIGH",
        "Column name matches financial account, balance, limit, or income data",
    ),
    # 4. Contact Information (Medium Risk PII)
    (
        r"(email|emailid|mail_addr|e_mail)",
        "PII_MEDIUM",
        "EMAIL",
        "HIGH",
        "Column name matches email address pattern",
    ),
    (
        r"(phone|mobile|cell|telephone|fax|contact_no|mob_no|alt_mob|us_phone|\bmob\b)",
        "PII_MEDIUM",
        "PHONE",
        "HIGH",
        "Column name matches telephone or mobile number pattern",
    ),
    # 5. Physical and Postal Addresses (Medium Risk PII)
    (
        r"(^addr$|^address$|addr_line|street|city|us_city|state|us_state|postal|zipcode|zip_code|pincode|pin_code|us_zip|residential_addr|us_addr)",
        "PII_MEDIUM",
        "ADDRESS",
        "HIGH",
        "Column name matches physical or postal address pattern",
    ),
    # 6. Personal Date of Birth (Medium Risk PII)
    (
        r"(^dob$|^dob_dt$|date_of_birth|birth_date|birthdate)",
        "PII_MEDIUM",
        "DATE_OF_BIRTH",
        "HIGH",
        "Column name matches date of birth",
    ),
    # 7. Unstructured Support Text, Notes, & KYC Payloads (Medium Risk PII)
    # Note: This is a column-level classification flag indicating free-form text or semi-structured payload risk.
    # It does NOT perform inline token/entity extraction on text contents.
    (
        r"(ticket_text|notes|remarks|extra_info|kyc_meta)",
        "PII_MEDIUM",
        "UNSTRUCTURED_TEXT",
        "MEDIUM",
        "Column name matches free-form text or semi-structured payload (column-level flag; not inline NLP extraction)",
    ),
    # 8. Person Names (Low Risk PII)
    (
        r"(name_on_card|cust_nm|pita_nm|nominee_nm|^name$|full_name|first_name|last_name|customer_name|cust_name|holder_name)",
        "PII_LOW",
        "NAME",
        "HIGH",
        "Column name matches customer, family, or personal name pattern",
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
    table_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Classify a database column into PII sensitivity tags using heuristic analysis
    on the column name (or underlying alias origin) and sample data values.
    Supports table-contextual disambiguation (e.g. public bank branch directory vs customer residential address).
    """
    # 0a. Check organizational public directory table context (e.g. bank branches directory)
    if table_name and table_name.lower().strip() in ("branches", "branch"):
        return {
            "name": column_name,
            "tag": "PUBLIC",
            "pii_type": "NONE",
            "confidence": "HIGH",
            "heuristic": "Column in branches table is public organizational directory information",
        }

    names_to_check = [column_name]
    if original_column and original_column != column_name:
        names_to_check.append(original_column)

    # 0b. Check explicit non-PII / system reference exclusion
    for name in names_to_check:
        col_normalized = name.lower().strip()
        if col_normalized in NON_PII_EXCLUSIONS:
            return {
                "name": column_name,
                "tag": "PUBLIC",
                "pii_type": "NONE",
                "confidence": "HIGH",
                "heuristic": "Column is an identified non-PII reference, system metadata, or audit attribute",
            }

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
