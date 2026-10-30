import re
from typing import Tuple

# Disallowed SQL action keywords
DISALLOWED_KEYWORDS = [
    r"\bINSERT\b",
    r"\bUPDATE\b",
    r"\bDELETE\b",
    r"\bDROP\b",
    r"\bALTER\b",
    r"\bCREATE\b",
    r"\bTRUNCATE\b",
    r"\bREPLACE\b",
    r"\bATTACH\b",
    r"\bDETACH\b",
    r"\bPRAGMA\b",
    r"\bEXEC\b",
    r"\bEXECUTE\b",
    r"\bGRANT\b",
    r"\bREVOKE\b",
]

DISALLOWED_PATTERN = re.compile("|".join(DISALLOWED_KEYWORDS), re.IGNORECASE)


def validate_sql(sql: str) -> Tuple[bool, str]:
    """
    Validate that an incoming SQL query:
    1. Is non-empty.
    2. Is strictly a read-only SELECT query.
    3. Contains no write/DDL/DML modification statements.
    4. Is a single query statement (rejects multiple statements separated by semicolons).
    """
    if not sql or not sql.strip():
        return False, "Query cannot be empty."

    cleaned_sql = sql.strip()

    # Disallow comments that might obscure injection or query chaining
    if "--" in cleaned_sql or "/*" in cleaned_sql:
        return False, "SQL comments are not permitted in queries."

    # Remove trailing semicolon if present
    sql_without_trailing_semicolon = cleaned_sql.rstrip().rstrip(";").strip()

    # Check for unquoted semicolons indicating multiple statements
    in_single_quote = False
    in_double_quote = False
    for char in sql_without_trailing_semicolon:
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
        elif char == ";" and not in_single_quote and not in_double_quote:
            return False, "Multiple SQL statements are not permitted."

    # Ensure the statement starts with SELECT or WITH (read-only CTE)
    if not re.match(r"^(SELECT|WITH)\b", sql_without_trailing_semicolon, re.IGNORECASE):
        return False, "Only read-only SELECT queries are permitted."

    # Search for forbidden write/modification keywords
    # Strip literal string contents first so users can search for words like 'create' in quotes
    string_stripped_sql = re.sub(r"'[^']*'|\"[^\"]*\"", "''", sql_without_trailing_semicolon)
    match = DISALLOWED_PATTERN.search(string_stripped_sql)
    if match:
        forbidden_word = match.group(0).upper()
        return False, f"Write or administrative command '{forbidden_word}' is forbidden. Only read-only SELECT queries are allowed."

    return True, ""

