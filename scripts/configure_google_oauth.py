"""
PII Shield — Secure Local Google OAuth Credential Configuration Script
Prompts the user locally in the terminal with hidden password input (getpass)
and updates root .env directly without exposing credentials to chat or logs.
"""

import getpass
import os
import re
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")

_PLACEHOLDER_MARKERS = [
    "your-google-client-id",
    "your-google-client-secret",
    "<your-client-id>",
    "<your-client-secret>",
    "placeholder",
    "change-this",
]


def update_env_variable(content: str, key: str, value: str) -> str:
    """Safely replace or append an environment variable in .env content."""
    pattern = rf"^{key}=.*$"
    new_line = f"{key}={value}"
    if re.search(pattern, content, flags=re.MULTILINE):
        return re.sub(pattern, new_line, content, flags=re.MULTILINE)
    else:
        return content.rstrip() + f"\n{new_line}\n"


def main():
    print("=" * 65)
    print("PII Shield — Secure Local Google OAuth Credential Setup")
    print("=" * 65)
    print("This script securely writes your Google OAuth credentials directly")
    print("to your local root .env file. The Client Secret input will be hidden.")
    print("Credentials are never transmitted to chat, terminal logs, or Git.")
    print("=" * 65)
    print()

    if not os.path.exists(_ENV_PATH):
        print(f"Error: .env file not found at {_ENV_PATH}")
        sys.exit(1)

    # 1. Prompt Client ID
    client_id = input("Enter your Google Client ID (e.g. xxxxx.apps.googleusercontent.com):\n> ").strip()
    if not client_id:
        print("Error: Client ID cannot be empty.")
        sys.exit(1)

    if any(marker in client_id.lower() for marker in _PLACEHOLDER_MARKERS):
        print("Error: The entered Client ID appears to be a placeholder.")
        sys.exit(1)

    # 2. Prompt Client Secret using getpass (hidden/masked)
    client_secret = getpass.getpass("Enter your Google Client Secret (hidden):\n> ").strip()
    if not client_secret:
        print("Error: Client Secret cannot be empty.")
        sys.exit(1)

    if any(marker in client_secret.lower() for marker in _PLACEHOLDER_MARKERS):
        print("Error: The entered Client Secret appears to be a placeholder.")
        sys.exit(1)

    # 3. Read current .env
    with open(_ENV_PATH, "r", encoding="utf-8") as f:
        env_content = f.read()

    # 4. Update entries
    env_content = update_env_variable(env_content, "GOOGLE_CLIENT_ID", client_id)
    env_content = update_env_variable(env_content, "GOOGLE_CLIENT_SECRET", client_secret)
    env_content = update_env_variable(env_content, "GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
    env_content = update_env_variable(env_content, "FRONTEND_URL", "http://localhost:3000")

    # 5. Write back to .env
    with open(_ENV_PATH, "w", encoding="utf-8") as f:
        f.write(env_content)

    print()
    print("[SUCCESS] Credentials safely saved to root .env file!")
    print(f"  GOOGLE_CLIENT_ID     : Configured (...{client_id[-20:]})")
    print(f"  GOOGLE_CLIENT_SECRET : Configured ({len(client_secret)} characters, masked)")
    print("  GOOGLE_REDIRECT_URI  : http://localhost:8000/auth/google/callback")
    print("  FRONTEND_URL         : http://localhost:3000")
    print()
    print("You can now restart your backend server or return to chat.")


if __name__ == "__main__":
    main()

