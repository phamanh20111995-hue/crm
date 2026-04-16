from __future__ import annotations

import argparse
import hashlib
import secrets
import sqlite3
from pathlib import Path


def hash_password(raw_password: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), b"crm_mvp_salt_v1", 120_000).hex()
    return f"pbkdf2_sha256${digest}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Rotate default passwords (123456) for active users in CRM SQLite DB.")
    parser.add_argument("--db", default="data/mvp_api.db", help="Path to SQLite DB file (default: data/mvp_api.db)")
    parser.add_argument(
        "--min-length",
        type=int,
        default=14,
        help="Generated password length (default: 14)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"DB file not found: {db_path}")

    default_hash = hash_password("123456")
    rotated: list[tuple[str, str]] = []

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT user_code FROM users WHERE active = 1 AND password = ? ORDER BY user_code",
            (default_hash,),
        ).fetchall()
        for (user_code,) in rows:
            # URL-safe chars; truncate to requested minimum length.
            new_password = secrets.token_urlsafe(max(args.min_length, 14))[: args.min_length]
            conn.execute(
                "UPDATE users SET password = ? WHERE user_code = ?",
                (hash_password(new_password), user_code),
            )
            rotated.append((user_code, new_password))

    if not rotated:
        print("No active user with default password found. Nothing changed.")
        return

    print("Rotated default passwords for users:")
    for user_code, pw in rotated:
        print(f"- {user_code}: {pw}")
    print("\nStore these passwords securely and rotate again after first login.")


if __name__ == "__main__":
    main()
