"""
lab5.py - Experiment 5: Static Analysis of Insecure Python Code with Bandit

All the code from the lab, compiled into one file:
  Part 1 - INSECURE version  (original, 5 intentional defects; functions prefixed insecure_)
  Part 2 - SECURE version    (remediated; functions prefixed secure_)

Usage:
    python lab5.py insecure   # run the insecure version
    python lab5.py secure     # run the secure version (default)
"""

import sys
import os
import re
import random
import secrets
import shutil
import subprocess
import hashlib
import hmac


# =============================================================================
# PART 1: INSECURE VERSION (original) -- kept only for the Bandit "before" scan.
#          Do not reuse this code; it is intentionally vulnerable.
# =============================================================================

INSECURE_DB_PASSWORD = "Sup3rSecret!"            # hard-coded password


def insecure_generate_token(length=16):
    """Generate a 'random' security token for password-reset links."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(length))


def insecure_backup_database(db_name):
    """Back up a database by shelling out to mysqldump."""
    cmd = "mysqldump -u admin -p" + INSECURE_DB_PASSWORD + " " + db_name + " > backup.sql"
    subprocess.call(cmd, shell=True)                       # shell injection risk


def insecure_hash_password(password):
    """Hash a user password before storing it."""
    return hashlib.md5(password.encode()).hexdigest()      # weak hash for passwords


def insecure_run_diagnostic(hostname):
    """Ping a host supplied by the caller."""
    os.system("ping -c 1 " + hostname)                     # shell injection risk


def insecure_main():
    token = insecure_generate_token()
    print("Password reset token:", token)

    hashed = insecure_hash_password("hunter2")
    print("Stored hash:", hashed)

    insecure_backup_database("app_production")
    insecure_run_diagnostic("localhost")


# =============================================================================
# PART 2: SECURE VERSION (remediated)
# =============================================================================

def secure_get_db_password():
    """Read the DB password from the environment instead of hard-coding it."""
    password = os.environ.get("DB_PASSWORD")
    if not password:
        raise RuntimeError("DB_PASSWORD environment variable is not set")
    return password


def secure_generate_token(length=16):
    """Generate a cryptographically secure security token."""
    return secrets.token_urlsafe(length)


def secure_backup_database(db_name):
    """Back up a database without going through a shell."""
    if not re.fullmatch(r"[A-Za-z0-9_]+", db_name):
        raise ValueError("invalid database name")

    password = secure_get_db_password()
    mysqldump = shutil.which("mysqldump")
    if mysqldump is None:
        raise FileNotFoundError("mysqldump not found on PATH")

    # shell=False, absolute path, fixed argv, db_name validated above, password passed via env, not argv
    with open("backup.sql", "wb") as out:
        subprocess.run(
            [mysqldump, "-u", "admin", db_name],
            check=True,
            stdout=out,
            env={**os.environ, "MYSQL_PWD": password},
        )  # nosec B603


def secure_hash_password(password, salt=None):
    """Hash a user password with a salted, slow KDF (PBKDF2-HMAC-SHA256)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt, derived


def secure_verify_password(password, salt, expected):
    """Verify a password against a stored salt/hash using a constant-time compare."""
    _, derived = secure_hash_password(password, salt)
    return hmac.compare_digest(derived, expected)


def secure_run_diagnostic(hostname):
    """Ping a host supplied by the caller, without going through a shell."""
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", hostname):
        raise ValueError("invalid hostname")

    ping = shutil.which("ping")
    if ping is None:
        raise FileNotFoundError("ping not found on PATH")

    # shell=False, absolute path, hostname validated above
    subprocess.run([ping, "-c", "1", hostname], check=True)  # nosec B603


def secure_main():
    token = secure_generate_token()
    print("Password reset token:", token)

    salt, hashed = secure_hash_password("hunter2")
    print("Stored hash:", hashed.hex())
    print("Verified:", secure_verify_password("hunter2", salt, hashed))

    # secure_backup_database("app_production")   # requires DB_PASSWORD env var and mysqldump installed
    try:
        secure_run_diagnostic("localhost")
    except FileNotFoundError as exc:
        print("Diagnostic skipped:", exc)


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    choice = sys.argv[1] if len(sys.argv) > 1 else "secure"
    if choice == "insecure":
        insecure_main()
    elif choice == "secure":
        secure_main()
    else:
        print("usage: python lab5.py [insecure|secure]")
