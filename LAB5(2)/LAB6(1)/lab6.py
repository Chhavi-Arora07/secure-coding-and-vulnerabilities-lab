"""
lab6.py - Experiment 6: Detecting Path Traversal in Python with Semgrep

All the code from the lab, compiled into one file:
  Part 1 - INSECURE version  (original; opens any user-supplied path, no validation)
  Part 2 - SECURE version    (remediated; confined to a safe directory)

Usage:
    python lab6.py insecure   # run the insecure version
    python lab6.py secure     # run the secure version (default)

Both versions prompt for a filename on stdin, same as in the lab.
"""

import sys
import os


# =============================================================================
# PART 1: INSECURE VERSION (original) -- kept only for the Semgrep "before" scan.
#          Do not reuse this code; it allows path traversal.
# =============================================================================

def insecure_read_user_file():
    """Ask the user for a filename and print its contents."""
    filename = input("Enter the name of the file to read: ")

    # No validation at all: filename is used exactly as typed, so a value
    # like "../../etc/passwd" or an absolute path escapes the intended folder.
    with open(filename, "r") as f:
        contents = f.read()

    print(contents)


def insecure_main():
    insecure_read_user_file()


# =============================================================================
# PART 2: SECURE VERSION (remediated)
# =============================================================================

SECURE_SAFE_DIR = os.path.realpath("safe_files")   # the only directory users may read from


def secure_read_user_file():
    """Ask the user for a filename and print its contents, confined to SECURE_SAFE_DIR."""
    filename = input("Enter the name of the file to read: ")

    # Reject path separators outright: only a bare filename is accepted,
    # never a relative or absolute path supplied by the user.
    if os.path.basename(filename) != filename:
        print("Invalid filename: only a plain filename is allowed, no path.")
        return

    # Resolve symlinks/'..' and confirm the final path is still inside SECURE_SAFE_DIR.
    candidate = os.path.realpath(os.path.join(SECURE_SAFE_DIR, filename))
    if os.path.commonpath([candidate, SECURE_SAFE_DIR]) != SECURE_SAFE_DIR:
        print("Invalid filename: outside the allowed directory.")
        return

    if not os.path.isfile(candidate):
        print("File not found.")
        return

    with open(candidate, "r") as f:
        contents = f.read()

    print(contents)


def secure_main():
    os.makedirs(SECURE_SAFE_DIR, exist_ok=True)
    secure_read_user_file()


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
        print("usage: python lab6.py [insecure|secure]")
