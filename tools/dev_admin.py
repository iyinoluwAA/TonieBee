#!/usr/bin/env python3
"""Make (or reset) a DEVELOPMENT admin by typing into the real `create-admin` command,
like a person would: password twice, then a code from the authenticator key it shows.

    python3 tools/dev_admin.py [email] [password]

Saves email, password, authenticator key and backup codes to tools/e2e/out/dev-admin.json
(git-ignored) so tests — and AJ — can sign in to the local dashboard. Never point this at
the live database: it only ever uses backend/.env (APP_ENV=development).

Print the current code any time:  python3 tools/dev_admin.py --code
"""

import base64
import hashlib
import hmac
import json
import os
import pty
import re
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tools" / "e2e" / "out" / "dev-admin.json"
BINARY = ROOT / "backend" / "target" / "debug" / "toniebee-api"


def totp(key: str, at: float | None = None) -> str:
    secret = base64.b32decode(key.replace(" ", "").upper() + "=" * (-len(key.replace(" ", "")) % 8))
    step = int((at or time.time()) // 30)
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def main() -> None:
    if sys.argv[1:2] == ["--code"]:
        saved = json.loads(OUT.read_text())
        print(totp(saved["key"]))
        return
    env_text = (ROOT / "backend" / ".env").read_text()
    if "APP_ENV=development" not in env_text:
        sys.exit("backend/.env isn't APP_ENV=development — refusing.")
    email = sys.argv[1] if len(sys.argv) > 1 else "admin@toniebee.dev"
    password = sys.argv[2] if len(sys.argv) > 2 else "quiet harbour lights at dawn"
    if not BINARY.exists():
        sys.exit("Build the API first: (cd backend && cargo build)")

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT / "backend")
        os.execv(str(BINARY), [str(BINARY), "create-admin", email])

    buffer = ""

    def read_until(pattern: str, timeout: float = 60) -> str:
        nonlocal buffer
        end = time.time() + timeout
        while time.time() < end:
            match = re.search(pattern, buffer)
            if match:
                found = buffer[: match.end()]
                buffer = buffer[match.end() :]
                return found
            try:
                chunk = os.read(fd, 4096).decode(errors="replace")
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
        sys.exit(f"create-admin didn't ask for {pattern!r}. Output so far:\n{buffer}")

    def send(text: str) -> None:
        os.write(fd, (text + "\n").encode())

    first = read_until(r"(Type RESET to continue: |Type ADMIN to continue: |typing is hidden\): )")
    if "RESET" in first:
        send("RESET")
        read_until(r"typing is hidden\): ")
    elif "ADMIN" in first:
        send("ADMIN")
        read_until(r"typing is hidden\): ")
    send(password)
    read_until(r"Type it again: ")
    send(password)
    shown = read_until(r"key: ([A-Z2-7 ]+)\r?\n")
    key = re.search(r"key: ([A-Z2-7 ]+)\r?\n", shown).group(1).strip()
    read_until(r"code the app shows now: ")
    send(totp(key))
    rest = read_until(r"Sign in at the website", timeout=60)
    codes = re.findall(r"\b([A-Z2-9]{5}-[A-Z2-9]{5})\b", rest)
    os.waitpid(pid, 0)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"email": email, "password": password, "key": key, "backupCodes": codes}, indent=2))
    os.chmod(OUT, 0o600)
    print(f"✓ Dev admin {email} ready ({len(codes)} backup codes). Saved to {OUT.relative_to(ROOT)}.")
    print(f"  Current code: python3 tools/dev_admin.py --code")


if __name__ == "__main__":
    main()
