"""Generate a small ELF-shaped sample binary with planted weaknesses.

This gives the Binary agent something to analyse without needing a compiler.
The file embeds (on purpose): a hard-coded credential, references to unsafe C
functions, and ELF headers indicating no PIE and no stack canary.
"""
from __future__ import annotations

import argparse
from pathlib import Path

DEFAULT = Path("targets/bin/auth_service")

PLANTED = [
    b"NightLab auth_service build 1.0",
    b"admin_password = admin",      # hard-coded credential (same as the web admin)
    b"gets", b"strcpy", b"sprintf", b"system", b"/bin/sh",
    b"login_user(admin)",
]


def make(path: str | Path = DEFAULT) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2          # EI_CLASS = ELFCLASS64
    header[5] = 1          # EI_DATA  = little-endian
    header[6] = 1          # EI_VERSION
    header[16:18] = (2).to_bytes(2, "little")     # e_type = ET_EXEC  -> no PIE
    header[18:20] = (0x3e).to_bytes(2, "little")  # e_machine = x86-64
    # Note: no "__stack_chk_fail" string is included -> checksec reports no canary.
    blob = bytes(header) + b"\x00".join(PLANTED) + b"\x00"
    path.write_bytes(blob)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT))
    args = ap.parse_args()
    p = make(args.out)
    print(f"wrote sample binary: {p} ({p.stat().st_size} bytes)")
