"""Privilege-free OS fingerprinting.

nmap's `-O` needs raw sockets and root/Administrator, which this engine does not
assume it has. So instead of active stack fingerprinting we *infer* the operating
-system family from signals we already collect during an ordinary, non-destructive
scan:

  * the IP TTL of a reply (Windows ships 128, most Unix 64, routers/printers 255);
  * the set of open ports (SMB/RDP say Windows, lockdownd says an Apple phone, ...);
  * the HTTP ``Server`` header (IIS vs Apache-on-Ubuntu, ...);
  * the MAC address (locally-administered bit => a randomized/mobile MAC).

Each signal nudges a per-family score; the winner, its confidence and the reasons
behind it are returned. This is not courtroom attribution -- it is enough for the
engine (and any model reading the blackboard) to choose OS-appropriate tactics:
SMB/RDP checks on Windows, SSH/web checks on Unix, and so on.
"""
from __future__ import annotations

import re
import subprocess
import sys

# Ports that strongly imply a given platform.
_WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986, 1433}
_APPLE_MOBILE_PORTS = {62078}          # lockdownd (iPhone / iPad)
_MACOS_PORTS = {548, 88}               # AFP, Kerberos
_PRINTER_PORTS = {515, 631, 9100}      # LPD, IPP, JetDirect
_UNIX_HINT_PORTS = {22, 2049, 111}     # ssh, nfs, rpcbind

_LABELS = {
    "windows": "Windows",
    "linux": "Linux/Unix",
    "macos": "macOS",
    "apple-mobile": "iOS/iPadOS (Apple mobile)",
    "network-device": "Network device / printer",
}

_TTL_RE = re.compile(r"ttl[=:]\s*(\d+)", re.I)


def ttl_ping(host: str, timeout: float = 1.0) -> int | None:
    """One ICMP echo, parse the reply TTL. Cross-platform, best-effort, None on
    failure. The caller is responsible for scope-checking the host first."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 2).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = _TTL_RE.search(out)
    return int(m.group(1)) if m else None


def is_randomized_mac(mac: str | None) -> bool:
    """True if the MAC has the locally-administered bit set -- i.e. a randomized
    address, as modern phones/laptops use for privacy."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (AttributeError, ValueError, IndexError):
        return False


def _ttl_class(ttl: int | None) -> str | None:
    if ttl is None:
        return None
    if ttl > 200:   # ~255, minus a few hops
        return "ttl255"
    if ttl > 100:   # ~128
        return "windows"
    if ttl >= 32:   # ~64
        return "unix"
    return None


def fingerprint(*, ttl: int | None = None, open_ports=None,
                http_server: str | None = None, mac: str | None = None) -> dict:
    """Infer the OS family from the given signals.

    Returns {os, family, confidence (0..1), reasons: [...], ttl, randomized_mac}.
    family is one of windows|linux|macos|apple-mobile|network-device|unknown.
    """
    ports = {int(p) for p in (open_ports or [])}
    scores = {k: 0.0 for k in _LABELS}
    reasons: list[str] = []

    tc = _ttl_class(ttl)
    if tc == "windows":
        scores["windows"] += 0.5
        reasons.append(f"TTL~128 implies Windows (observed {ttl})")
    elif tc == "unix":
        scores["linux"] += 0.25
        scores["macos"] += 0.18
        scores["apple-mobile"] += 0.12
        reasons.append(f"TTL~64 implies a Unix-like stack (observed {ttl})")
    elif tc == "ttl255":
        scores["network-device"] += 0.45
        reasons.append(f"TTL~255 implies a router/printer/other device (observed {ttl})")

    win_hits = ports & _WINDOWS_PORTS
    if win_hits:
        scores["windows"] += 0.5
        reasons.append("Windows service ports: " + ",".join(map(str, sorted(win_hits))))
    if ports & _APPLE_MOBILE_PORTS:
        scores["apple-mobile"] += 0.6
        reasons.append("port 62078 (Apple lockdownd) implies an iPhone/iPad")
    if ports & _MACOS_PORTS:
        scores["macos"] += 0.35
        reasons.append("AFP/Kerberos ports suggest macOS")
    if ports & _PRINTER_PORTS:
        scores["network-device"] += 0.4
        reasons.append("printing ports suggest a printer/appliance")
    if (ports & _UNIX_HINT_PORTS) and not win_hits:
        scores["linux"] += 0.22
        scores["macos"] += 0.1
        reasons.append("SSH/NFS present with no Windows ports")

    srv = (http_server or "").lower()
    if srv:
        if "microsoft" in srv or "iis" in srv:
            scores["windows"] += 0.4
            reasons.append(f"HTTP Server header '{http_server}' (IIS/Windows)")
        elif any(k in srv for k in ("ubuntu", "debian", "centos", "red hat", "fedora", "unix", "linux")):
            scores["linux"] += 0.4
            reasons.append(f"HTTP Server header '{http_server}' (Linux)")
        elif "darwin" in srv or "mac" in srv:
            scores["macos"] += 0.3
            reasons.append(f"HTTP Server header '{http_server}' (macOS)")
        elif "win" in srv:
            scores["windows"] += 0.2
            reasons.append(f"HTTP Server header '{http_server}'")

    randomized = is_randomized_mac(mac)
    if randomized:
        reasons.append("randomized/locally-administered MAC (modern phone/laptop privacy)")

    family, best = max(scores.items(), key=lambda kv: kv[1])
    total = sum(scores.values())
    if best <= 0:
        return {"os": "unknown", "family": "unknown", "confidence": 0.0,
                "reasons": reasons or ["no OS-distinguishing signals observed"],
                "ttl": ttl, "randomized_mac": randomized}

    # Confidence: how dominant the winner is, scaled by how much evidence there is.
    confidence = round(min(0.95, (best / total) * (0.55 + min(best, 1.0) * 0.45)), 2)
    return {"os": _LABELS[family], "family": family, "confidence": confidence,
            "reasons": reasons, "ttl": ttl, "randomized_mac": randomized}


# Convenience for downstream method-selection: tactics worth trying per family.
SUGGESTED_TACTICS = {
    "windows": ["smb-enum", "rdp-check", "eternalblue-era-smb", "http-iis", "mssql"],
    "linux": ["ssh-audit", "web-app", "nfs-export", "known-service-cves"],
    "macos": ["ssh-audit", "web-app", "afp", "screen-sharing-vnc"],
    "apple-mobile": ["passive-only", "service-exposure"],
    "network-device": ["default-creds", "admin-web-ui", "snmp"],
    "unknown": ["web-app", "service-banner-cves"],
}


def suggested_tactics(family: str) -> list[str]:
    return SUGGESTED_TACTICS.get(family, SUGGESTED_TACTICS["unknown"])
