"""Non-destructive network-service interrogation.

Low-level, read-only probes the network checks use to turn an open port into a
real finding: identify the product/version behind a banner, detect services
left open without authentication, and audit a TLS endpoint's certificate and
protocol. Every probe asks the Scope Guard for permission first (so these count
toward scope safety and stray-probe stays at zero) and none of them writes,
deletes, or changes anything on the target.
"""
from __future__ import annotations

import re
import secrets
import socket
import ssl

from nighttrace import tools
from nighttrace.safety.scope_guard import ScopeGuard


# -- banner / version fingerprinting -----------------------------------------
# (product, regex). Separators are flexible ([\s_/-]+) so the same pattern
# matches a raw banner ("OpenSSH_7.6p1"), an HTTP Server header ("Apache/2.4.49"),
# and an nmap -sV product string ("OpenSSH 7.6p1 Ubuntu"). First group = version.
_VERSION_PATTERNS: list[tuple[str, str]] = [
    ("openssh", r"OpenSSH[\s_/-]+([0-9]+\.[0-9]+(?:p[0-9]+)?)"),
    ("dropbear", r"[Dd]ropbear(?:[\s_/-]*SSH)?[\s_/-]+([0-9]{4}\.[0-9]+)"),
    ("vsftpd", r"vsFTPd[\s_/-]+([0-9]+\.[0-9]+\.[0-9]+)"),
    ("proftpd", r"ProFTPD[\s_/-]+([0-9]+\.[0-9]+\.[0-9]+)"),
    ("pure-ftpd", r"Pure-FTPd.*?([0-9]+\.[0-9]+\.[0-9]+)"),
    ("exim", r"Exim[\s_/-]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("apache", r"Apache(?:/|[\s_-]+httpd[\s_-]+|[\s_-]+)([0-9]+\.[0-9]+\.[0-9]+)"),
    ("nginx", r"nginx[\s_/-]+([0-9]+\.[0-9]+\.[0-9]+)"),
    ("microsoft-iis", r"(?:Microsoft-IIS|IIS)[\s_/-]+([0-9]+\.[0-9]+)"),
    ("webmin", r"(?:MiniServ|Webmin)[\s_/-]+([0-9]+\.[0-9]+)"),
    ("openssl", r"OpenSSL[\s_/-]+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)"),
]


def identify(service: str | None, banner: str, http_server: str | None = None) -> tuple[str | None, str | None]:
    """Best-effort (product, version) from a service banner and/or HTTP Server
    header. Returns (None, None) when nothing is confidently recognised."""
    text = " ".join(t for t in (banner, http_server) if t)
    if not text:
        return None, None
    for product, pattern in _VERSION_PATTERNS:
        m = re.search(pattern, text, re.I)
        if m:
            version = m.group(1) if m.groups() else None
            return product, version
    return None, None


def _connect(guard: ScopeGuard, host: str, port: int, timeout: float) -> socket.socket | None:
    if not guard.check_network(host, port).allowed:
        return None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        return s
    except OSError:
        return None


def banner(guard: ScopeGuard, host: str, port: int, timeout: float = 2.0,
           send: bytes | None = None) -> str:
    """Read a service banner (optionally after sending a tiny, harmless nudge)."""
    s = _connect(guard, host, port, timeout)
    if s is None:
        return ""
    try:
        if send:
            s.sendall(send)
        return s.recv(256).decode("latin-1", "replace").strip()
    except OSError:
        return ""
    finally:
        try:
            s.close()
        except OSError:
            pass


# -- unauthenticated-exposure probes (read-only) -----------------------------
def redis_unauth(guard: ScopeGuard, host: str, port: int, timeout: float = 2.0) -> dict:
    """Redis answers INFO without auth when protected-mode/AUTH is off. INFO is
    read-only. Returns {open, version} (open=True means no authentication)."""
    s = _connect(guard, host, port, timeout)
    if s is None:
        return {"open": False}
    try:
        s.sendall(b"INFO\r\n")
        resp = s.recv(2048).decode("latin-1", "replace")
    except OSError:
        return {"open": False}
    finally:
        try:
            s.close()
        except OSError:
            pass
    if "NOAUTH" in resp or "-ERR" in resp[:16]:
        return {"open": False}  # authentication is required — good
    if "redis_version" in resp:
        m = re.search(r"redis_version:([0-9.]+)", resp)
        return {"open": True, "version": m.group(1) if m else None}
    return {"open": False}


def memcached_unauth(guard: ScopeGuard, host: str, port: int, timeout: float = 2.0) -> dict:
    """memcached 'stats' (read-only) succeeds when the server is exposed without SASL."""
    s = _connect(guard, host, port, timeout)
    if s is None:
        return {"open": False}
    try:
        s.sendall(b"stats\r\n")
        resp = s.recv(2048).decode("latin-1", "replace")
    except OSError:
        return {"open": False}
    finally:
        try:
            s.close()
        except OSError:
            pass
    if resp.startswith("STAT ") or "\nSTAT " in resp:
        m = re.search(r"STAT version ([0-9.]+)", resp)
        return {"open": True, "version": m.group(1) if m else None}
    return {"open": False}


def elasticsearch_open(guard: ScopeGuard, host: str, port: int) -> dict:
    """Elasticsearch returns cluster info on GET / when exposed without auth."""
    resp = tools.http_request(guard, f"http://{host}:{port}/")
    if not resp or resp.get("status") != 200:
        return {"open": False}
    body = resp.get("body", "")
    if '"cluster_name"' in body and ('"lucene_version"' in body or '"number"' in body):
        m = re.search(r'"number"\s*:\s*"([0-9.]+)"', body)
        return {"open": True, "version": m.group(1) if m else None}
    return {"open": False}


def ftp_anonymous(guard: ScopeGuard, host: str, port: int, timeout: float = 3.0) -> dict:
    """Check whether the FTP server accepts the anonymous account. Read-only: it
    logs in and stops — it never lists, reads, or writes files."""
    s = _connect(guard, host, port, timeout)
    if s is None:
        return {"open": False}
    try:
        s.recv(256)  # 220 greeting
        s.sendall(b"USER anonymous\r\n")
        s.recv(256)
        s.sendall(b"PASS anonymous@example.com\r\n")
        resp = s.recv(256).decode("latin-1", "replace")
    except OSError:
        return {"open": False}
    finally:
        try:
            s.sendall(b"QUIT\r\n")
            s.close()
        except OSError:
            pass
    return {"open": resp.strip().startswith("230")}


def tcp_reachable(guard: ScopeGuard, host: str, port: int, timeout: float = 2.0) -> bool:
    """A plain scope-checked 'is this port accepting connections' test, used to
    confirm an exposed-service finding non-destructively."""
    s = _connect(guard, host, port, timeout)
    if s is None:
        return False
    try:
        return True
    finally:
        try:
            s.close()
        except OSError:
            pass


# -- TLS certificate / protocol audit ----------------------------------------
_WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def tls_audit(guard: ScopeGuard, host: str, port: int, timeout: float = 4.0) -> dict:
    """Audit a TLS endpoint without a third-party library. Returns
    {reachable, tls_version, weak_protocol, cert_status} where cert_status is one
    of valid | self-signed | expired | hostname-mismatch | untrusted | unknown."""
    if not guard.check_network(host, port).allowed:
        return {"reachable": False}

    # 1) An unverified handshake always succeeds (if TLS is spoken) and tells us
    #    the negotiated protocol version.
    tls_version = None
    try:
        unv = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with unv.wrap_socket(raw, server_hostname=host) as ss:
                tls_version = ss.version()
    except (OSError, ssl.SSLError, ValueError):
        return {"reachable": False}

    # 2) A verifying handshake classifies the certificate from the failure (or
    #    its success). No certificate parsing library needed.
    cert_status = "valid"
    try:
        ver = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ver.wrap_socket(raw, server_hostname=host):
                cert_status = "valid"
    except ssl.SSLCertVerificationError as exc:
        reason = str(exc).lower()
        if "self signed" in reason or "self-signed" in reason:
            cert_status = "self-signed"
        elif "expired" in reason:
            cert_status = "expired"
        elif "hostname mismatch" in reason or "doesn't match" in reason or "ip address mismatch" in reason:
            cert_status = "hostname-mismatch"
        else:
            cert_status = "untrusted"
    except (OSError, ssl.SSLError):
        cert_status = "unknown"

    return {"reachable": True, "tls_version": tls_version,
            "weak_protocol": tls_version in _WEAK_TLS, "cert_status": cert_status}


# -- SNMP default community (UDP/161) ----------------------------------------
_SYSDESCR_OID = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _snmp_get_packet(community: str, request_id: int) -> bytes:
    """SNMPv1 GetRequest for sysDescr.0 — a read-only query."""
    rid = request_id.to_bytes((request_id.bit_length() + 8) // 8, "big")  # minimal, positive
    varbind = _tlv(0x30, _tlv(0x06, _SYSDESCR_OID) + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _tlv(0x02, rid) + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00")
               + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community.encode()) + pdu)


def _snmp_response(data: bytes, community: str, request_id: int) -> dict | None:
    """Accept only a real GetResponse that echoes our community and request id
    (agents silently drop a wrong community, so a reply means it was accepted)."""
    rid = request_id.to_bytes((request_id.bit_length() + 8) // 8, "big")
    if not data or data[0] != 0x30 or b"\xa2" not in data:
        return None
    if _tlv(0x04, community.encode()) not in data or _tlv(0x02, rid) not in data:
        return None
    descr = None
    marker = _tlv(0x06, _SYSDESCR_OID)
    i = data.find(marker)
    if i != -1 and i + len(marker) + 1 < len(data) and data[i + len(marker)] == 0x04:
        j = i + len(marker) + 1
        ln, start = data[j], j + 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln, start = int.from_bytes(data[j + 1:j + 1 + nb], "big"), j + 1 + nb
        descr = data[start:start + ln].decode("latin-1", "replace").strip() or None
    return {"sysdescr": descr}


def snmp_default_community(guard: ScopeGuard, host: str, port: int = 161, timeout: float = 1.5,
                           communities: tuple[str, ...] = ("public", "private")) -> dict:
    """Does the SNMP agent answer a read-only GET with a default community?
    Returns {open, community, sysdescr}."""
    for community in communities:
        if not community or not guard.check_network(host, port).allowed:
            continue
        rid = secrets.randbelow(0x7FFFFFF0) + 1
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))  # connected UDP surfaces ICMP 'port unreachable' fast
                s.send(_snmp_get_packet(community, rid))
                data = s.recv(4096)
        except OSError:
            continue
        info = _snmp_response(data, community, rid)
        if info is not None:
            return {"open": True, "community": community, "sysdescr": info.get("sysdescr")}
    return {"open": False}


# -- SMB (TCP/445): legacy SMBv1 and message signing --------------------------
# SMB1 NEGOTIATE offering only the "NT LM 0.12" dialect. A server that still
# speaks SMBv1 answers with an SMB1 negotiate response; one with SMBv1 disabled
# closes the connection or refuses the dialect.
_SMB1_NEGOTIATE = bytes.fromhex(
    "0000002f"                                    # direct-TCP header, length 47
    "ff534d42" "72" "00000000" "18" "0128"        # \xffSMB, NEGOTIATE, status, flags, flags2
    "0000" "0000000000000000" "0000" "0000"       # PID-high, signature, reserved, TID
    "2f4b" "0000" "c55e"                          # PID, UID, MID
    "00" "0c00" "024e54204c4d20302e313200"        # word count, byte count, "NT LM 0.12"
)


def _smb2_negotiate() -> bytes:
    header = (b"\xfeSMB" + (64).to_bytes(2, "little") + b"\x00" * 2 + b"\x00" * 4
              + b"\x00\x00"                       # command: NEGOTIATE
              + (1).to_bytes(2, "little")         # credits requested
              + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 4 + b"\x00" * 4
              + b"\x00" * 8 + b"\x00" * 16)
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = ((36).to_bytes(2, "little") + len(dialects).to_bytes(2, "little")
            + (1).to_bytes(2, "little")          # SecurityMode: signing enabled
            + b"\x00" * 2 + b"\x00" * 4 + secrets.token_bytes(16) + b"\x00" * 8
            + b"".join(d.to_bytes(2, "little") for d in dialects))
    msg = header + body
    return len(msg).to_bytes(4, "big") + msg


def _smb_exchange(guard: ScopeGuard, host: str, port: int, payload: bytes, timeout: float) -> bytes:
    s = _connect(guard, host, port, timeout)
    if s is None:
        return b""
    try:
        s.sendall(payload)
        return s.recv(1024)
    except OSError:
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def smb_info(guard: ScopeGuard, host: str, port: int = 445, timeout: float = 3.0) -> dict:
    """Read-only SMB negotiation. Returns {smbv1, signing_required, dialect};
    signing_required is None when SMB2 negotiation did not complete."""
    r1 = _smb_exchange(guard, host, port, _SMB1_NEGOTIATE, timeout)
    smbv1 = (len(r1) >= 39 and r1[4:8] == b"\xffSMB" and r1[8] == 0x72
             and r1[9:13] == b"\x00\x00\x00\x00" and r1[36] > 0
             and int.from_bytes(r1[37:39], "little") != 0xFFFF)

    r2 = _smb_exchange(guard, host, port, _smb2_negotiate(), timeout)
    signing_required, dialect = None, None
    if (len(r2) >= 74 and r2[4:8] == b"\xfeSMB" and r2[12:16] == b"\x00\x00\x00\x00"
            and r2[16:18] == b"\x00\x00"):
        security_mode = int.from_bytes(r2[70:72], "little")
        signing_required = bool(security_mode & 0x02)
        dialect = int.from_bytes(r2[72:74], "little")
    return {"smbv1": smbv1, "signing_required": signing_required, "dialect": dialect}
