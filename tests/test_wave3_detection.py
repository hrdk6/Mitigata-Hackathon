"""Wave 3: version-parser accuracy, expanded CVEs, catch-all-aware sensitive
paths, SNMP default communities, and SMB (SMBv1 / signing) detection."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nighttrace import netservices, vulndb
from nighttrace.checks import CheckEngine
from nighttrace.config import Config, Scope
from nighttrace.netservices import _SYSDESCR_OID, _tlv
from nighttrace.safety import ScopeGuard

LOCAL = "127.0.0.1"


def _guard() -> ScopeGuard:
    return ScopeGuard(Config(scope=Scope(hosts=[LOCAL])))


# -- CVE data accuracy --------------------------------------------------------
def test_openssl_letter_release_is_not_confused_with_vulnerable_one():
    assert [h.cve for h in vulndb.lookup("openssl", "1.0.1f")] == ["CVE-2014-0160"]
    assert vulndb.lookup("openssl", "1.0.1g") == []      # the fixed release
    assert vulndb.lookup("openssl", "1.0.0") == []       # predates Heartbleed
    assert [h.cve for h in vulndb.lookup("openssl", "3.0.2")] == ["CVE-2022-3602"]


def test_expanded_cve_entries():
    assert {h.cve for h in vulndb.lookup("exim", "4.89")} == {"CVE-2019-10149", "CVE-2020-28018"}
    assert [h.cve for h in vulndb.lookup("exim", "4.93")] == ["CVE-2020-28018"]
    assert vulndb.lookup("exim", "4.96") == []
    assert [h.cve for h in vulndb.lookup("nginx", "1.18.0")] == ["CVE-2021-23017"]


# -- sensitive paths vs catch-all servers --------------------------------------
def _http_server(handler):
    httpd = ThreadingHTTPServer((LOCAL, 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class _CatchAll(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # every route answers 200 with the same app shell
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>app shell</body></html>")


class _Strict(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/admin":
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /secret\n")
            return
        self.send_response(404)
        self.end_headers()


_PATHS_CHECK = {"probe": {"type": "http_paths", "expect_status": [200, 401, 403],
                          "paths": ["/admin", "/robots.txt", "/.env", "/debug"]}}


def _web_target(port):
    return {"host": LOCAL, "port": port, "base_url": f"http://{LOCAL}:{port}", "params": []}


def test_sensitive_paths_silent_on_catchall():
    httpd = _http_server(_CatchAll)
    try:
        out = CheckEngine([])._probe_http_paths(_PATHS_CHECK, _web_target(httpd.server_address[1]), _guard())
    finally:
        httpd.shutdown()
    assert out == []


def test_sensitive_paths_still_flags_real_resources():
    httpd = _http_server(_Strict)
    try:
        out = CheckEngine([])._probe_http_paths(_PATHS_CHECK, _web_target(httpd.server_address[1]), _guard())
    finally:
        httpd.shutdown()
    assert sorted(o.data["path"] for o in out) == ["/admin", "/robots.txt"]


# -- SNMP ----------------------------------------------------------------------
def _snmp_agent(accepted: bytes) -> int:
    """A UDP agent that answers sysDescr.0 only for the accepted community and
    silently drops anything else — like a real agent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL, 0))
    sock.settimeout(10)

    def parse(data):
        i = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
        i += 2 + data[i + 1]                                  # version
        community = data[i + 2:i + 2 + data[i + 1]]
        i += 2 + data[i + 1]                                  # community
        i += 2 if data[i + 1] < 0x80 else 2 + (data[i + 1] & 0x7F)  # into the PDU
        return community, data[i + 2:i + 2 + data[i + 1]]     # request-id value

    def serve():
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                break
            community, rid = parse(data)
            if community != accepted:
                continue
            varbind = _tlv(0x30, _tlv(0x06, _SYSDESCR_OID) + _tlv(0x04, b"Linux nt-test 5.4"))
            pdu = _tlv(0xA2, _tlv(0x02, rid) + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00")
                       + _tlv(0x30, varbind))
            sock.sendto(_tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community) + pdu), addr)

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_snmp_default_community_detected():
    port = _snmp_agent(b"public")
    r = netservices.snmp_default_community(_guard(), LOCAL, port, timeout=0.5,
                                           communities=("not-it", "public"))
    assert r["open"] and r["community"] == "public"
    assert r["sysdescr"] == "Linux nt-test 5.4"

    outs = CheckEngine([])._probe_net_snmp({}, {"host": LOCAL, "port": port}, _guard())
    assert outs and outs[0].severity == "medium" and "public" in outs[0].title


def test_snmp_wrong_community_is_not_reported():
    port = _snmp_agent(b"s3cret-community")
    r = netservices.snmp_default_community(_guard(), LOCAL, port, timeout=0.4)
    assert r == {"open": False}


# -- SMB -----------------------------------------------------------------------
def _smb1_response() -> bytes:
    hdr = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x98" + b"\x01\x28" + b"\x00" * 2
           + b"\x00" * 8 + b"\x00" * 2 + b"\x00" * 2 + b"\x2f\x4b" + b"\x00" * 2 + b"\xc5\x5e")
    body = bytes([17]) + (0).to_bytes(2, "little") + b"\x00" * 32  # dialect 0 accepted
    msg = hdr + body
    return len(msg).to_bytes(4, "big") + msg


def _smb2_response(security_mode: int) -> bytes:
    hdr = (b"\xfeSMB" + (64).to_bytes(2, "little") + b"\x00" * 2 + b"\x00" * 4 + b"\x00\x00"
           + b"\x01\x00" + b"\x01\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 4
           + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 16)
    body = ((65).to_bytes(2, "little") + security_mode.to_bytes(2, "little")
            + (0x0302).to_bytes(2, "little") + b"\x00" * 58)
    msg = hdr + body
    return len(msg).to_bytes(4, "big") + msg


def _smb_server(smbv1: bool, security_mode: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOCAL, 0))
    srv.listen()
    srv.settimeout(10)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            try:
                req = conn.recv(1024)
                if req[4:8] == b"\xffSMB" and smbv1:
                    conn.sendall(_smb1_response())
                elif req[4:8] == b"\xfeSMB":
                    conn.sendall(_smb2_response(security_mode))
                # SMBv1 disabled: close without answering, as Windows does
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_smb_info_detects_smbv1_and_unsigned():
    port = _smb_server(smbv1=True, security_mode=0x0001)  # signing enabled, not required
    info = netservices.smb_info(_guard(), LOCAL, port, timeout=2.0)
    assert info["smbv1"] is True
    assert info["signing_required"] is False
    assert info["dialect"] == 0x0302


def test_smb_info_no_false_positive_when_hardened():
    port = _smb_server(smbv1=False, security_mode=0x0003)  # SMBv1 off, signing required
    info = netservices.smb_info(_guard(), LOCAL, port, timeout=2.0)
    assert info["smbv1"] is False
    assert info["signing_required"] is True


def test_engine_maps_smb_results_to_findings(monkeypatch):
    monkeypatch.setattr(netservices, "smb_info",
                        lambda *a, **k: {"smbv1": True, "signing_required": False, "dialect": 0x0302})
    outs = CheckEngine([])._probe_net_unauth(
        {"probe": {"type": "net_unauth"}}, {"host": LOCAL, "port": 445, "service": "smb"}, _guard())
    assert {o.data["sub"]: o.severity for o in outs} == {"smbv1": "high", "smb-signing": "medium"}
    # port 139 needs a NetBIOS session first, so it is deliberately skipped
    assert CheckEngine([])._probe_net_unauth(
        {"probe": {"type": "net_unauth"}}, {"host": LOCAL, "port": 139, "service": "smb"}, _guard()) == []
