"""The check engine: runs declarative checks (from checks.yaml).

A *probe* looks for a weakness and produces a Suspected outcome. A *verify*
step re-tests it and captures evidence, promoting it to Confirmed (or Refuted).
Checks are data; this module maps each declared probe/verify `type` to a safe,
non-destructive handler. Adding a new check means editing YAML, not code (B-4).
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlencode

from nighttrace import netservices, tools, vulndb
from nighttrace.safety.scope_guard import ScopeGuard


@dataclass
class ProbeOutcome:
    type: str
    title: str
    severity: str
    description: str = ""
    fix: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


@dataclass
class VerifyOutcome:
    confirmed: bool
    evidence: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)


def _extract_strings(raw: bytes, min_len: int = 4) -> list[str]:
    out, cur = [], bytearray()
    for b in raw:
        if 32 <= b < 127:
            cur.append(b)
        elif len(cur) >= min_len:
            out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
        else:
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "ignore"))
    return out


def _secret_value(s: str) -> str:
    m = re.search(r"[=:]\s*['\"]?([^'\"\s]+)", s)
    return m.group(1) if m else ""


def _mask(s: str) -> str:
    m = re.search(r"(.*?[=:]\s*['\"]?)(\S+)", s)
    if not m:
        return s[:48]
    val = m.group(2)
    masked = val[0] + "•" * max(len(val) - 1, 1) if val else "•"
    return (m.group(1) + masked)[:64]


# Signatures used for non-destructive, read-only detection.
_SQL_ERRORS = (
    "sql syntax", "mysql_fetch", "you have an error in your sql", "ora-",
    "sqlite", "sqlstate", "unclosed quotation", "odbc", "pg::", "psql:",
    "warning: pg_", "syntax error at or near", "quoted string not properly terminated",
)
_TRAVERSAL = (
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
    "netops-handover.txt",
    "ops&view=netops-handover.txt",
    "edr_log_generator.py",
)
_SQL_PROBE = "1'"   # a single quote — read-only, non-destructive SQL-error probe
_SQL_SAFE = "1"


def _sql_error(body: str) -> bool:
    low = body.lower()
    return any(sig in low for sig in _SQL_ERRORS)


def _traversal_hit(body: str) -> bool:
    low = body.lower()
    return (
        ("root:x:0:0" in body) or ("[extensions]" in low) or ("16-bit app support" in low)
        or ("root:" in low and ":0:0:" in low)
        or ("netops handover notes" in low)
        or ("x-forwarded-for header" in low)
        or ("def " in body and "import " in body and "print(" in body)
    )


def _dir_listing(body: str) -> bool:
    low = body.lower()
    return (
        "index of /" in low or "directory listing for" in low
        or "tiny file manager" in low
        or ("parent directory" in low and "<table" in low)
    )


# -- extended web-check configuration ----------------------------------------
_SEC_HEADERS = {  # header key (lowercase) -> canonical label
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}
_CORS_EVIL = "https://nighttrace-cors-probe.example"      # attacker origin, non-routable
_RISKY_METHODS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"}
_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnurl", "dest",
                    "destination", "continue", "redirect_uri", "r", "u"]
_REDIRECT_EVIL = "https://nighttrace-oob.example/x"       # external target, non-routable
_BACKUP_PATHS = [
    "/.env", "/.env.bak", "/.env.local", "/.env.save", "/config.php.bak",
    "/wp-config.php.bak", "/web.config.bak", "/settings.py.bak",
    "/backup.sql", "/database.sql", "/db.sql", "/dump.sql",
    "/backup.zip", "/backup.tar.gz", "/site.tar.gz", "/www.zip",
    "/.htpasswd", "/.svn/entries", "/.DS_Store", "/id_rsa",
    "/.bash_history", "/index.php~", "/config.json.bak",
]
_FILE_SIGS = ("-----begin", "<?php", "[core]", "sqlite format 3",
              "db_password", "aws_secret", "private key", "password=")


def _looks_like_baseline(resp: dict, baseline: dict | None) -> bool:
    """True when `resp` is indistinguishable from the server's answer for a
    random, nonexistent path — i.e. a catch-all page (an SPA that 200s every
    route, or a WAF that 403s everything), not a real resource."""
    if not baseline or resp.get("status") != baseline.get("status"):
        return False
    a, b = resp.get("body") or "", baseline.get("body") or ""
    if a == b:
        return True
    ca = (resp.get("headers") or {}).get("content-type", "")
    cb = (baseline.get("headers") or {}).get("content-type", "")
    return ca == cb and abs(len(a) - len(b)) <= max(32, len(b) // 50)


class CheckEngine:
    def __init__(self, checks: list[dict], flag_pattern: str = r"FLAG\{.*?\}"):
        self.checks = checks
        self.flag_re = re.compile(flag_pattern)

    # -- selection -----------------------------------------------------------
    def applicable(self, surface: str, context: dict) -> list[dict]:
        out = []
        for c in self.checks:
            if c.get("surface") != surface:
                continue
            when = c.get("when") or {}
            if all(context.get(k) == v for k, v in when.items()):
                out.append(c)
        return out

    def _flag(self, body: str) -> str | None:
        m = self.flag_re.search(body or "")
        return m.group(0) if m else None

    # -- probe dispatch ------------------------------------------------------
    def probe(self, check: dict, target: dict, guard: ScopeGuard) -> list[ProbeOutcome]:
        ptype = (check.get("probe") or {}).get("type", "")
        handler = getattr(self, f"_probe_{ptype}", None)
        if handler is None:
            return []
        try:
            return handler(check, target, guard) or []
        except Exception:
            return []

    def verify(self, check: dict, finding: dict, target: dict, guard: ScopeGuard) -> VerifyOutcome:
        vtype = (check.get("verify") or {}).get("type", "")
        handler = getattr(self, f"_verify_{vtype}", None)
        if handler is None:
            return VerifyOutcome(False, ["no verify handler for this check"])
        try:
            return handler(check, finding, target, guard)
        except Exception as exc:
            return VerifyOutcome(False, [f"verification error: {exc.__class__.__name__}"])

    # -- web probes ----------------------------------------------------------
    def _probe_http_login(self, check, target, guard) -> list[ProbeOutcome]:
        p, v = check["probe"], check.get("verify", {})
        base = target["base_url"]
        uf, pf = p.get("username_field", "username"), p.get("password_field", "password")
        for path in p.get("paths", ["/login"]):
            for cred in p.get("credentials", []):
                u, pw = cred[0], cred[1]
                resp = tools.http_request(
                    guard, base + path, method="POST",
                    data=urlencode({uf: u, pf: pw}),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                if not resp:
                    continue
                cookie = resp["headers"].get("set-cookie", "")
                body = resp.get("body", "")
                fail = p.get("fail_contains")
                ok = (resp["status"] in (301, 302, 303) and cookie) or \
                     (resp["status"] == 200 and p.get("success_contains") and p["success_contains"] in body)
                if fail and fail in body:
                    ok = False
                if ok:
                    return [ProbeOutcome(
                        type="default_credentials",
                        title=f"Default credentials on {path}",
                        severity="high",
                        description=f"The login at {path} accepts the default/guessable account {u}:{pw}.",
                        fix="Remove default accounts; enforce a strong password policy and account lockout.",
                        evidence=f"POST {path} as {u}:{pw} -> HTTP {resp['status']} with a session cookie",
                        data={"path": path, "username": u, "password": pw,
                              "cookie": cookie.split(";")[0] if cookie else "",
                              "authed_path": v.get("authed_path", "/admin")})]
        return []

    def _verify_http_login(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        base = target["base_url"]
        authed = d.get("authed_path", "/admin")
        cookie = d.get("cookie", "")
        resp = tools.http_request(guard, base + authed, headers={"Cookie": cookie} if cookie else None)
        if resp and resp["status"] == 200:
            ev = [f"GET {authed} with the captured session -> HTTP 200 "
                  f"({len(resp['body'])} bytes): authenticated access confirmed"]
            data = {}
            flag = self._flag(resp["body"])
            if flag:
                ev.append(f"Captured planted flag: {flag}")
                data["flag"] = flag
            return VerifyOutcome(True, ev, data)
        return VerifyOutcome(False, ["Captured session did not yield an authenticated page"])

    def _probe_http_git_exposure(self, check, target, guard) -> list[ProbeOutcome]:
        p = check["probe"]
        base = target["base_url"]
        path = p.get("path", "/.git/config")
        resp = tools.http_request(guard, base + path)
        if resp and resp["status"] == 200 and "[core]" in resp.get("body", ""):
            leaked = None
            m = re.search(r"cred(?:ential)?s?\s*[:=]\s*([^\s/]+)\s*[/:]\s*(\S+)", resp["body"], re.I)
            if m:
                leaked = f"{m.group(1)}:{m.group(2)}"
            return [ProbeOutcome(
                type="exposed_git",
                title="Exposed .git repository",
                severity="medium",
                description=f"{path} is world-readable, exposing source/repository configuration.",
                fix="Block access to .git over HTTP; never deploy the VCS directory to web root.",
                evidence=f"GET {path} -> HTTP 200 exposing repository config",
                data={"path": path, "leaked_cred": leaked})]
        return []

    def _verify_http_git_exposure(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        base = target["base_url"]
        resp = tools.http_request(guard, base + d.get("path", "/.git/config"))
        if resp and resp["status"] == 200 and "[core]" in resp.get("body", ""):
            ev = [f"GET {d.get('path')} -> HTTP 200, repository config is readable"]
            if d.get("leaked_cred"):
                u = d["leaked_cred"].split(":")[0]
                ev.append(f"Repository leaks credentials: {u}:•••••")
            return VerifyOutcome(True, ev)
        return VerifyOutcome(False, ["Could not re-read the exposed repository config"])

    def _candidates(self, check: dict, target: dict) -> list[tuple[str, str]]:
        """(path, param) pairs to test: those configured on the check plus any the
        crawler discovered. This is what lets a check hit an unknown app."""
        p = check.get("probe", {})
        param = p.get("param")
        out: list[tuple[str, str]] = []
        for path in p.get("paths", []) or []:
            if param:
                out.append((path, param))
        for d in target.get("params", []) or []:
            out.append((d["path"], d.get("param") or param or "q"))
        seen, res = set(), []
        for t in out:
            if t not in seen:
                seen.add(t)
                res.append(t)


        return res[:15]

    def _probe_http_header_bypass(self, check, target, guard) -> list[ProbeOutcome]:
        p = check.get("probe", {})
        base = target["base_url"]
        headers_list = p.get("headers", [
            {"X-Forwarded-For": "192.168.60.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ])
        baseline = tools.http_request(guard, base + "/")
        baseline_body = baseline.get("body", "") if baseline else ""
        baseline_status = baseline.get("status", 0) if baseline else 0
        out = []
        for hdr in headers_list:
            resp = tools.http_request(guard, base + "/", headers=hdr)
            if not resp:
                continue
            body = resp.get("body", "")
            if resp["status"] == 200 and (baseline_status != 200 or len(body) != len(baseline_body)):
                hdr_str = ", ".join(f"{k}: {v}" for k, v in hdr.items())
                title_match = re.search(r"<title>([^<]+)</title>", body, re.I)
                doc_title = title_match.group(1).strip() if title_match else "Restricted Content"
                out.append(ProbeOutcome(
                    type="access_control_bypass",
                    title=f"Access control bypass via {hdr_str}",
                    severity="high",
                    description=f"Supplying the header '{hdr_str}' bypasses edge proxy access controls, exposing '{doc_title}'.",
                    fix="Do not trust client-supplied X-Forwarded-For headers from untrusted networks; configure reverse proxy to strip or overwrite forwarding headers.",
                    evidence=f"GET / with {hdr_str} -> HTTP 200 revealing '{doc_title}' (baseline was HTTP {baseline_status})",
                    data={"headers": hdr, "doc_title": doc_title, "path": "/"}))
                break
        return out

    def _verify_http_header_bypass(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        base = target["base_url"]
        hdr = d.get("headers") or {"X-Forwarded-For": "192.168.60.1"}
        resp = tools.http_request(guard, base + d.get("path", "/"), headers=hdr)
        if resp and resp["status"] == 200:
            doc_title = d.get("doc_title", "Restricted Area")
            return VerifyOutcome(True, [
                f"Re-sent {hdr} to {d.get('path', '/')} -> HTTP 200 with {len(resp.get('body', ''))} bytes "
                f"exposing '{doc_title}' — confirmed access control bypass"
            ])
        return VerifyOutcome(False, ["Header bypass could not be reproduced on re-test"])

    def _probe_http_reflected_input(self, check, target, guard) -> list[ProbeOutcome]:
        token = "nt" + secrets.token_hex(4)
        marker = f"{token}<x>"
        base = target["base_url"]
        out = []
        for path, param in self._candidates(check, target):
            resp = tools.http_request(guard, f"{base}{path}?{urlencode({param: marker})}")
            if resp and marker in resp.get("body", ""):  # raw '<x>' survived -> unescaped
                out.append(ProbeOutcome(
                    type="reflected_input",
                    title=f"Reflected unescaped input at {path} ({param})",
                    severity="medium",
                    description=f"The '{param}' parameter at {path} is reflected without output "
                                f"encoding (cross-site scripting indicator).",
                    fix="Apply context-aware output encoding to user-controlled values; add a CSP.",
                    evidence=f"GET {path}?{param}=<marker> reflected the raw marker unescaped",
                    data={"path": path, "param": param}))
            if len(out) >= 5:
                break
        return out

    def _verify_http_reflected_input(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        token = "nt" + secrets.token_hex(4)
        marker = f"{token}<x>"
        url = f"{target['base_url']}{d.get('path', '/')}?{urlencode({d.get('param', 'q'): marker})}"
        resp = tools.http_request(guard, url)
        if resp and marker in resp.get("body", ""):
            return VerifyOutcome(True, [f"A fresh unique marker '{marker}' was reflected unescaped "
                                        f"— confirmed non-destructively"])
        return VerifyOutcome(False, ["Marker was not reflected unescaped on re-test"])

    # -- SQL injection (error-based, read-only / non-destructive) -----------
    def _probe_sql_injection(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        out = []
        for path, param in self._candidates(check, target):
            resp = tools.http_request(guard, f"{base}{path}?{urlencode({param: _SQL_PROBE})}")
            if resp and _sql_error(resp.get("body", "")):
                out.append(ProbeOutcome(
                    type="sql_injection",
                    title=f"SQL injection at {path} ({param})",
                    severity="high",
                    description=f"The '{param}' parameter at {path} returns a database error when sent a "
                                f"single quote — a SQL injection indicator.",
                    fix="Use parameterised queries / prepared statements; never concatenate user input into SQL.",
                    evidence=f"GET {path}?{param}=1' returned a database error signature",
                    data={"path": path, "param": param}))
            if len(out) >= 5:
                break
        return out

    def _verify_sql_injection(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        base = target["base_url"]
        path, param = d.get("path", "/"), d.get("param", "id")
        bad = tools.http_request(guard, f"{base}{path}?{urlencode({param: _SQL_PROBE})}")
        good = tools.http_request(guard, f"{base}{path}?{urlencode({param: _SQL_SAFE})}")
        if bad and _sql_error(bad.get("body", "")) and not (good and _sql_error(good.get("body", ""))):
            return VerifyOutcome(True, [f"'{param}=1'' triggers a DB error while '{param}=1' does not "
                                        f"— confirmed read-only"])
        return VerifyOutcome(False, ["No differential database error on re-test"])

    # -- Path traversal / LFI (reads a benign known system file) ------------
    def _probe_path_traversal(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        out = []
        for path, param in self._candidates(check, target):
            for payload in _TRAVERSAL:
                resp = tools.http_request(guard, f"{base}{path}?{urlencode({param: payload})}")
                if resp and _traversal_hit(resp.get("body", "")):
                    out.append(ProbeOutcome(
                        type="path_traversal",
                        title=f"Path traversal / LFI at {path} ({param})",
                        severity="high",
                        description=f"The '{param}' parameter at {path} can read files outside the web root.",
                        fix="Canonicalise and validate paths against an allow-list; keep user input out of file APIs.",
                        evidence=f"GET {path}?{param}=<traversal> returned a known system-file signature",
                        data={"path": path, "param": param, "payload": payload}))
                    break
            if len(out) >= 5:
                break
        return out

    def _verify_path_traversal(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        url = (f"{target['base_url']}{d.get('path', '/')}?"
               f"{urlencode({d.get('param', 'file'): d.get('payload', '')})}")
        resp = tools.http_request(guard, url)
        if resp and _traversal_hit(resp.get("body", "")):
            return VerifyOutcome(True, ["Re-read a known system file through the parameter — confirmed"])
        return VerifyOutcome(False, ["System-file signature not returned on re-test"])

    # -- Directory listing ---------------------------------------------------
    def _probe_directory_listing(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        out = []
        for d in check["probe"].get("paths", ["/"]):
            resp = tools.http_request(guard, base + d)
            if resp and resp["status"] == 200 and _dir_listing(resp.get("body", "")):
                out.append(ProbeOutcome(
                    type="directory_listing",
                    title=f"Directory listing enabled at {d}",
                    severity="low",
                    description=f"{d} returns an auto-generated directory index, disclosing file names.",
                    fix="Disable automatic directory indexing on the web server.",
                    evidence=f"GET {d} -> HTTP 200 with a directory index",
                    data={"path": d}))
        return out

    def _verify_directory_listing(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        resp = tools.http_request(guard, target["base_url"] + d.get("path", "/"))
        if resp and resp["status"] == 200 and _dir_listing(resp.get("body", "")):
            return VerifyOutcome(True, [f"GET {d.get('path')} re-confirmed a directory index"])
        return VerifyOutcome(False, ["No directory index on re-test"])

    def _probe_http_paths(self, check, target, guard) -> list[ProbeOutcome]:
        p = check["probe"]
        base = target["base_url"]
        expect = set(p.get("expect_status", [200, 401, 403]))
        # How does the server answer for something that doesn't exist? A "hit"
        # that looks the same is a catch-all page, not an exposed resource.
        baseline = tools.http_request(guard, base + "/nt-" + secrets.token_hex(6))
        out = []
        for path in p.get("paths", []):
            resp = tools.http_request(guard, base + path)
            if resp and resp["status"] in expect and not _looks_like_baseline(resp, baseline):
                out.append(ProbeOutcome(
                    type="exposed_path",
                    title=f"Reachable sensitive path {path}",
                    severity=p.get("severity", "low"),
                    description=f"{path} is reachable (HTTP {resp['status']}) and may disclose information.",
                    fix="Restrict access, require authentication, or remove the endpoint if not needed.",
                    evidence=f"GET {path} -> HTTP {resp['status']}",
                    data={"path": path, "status": resp["status"]}))
        return out

    def _verify_http_status(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        p = check["probe"]
        base = target["base_url"]
        expect = set((check.get("verify") or {}).get("expect_status", p.get("expect_status", [200, 401, 403])))
        resp = tools.http_request(guard, base + d.get("path", "/"))
        if resp and resp["status"] in expect:
            return VerifyOutcome(True, [f"GET {d.get('path')} -> HTTP {resp['status']} (reachable, re-confirmed)"])
        return VerifyOutcome(False, ["Path was not reachable on re-test"])

    def _probe_http_header_disclosure(self, check, target, guard) -> list[ProbeOutcome]:
        p = check["probe"]
        base = target["base_url"]
        resp = tools.http_request(guard, base + p.get("path", "/"))
        if resp:
            server = resp["headers"].get("server", "")
            if server and re.search(r"\d", server):
                return [ProbeOutcome(
                    type="version_disclosure",
                    title="Server version disclosure",
                    severity="low",
                    description=f"The Server header reveals software and version: {server}",
                    fix="Suppress or genericise the Server header to avoid version fingerprinting.",
                    evidence=f"Server: {server}",
                    data={"server": server, "path": p.get("path", "/")})]
        return []

    def _verify_http_header_present(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        base = target["base_url"]
        resp = tools.http_request(guard, base + d.get("path", "/"))
        if resp and resp["headers"].get("server"):
            return VerifyOutcome(True, [f"Server header re-observed: {resp['headers'].get('server')}"])
        return VerifyOutcome(False, ["Server header not present on re-test"])

    # -- binary probes -------------------------------------------------------
    def _probe_binary_strings(self, check, target, guard) -> list[ProbeOutcome]:
        p = check["probe"]
        raw = tools.read_binary(guard, target["path"])
        if raw is None:
            return []
        text = "\n".join(_extract_strings(raw))
        out: list[ProbeOutcome] = []
        seen_cred = False
        for rx in p.get("credentials", []):
            m = re.search(rx, text, re.I)
            if m and not seen_cred:
                seen_cred = True
                s = m.group(0)
                out.append(ProbeOutcome(
                    type="hardcoded_credential",
                    title="Hard-coded credential in binary",
                    severity="high",
                    description="The binary embeds a plaintext credential in its string table.",
                    fix="Remove embedded secrets; load them from a secret store or environment at runtime.",
                    evidence=f"string table contains: {_mask(s)}",
                    data={"match": _mask(s), "password": _secret_value(s), "path": target["path"]}))
        funcs = sorted({name for name in p.get("unsafe_functions", [])
                        if re.search(rf"\b{re.escape(name)}\b", text)})
        for name in funcs:
            out.append(ProbeOutcome(
                type="unsafe_function",
                title=f"Unsafe C function referenced: {name}",
                severity="medium",
                description=f"The binary references {name}, a function commonly linked to memory-safety bugs.",
                fix=f"Replace {name} with a bounded-length safe equivalent and enable compiler hardening.",
                evidence=f"string table references '{name}'",
                data={"function": name, "path": target["path"]}))
        return out

    def _verify_binary_strings(self, check, finding, target, guard) -> VerifyOutcome:
        p = check["probe"]
        raw = tools.read_binary(guard, target["path"])
        if raw is None:
            return VerifyOutcome(False, ["Binary could not be read for verification"])
        text = "\n".join(_extract_strings(raw))
        d = finding.get("data") or {}
        if d.get("function"):
            present = re.search(rf"\b{re.escape(d['function'])}\b", text) is not None
            return VerifyOutcome(present, [f"Re-read binary: reference to '{d['function']}' "
                                           f"{'present' if present else 'absent'}"])
        # credential: confirm a credential pattern is still present
        for rx in p.get("credentials", []):
            if re.search(rx, text, re.I):
                return VerifyOutcome(True, [f"Re-read binary: embedded credential still present ({d.get('match', '')})"])
        return VerifyOutcome(False, ["Credential pattern not found on re-read"])

    def _probe_binary_checksec(self, check, target, guard) -> list[ProbeOutcome]:
        raw = tools.read_binary(guard, target["path"])
        if raw is None or len(raw) < 20 or raw[:4] != b"\x7fELF":
            return []
        endian = "little" if raw[5] == 1 else "big"
        e_type = int.from_bytes(raw[16:18], endian)
        out = []
        if e_type == 2:  # ET_EXEC → not a PIE
            out.append(ProbeOutcome(
                type="missing_mitigation", title="No PIE (position-independent executable)",
                severity="medium",
                description="The executable is not position-independent, weakening ASLR.",
                fix="Compile with -fPIE -pie to enable full address-space layout randomisation.",
                evidence="ELF e_type = ET_EXEC (2): PIE disabled", data={"check": "pie", "path": target["path"]}))
        if b"__stack_chk_fail" not in raw:
            out.append(ProbeOutcome(
                type="missing_mitigation", title="No stack canary",
                severity="medium",
                description="No stack-protector symbol is present; stack buffer overflows are easier to exploit.",
                fix="Compile with -fstack-protector-strong.",
                evidence="symbol __stack_chk_fail not found", data={"check": "canary", "path": target["path"]}))
        return out

    def _verify_binary_checksec(self, check, finding, target, guard) -> VerifyOutcome:
        raw = tools.read_binary(guard, target["path"])
        if raw is None or raw[:4] != b"\x7fELF":
            return VerifyOutcome(False, ["Binary could not be re-parsed"])
        d = finding.get("data") or {}
        endian = "little" if raw[5] == 1 else "big"
        if d.get("check") == "pie":
            ok = int.from_bytes(raw[16:18], endian) == 2
            return VerifyOutcome(ok, ["Re-parsed ELF header: PIE disabled (ET_EXEC)" if ok else "PIE appears enabled"])
        if d.get("check") == "canary":
            ok = b"__stack_chk_fail" not in raw
            return VerifyOutcome(ok, ["Re-parsed binary: no stack-protector symbol" if ok else "canary symbol present"])
        return VerifyOutcome(False, ["Unknown checksec sub-check"])

    # -- network probes ------------------------------------------------------
    def _probe_net_version(self, check, target, guard) -> list[ProbeOutcome]:
        """Identify the product/version behind an open port and correlate it with
        the offline CVE database. Version-based, non-destructive."""
        host, port, svc = target["host"], target["port"], target.get("service")
        product, version = target.get("product"), target.get("version")
        if not (product and version):
            b = target.get("banner") or ""
            # Actively grab the banner (longer window than the scan's) for any
            # non-HTTP service when we don't already have a version. HTTP carries
            # its version in the Server header, passed as http_server instead.
            if not b and svc not in ("http", "https"):
                b = netservices.banner(guard, host, port)
            product, version = netservices.identify(svc, b, target.get("http_server"))
        if not (product and version):
            return []
        out = []
        for hit in vulndb.lookup(product, version):
            out.append(ProbeOutcome(
                type="vulnerable_version",
                title=f"{product} {version} affected by {hit.cve}",
                severity=hit.severity,
                description=f"{hit.summary} Identified from the service banner on {host}:{port} "
                            f"(version-based detection, non-destructive).",
                fix=hit.fix,
                evidence=f"{host}:{port} identifies as {product} {version}; {hit.cve} affects this version",
                data={"host": host, "port": port, "service": svc, "product": product,
                      "version": version, "cve": hit.cve}))
        return out

    def _verify_net_version(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        host = (target or {}).get("host") or d.get("host")
        port = (target or {}).get("port") or d.get("port")
        svc = d.get("service")
        if svc in ("http", "https"):
            resp = tools.http_request(guard, tools.base_url_for(host, port))
            server = resp.get("headers", {}).get("server") if resp else None
            product, version = netservices.identify(svc, "", server)
        else:
            product, version = netservices.identify(svc, netservices.banner(guard, host, port), None)
        if product == d.get("product") and version == d.get("version"):
            return VerifyOutcome(True, [f"Re-read {host}:{port}: still {product} {version} "
                                        f"(affected by {d.get('cve')})"])
        return VerifyOutcome(False, [f"Version banner changed or not re-observed on {host}:{port}"])

    def _probe_net_unauth(self, check, target, guard) -> list[ProbeOutcome]:
        """Detect services left open without authentication (read-only probes)."""
        host, port, svc = target["host"], target["port"], target.get("service")
        services = (check.get("probe") or {}).get("services")
        if services:  # generic "database exposed to the network" check
            if svc in services and netservices.tcp_reachable(guard, host, port):
                return [ProbeOutcome(
                    type="exposed_service",
                    title=f"{svc} database reachable over the network",
                    severity="medium",
                    description=f"A {svc} database on {host}:{port} accepts connections from the network; "
                                f"databases should not be exposed to untrusted networks.",
                    fix="Bind the database to localhost / a private interface and firewall the port.",
                    evidence=f"{host}:{port} accepts {svc} connections",
                    data={"host": host, "port": port, "service": svc})]
            return []
        if svc == "redis":
            r = netservices.redis_unauth(guard, host, port)
            if r.get("open"):
                return [ProbeOutcome(
                    type="unauth_service", title="Unauthenticated Redis exposed", severity="high",
                    description=f"Redis on {host}:{port} answers commands without authentication; keys can be "
                                f"read/overwritten and code execution is often possible.",
                    fix="Require AUTH, enable protected-mode, and bind Redis to localhost / a trusted interface.",
                    evidence=f"INFO on {host}:{port} returned server data without AUTH"
                             + (f" (redis_version {r['version']})" if r.get("version") else ""),
                    data={"host": host, "port": port, "service": "redis"})]
        elif svc == "memcached":
            r = netservices.memcached_unauth(guard, host, port)
            if r.get("open"):
                return [ProbeOutcome(
                    type="unauth_service", title="Unauthenticated memcached exposed", severity="medium",
                    description=f"memcached on {host}:{port} returns stats without authentication; cached data "
                                f"is readable and the service is abusable for DDoS amplification.",
                    fix="Enable SASL, disable UDP, and bind memcached to localhost / a trusted interface.",
                    evidence=f"'stats' on {host}:{port} returned data without auth",
                    data={"host": host, "port": port, "service": "memcached"})]
        elif svc == "elasticsearch":
            r = netservices.elasticsearch_open(guard, host, port)
            if r.get("open"):
                return [ProbeOutcome(
                    type="unauth_service", title="Unauthenticated Elasticsearch exposed", severity="high",
                    description=f"Elasticsearch on {host}:{port} serves cluster data without authentication; "
                                f"all indexed data is readable.",
                    fix="Enable the security realm (authentication + TLS) and restrict network access.",
                    evidence=f"GET / on {host}:{port} returned cluster info without auth"
                             + (f" (version {r['version']})" if r.get("version") else ""),
                    data={"host": host, "port": port, "service": "elasticsearch"})]
        elif svc == "ftp":
            if netservices.ftp_anonymous(guard, host, port).get("open"):
                return [ProbeOutcome(
                    type="anonymous_access", title="Anonymous FTP enabled", severity="medium",
                    description=f"The FTP server on {host}:{port} accepts the anonymous account.",
                    fix="Disable anonymous access unless a public read-only area is explicitly intended.",
                    evidence=f"USER anonymous on {host}:{port} returned 230 (login accepted)",
                    data={"host": host, "port": port, "service": "ftp"})]
        elif svc == "telnet":
            if netservices.tcp_reachable(guard, host, port):
                return [ProbeOutcome(
                    type="insecure_protocol", title="Telnet service exposed (cleartext)", severity="medium",
                    description=f"Telnet on {host}:{port} transmits credentials and sessions in cleartext.",
                    fix="Disable Telnet and use SSH instead.",
                    evidence=f"{host}:{port} accepts Telnet connections",
                    data={"host": host, "port": port, "service": "telnet"})]
        elif svc == "smb":
            if port != 445:  # 139 needs a NetBIOS session first; 445 is direct-hosted SMB
                return []
            info = netservices.smb_info(guard, host, port)
            out = []
            if info.get("smbv1"):
                out.append(ProbeOutcome(
                    type="legacy_protocol", title="SMBv1 enabled", severity="high",
                    description=f"The SMB server on {host}:{port} still accepts SMBv1, the deprecated protocol "
                                f"behind wormable flaws such as EternalBlue (MS17-010).",
                    fix="Disable SMBv1 and allow SMB 2/3 only.",
                    evidence=f"SMB1 NEGOTIATE ('NT LM 0.12') to {host}:{port} was accepted",
                    data={"host": host, "port": port, "service": "smb", "sub": "smbv1"}))
            if info.get("signing_required") is False:
                out.append(ProbeOutcome(
                    type="smb_signing", title="SMB signing not required", severity="medium",
                    description=f"The SMB server on {host}:{port} does not require message signing, which "
                                f"enables NTLM relay and man-in-the-middle attacks.",
                    fix="Require SMB signing (RequireSecuritySignature = 1) on servers and clients.",
                    evidence="SMB2 NEGOTIATE response SecurityMode does not set SIGNING_REQUIRED",
                    data={"host": host, "port": port, "service": "smb", "sub": "smb-signing"}))
            return out
        return []

    def _probe_net_snmp(self, check, target, guard) -> list[ProbeOutcome]:
        """SNMP is UDP, so recon runs this once per host rather than per TCP port."""
        host, port = target["host"], target.get("port") or 161
        r = netservices.snmp_default_community(guard, host, port)
        if not r.get("open"):
            return []
        c = r["community"]
        rw = c == "private"
        return [ProbeOutcome(
            type="unauth_service", title=f"SNMP accepts default community '{c}'",
            severity="high" if rw else "medium",
            description=f"The SNMP agent on {host}:{port}/udp answers queries with the default community "
                        f"'{c}', disclosing device and network configuration"
                        + (" ('private' is commonly configured with write access)." if rw else "."),
            fix="Remove default communities; use SNMPv3 with authentication and restrict SNMP by ACL.",
            evidence=f"SNMP GET sysDescr.0 with community '{c}' was answered"
                     + (f": {r['sysdescr'][:80]}" if r.get("sysdescr") else ""),
            data={"host": host, "port": port, "service": "snmp", "community": c})]

    def _verify_net_unauth(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        host = (target or {}).get("host") or d.get("host")
        port = (target or {}).get("port") or d.get("port")
        svc = d.get("service")
        if svc == "redis":
            ok = netservices.redis_unauth(guard, host, port).get("open")
        elif svc == "memcached":
            ok = netservices.memcached_unauth(guard, host, port).get("open")
        elif svc == "elasticsearch":
            ok = netservices.elasticsearch_open(guard, host, port).get("open")
        elif svc == "ftp":
            ok = netservices.ftp_anonymous(guard, host, port).get("open")
        elif svc == "snmp":
            ok = netservices.snmp_default_community(
                guard, host, port, communities=(d.get("community") or "public",)).get("open")
        elif svc == "smb":
            info = netservices.smb_info(guard, host, port)
            ok = info.get("smbv1") if d.get("sub") == "smbv1" else info.get("signing_required") is False
        else:  # telnet / exposed database: reachability is the condition
            ok = netservices.tcp_reachable(guard, host, port)
        what = d.get("sub") or f"{svc} exposure"
        if ok:
            return VerifyOutcome(True, [f"Re-checked {host}:{port}: {what} re-confirmed"])
        return VerifyOutcome(False, [f"{what} not reproduced on re-check of {host}:{port}"])

    def _probe_tls_audit(self, check, target, guard) -> list[ProbeOutcome]:
        host, port = target["host"], target["port"]
        a = netservices.tls_audit(guard, host, port)
        if not a.get("reachable"):
            return []
        out = []
        cs = a.get("cert_status")
        _CERT = {
            "self-signed": ("Self-signed TLS certificate", "low",
                            "presents a self-signed certificate; clients cannot verify the server's identity"),
            "expired": ("Expired TLS certificate", "medium",
                        "presents an expired certificate"),
            "hostname-mismatch": ("TLS certificate hostname mismatch", "low",
                                  "presents a certificate that does not match the host"),
            "untrusted": ("Untrusted TLS certificate", "low",
                          "presents a certificate not signed by a trusted CA"),
        }
        if cs in _CERT:
            title, sev, phrase = _CERT[cs]
            out.append(ProbeOutcome(
                type="tls_certificate", title=title, severity=sev,
                description=f"{host}:{port} {phrase}.",
                fix="Install a valid certificate signed by a trusted CA whose SAN matches the hostname.",
                evidence=f"Verifying TLS handshake to {host}:{port}: {cs}",
                data={"host": host, "port": port, "sub": cs}))
        if a.get("weak_protocol"):
            out.append(ProbeOutcome(
                type="tls_protocol", title=f"Obsolete TLS protocol {a.get('tls_version')}", severity="medium",
                description=f"{host}:{port} negotiated {a.get('tls_version')}, an obsolete protocol with known weaknesses.",
                fix="Disable SSLv3/TLS1.0/TLS1.1 and require TLS 1.2 or newer.",
                evidence=f"TLS handshake negotiated {a.get('tls_version')}",
                data={"host": host, "port": port, "sub": "weak_protocol"}))
        return out

    def _verify_tls_audit(self, check, finding, target, guard) -> VerifyOutcome:
        d = finding.get("data") or {}
        host = (target or {}).get("host") or d.get("host")
        port = (target or {}).get("port") or d.get("port")
        sub = d.get("sub")
        a = netservices.tls_audit(guard, host, port)
        if not a.get("reachable"):
            return VerifyOutcome(False, ["TLS endpoint not reachable on re-check"])
        ok = a.get("weak_protocol") if sub == "weak_protocol" else (a.get("cert_status") == sub)
        if ok:
            return VerifyOutcome(True, [f"Re-audited {host}:{port}: {sub} re-confirmed"])
        return VerifyOutcome(False, [f"{sub} not reproduced on re-audit of {host}:{port}"])

    # -- extended web probes -------------------------------------------------
    def _probe_http_security_headers(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        resp = tools.http_request(guard, base + "/")
        if not resp:
            return []
        h = resp.get("headers", {})
        missing = [label for key, label in _SEC_HEADERS.items() if key not in h]
        if base.startswith("https") and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        if not missing:
            return []
        return [ProbeOutcome(
            type="missing_security_headers", title="Missing HTTP security headers", severity="low",
            description="The application does not set recommended security response headers: "
                        + ", ".join(missing) + ".",
            fix="Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and HSTS (over TLS).",
            evidence=f"GET / response is missing: {', '.join(missing)}",
            data={"base_url": base, "missing": missing})]

    def _verify_http_security_headers(self, check, finding, target, guard) -> VerifyOutcome:
        base = (target or {}).get("base_url") or (finding.get("data") or {}).get("base_url")
        d = finding.get("data") or {}
        resp = tools.http_request(guard, base + "/")
        if not resp:
            return VerifyOutcome(False, ["Could not re-fetch to re-check headers"])
        h = resp.get("headers", {})
        still = [label for label in d.get("missing", []) if label.lower() not in h]
        if still:
            return VerifyOutcome(True, [f"Re-checked GET /: still missing {', '.join(still)}"])
        return VerifyOutcome(False, ["Security headers are present on re-check"])

    def _probe_http_insecure_cookies(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        out, seen = [], set()
        for path in ("/", "/login"):
            resp = tools.http_request(guard, base + path)
            sc = resp.get("headers", {}).get("set-cookie", "") if resp else ""
            if not sc:
                continue
            name = sc.split("=", 1)[0].strip()
            low = sc.lower()
            issues = [a for a, tok in (("HttpOnly", "httponly"), ("SameSite", "samesite"))
                      if tok not in low]
            if base.startswith("https") and "secure" not in low:
                issues.append("Secure")
            if issues and name not in seen:
                seen.add(name)
                out.append(ProbeOutcome(
                    type="insecure_cookie", title=f"Cookie '{name}' set without {', '.join(issues)}",
                    severity="low",
                    description=f"The cookie '{name}' set at {path} is missing the {', '.join(issues)} "
                                f"attribute(s), weakening session protection.",
                    fix="Set HttpOnly and SameSite on session cookies (and Secure over TLS).",
                    evidence=f"Set-Cookie at {path} lacks: {', '.join(issues)}",
                    data={"base_url": base, "path": path, "cookie": name, "issues": issues}))
        return out

    def _verify_http_insecure_cookies(self, check, finding, target, guard) -> VerifyOutcome:
        base = (target or {}).get("base_url") or (finding.get("data") or {}).get("base_url")
        d = finding.get("data") or {}
        resp = tools.http_request(guard, base + d.get("path", "/"))
        sc = resp.get("headers", {}).get("set-cookie", "") if resp else ""
        still = [a for a in d.get("issues", []) if a.lower() not in sc.lower()]
        if sc and still:
            return VerifyOutcome(True, [f"Re-checked {d.get('path')}: cookie still lacks {', '.join(still)}"])
        return VerifyOutcome(False, ["Cookie attributes present or no cookie on re-check"])

    def _probe_http_cors(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        resp = tools.http_request(guard, base + "/", headers={"Origin": _CORS_EVIL})
        if not resp:
            return []
        h = resp.get("headers", {})
        acao = h.get("access-control-allow-origin", "")
        creds = h.get("access-control-allow-credentials", "").lower() == "true"
        if acao != _CORS_EVIL:
            return []
        return [ProbeOutcome(
            type="cors_misconfig",
            title="CORS reflects arbitrary Origin" + (" with credentials" if creds else ""),
            severity="high" if creds else "medium",
            description="The server reflects an attacker-supplied Origin in Access-Control-Allow-Origin"
                        + (", together with Access-Control-Allow-Credentials: true — authenticated data "
                           "can be read cross-origin." if creds else "."),
            fix="Validate Origin against an allow-list; never reflect arbitrary origins with credentials.",
            evidence=f"Origin: {_CORS_EVIL} -> Access-Control-Allow-Origin: {acao}"
                     + ("; Access-Control-Allow-Credentials: true" if creds else ""),
            data={"base_url": base, "credentials": creds})]

    def _verify_http_cors(self, check, finding, target, guard) -> VerifyOutcome:
        base = (target or {}).get("base_url") or (finding.get("data") or {}).get("base_url")
        resp = tools.http_request(guard, base + "/", headers={"Origin": _CORS_EVIL})
        if resp and resp.get("headers", {}).get("access-control-allow-origin") == _CORS_EVIL:
            return VerifyOutcome(True, [f"Re-sent Origin {_CORS_EVIL}; still reflected in ACAO"])
        return VerifyOutcome(False, ["Origin not reflected on re-check"])

    def _probe_http_methods(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        resp = tools.http_request(guard, base + "/", method="OPTIONS")
        allow = resp.get("headers", {}).get("allow", "") if resp else ""
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & _RISKY_METHODS)
        trace_on = False
        if "TRACE" in methods or not methods:  # actively confirm XST non-destructively
            tr = tools.http_request(guard, base + "/", method="TRACE")
            if tr and tr.get("status") == 200 and "TRACE" in (tr.get("body", "")[:200].upper()):
                trace_on = True
                if "TRACE" not in risky:
                    risky.append("TRACE")
        if not risky:
            return []
        sev = "medium" if {"TRACE", "PUT", "DELETE", "CONNECT"} & set(risky) else "low"
        return [ProbeOutcome(
            type="dangerous_http_methods", title=f"Dangerous HTTP methods enabled: {', '.join(risky)}",
            severity=sev,
            description=f"The server allows {', '.join(risky)}."
                        + (" TRACE enables Cross-Site Tracing (XST)." if "TRACE" in risky else ""),
            fix="Disable TRACE/TRACK and any write methods (PUT/DELETE) that are not required.",
            evidence=(f"OPTIONS / Allow: {allow}" if allow else "")
                     + (" ; TRACE echoed the request (XST)" if trace_on else ""),
            data={"base_url": base, "methods": risky, "trace": trace_on})]

    def _verify_http_methods(self, check, finding, target, guard) -> VerifyOutcome:
        base = (target or {}).get("base_url") or (finding.get("data") or {}).get("base_url")
        d = finding.get("data") or {}
        if d.get("trace"):
            tr = tools.http_request(guard, base + "/", method="TRACE")
            if tr and tr.get("status") == 200 and "TRACE" in (tr.get("body", "")[:200].upper()):
                return VerifyOutcome(True, ["Re-sent TRACE; server echoed the request (XST confirmed)"])
        resp = tools.http_request(guard, base + "/", method="OPTIONS")
        allow = resp.get("headers", {}).get("allow", "") if resp else ""
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        still = sorted(set(d.get("methods", [])) & methods)
        if still:
            return VerifyOutcome(True, [f"Re-checked OPTIONS: still allows {', '.join(still)}"])
        return VerifyOutcome(False, ["Risky methods not confirmed on re-check"])

    def _probe_http_open_redirect(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        paths = ["/"] + [d["path"] for d in (target.get("params") or [])]
        seen_paths, out, tested = set(), [], 0
        for path in paths:
            if path in seen_paths:
                continue
            seen_paths.add(path)
            for param in _REDIRECT_PARAMS:
                if tested >= 40:
                    break
                tested += 1
                resp = tools.http_request(guard, f"{base}{path}?{urlencode({param: _REDIRECT_EVIL})}")
                if not resp:
                    continue
                loc = (resp.get("headers", {}) or {}).get("location", "")
                if resp.get("status") in (301, 302, 303, 307, 308) and \
                        (loc.startswith(_REDIRECT_EVIL) or loc.startswith("//nighttrace-oob")):
                    out.append(ProbeOutcome(
                        type="open_redirect", title=f"Open redirect at {path} ({param})", severity="medium",
                        description=f"The '{param}' parameter at {path} redirects to an attacker-controlled URL.",
                        fix="Allow-list redirect targets; never place user-controlled values in Location.",
                        evidence=f"GET {path}?{param}=<external> -> {resp.get('status')} Location: {loc}",
                        data={"base_url": base, "path": path, "param": param}))
                    break
            if len(out) >= 3:
                break
        return out

    def _verify_http_open_redirect(self, check, finding, target, guard) -> VerifyOutcome:
        base = (target or {}).get("base_url") or (finding.get("data") or {}).get("base_url")
        d = finding.get("data") or {}
        resp = tools.http_request(
            guard, f"{base}{d.get('path', '/')}?{urlencode({d.get('param', 'next'): _REDIRECT_EVIL})}")
        loc = (resp.get("headers", {}) or {}).get("location", "") if resp else ""
        if resp and resp.get("status") in (301, 302, 303, 307, 308) and loc.startswith(_REDIRECT_EVIL):
            return VerifyOutcome(True, [f"Re-tested: Location still redirects externally ({loc[:60]})"])
        return VerifyOutcome(False, ["External redirect not reproduced on re-check"])

    def _probe_http_backup_files(self, check, target, guard) -> list[ProbeOutcome]:
        base = target["base_url"]
        # Baseline: if a random path returns 200, the site is a catch-all, so only
        # non-HTML responses or ones carrying a secret signature are trustworthy.
        rnd = tools.http_request(guard, base + "/nt-" + secrets.token_hex(6))
        catchall = bool(rnd and rnd.get("status") == 200)
        out = []
        for path in _BACKUP_PATHS:
            resp = tools.http_request(guard, base + path)
            if not resp or resp.get("status") != 200:
                continue
            body = resp.get("body", "") or ""
            ctype = (resp.get("headers", {}) or {}).get("content-type", "").lower()
            is_html = "text/html" in ctype or "<html" in body[:200].lower()
            has_sig = any(s in body.lower() for s in _FILE_SIGS)
            if has_sig or (not is_html and not catchall):
                out.append(ProbeOutcome(
                    type="exposed_backup_file", title=f"Exposed sensitive file {path}", severity="medium",
                    description=f"{path} is downloadable and may expose source, configuration, or secrets.",
                    fix="Remove backup/secret files from the web root and block access to dotfiles.",
                    evidence=f"GET {path} -> 200 ({len(body)} bytes)" + (" with a secret signature" if has_sig else ""),
                    data={"base_url": base, "path": path, "has_sig": has_sig}))
            if len(out) >= 8:
                break
        return out

    def _verify_http_backup_files(self, check, finding, target, guard) -> VerifyOutcome:
        base = (target or {}).get("base_url") or (finding.get("data") or {}).get("base_url")
        d = finding.get("data") or {}
        resp = tools.http_request(guard, base + d.get("path", "/"))
        if resp and resp.get("status") == 200:
            body = resp.get("body", "") or ""
            if d.get("has_sig"):
                ok = any(s in body.lower() for s in _FILE_SIGS)
            else:
                ok = "text/html" not in (resp.get("headers", {}) or {}).get("content-type", "").lower()
            if ok:
                return VerifyOutcome(True, [f"Re-fetched {d.get('path')} -> 200, content re-confirmed"])
        return VerifyOutcome(False, ["File not retrievable on re-check"])
