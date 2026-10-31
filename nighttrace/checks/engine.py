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

from nighttrace import tools
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
)
_SQL_PROBE = "1'"   # a single quote — read-only, non-destructive SQL-error probe
_SQL_SAFE = "1"


def _sql_error(body: str) -> bool:
    low = body.lower()
    return any(sig in low for sig in _SQL_ERRORS)


def _traversal_hit(body: str) -> bool:
    low = body.lower()
    return ("root:x:0:0" in body) or ("[extensions]" in low) or ("16-bit app support" in low)


def _dir_listing(body: str) -> bool:
    low = body.lower()
    return "index of /" in low or "directory listing for" in low


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
        out = []
        for path in p.get("paths", []):
            resp = tools.http_request(guard, base + path)
            if resp and resp["status"] in expect:
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
