"""Offline known-vulnerability database (version -> CVE correlation).

A small, *curated* map from a service product + version to well-known CVEs. It is
deliberately conservative: an entry only matches when the product is clearly
identified and the version falls in a precisely known-vulnerable range, so a
"vulnerable version" finding is accurate rather than noisy. This is version-based
inference (the same thing nmap's vulners / a baseline scanner does) — we report
it honestly as such, and the finding is still run through the verify step (the
banner is re-read) before it reaches the report.

It is fully offline: no NVD API, no key, no internet — so it works on the
isolated network a hackathon assigns. Add entries here; no engine code changes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class VulnHit:
    cve: str
    severity: str          # info | low | medium | high | critical
    summary: str
    fix: str


def _nums(version: str) -> tuple[int, ...]:
    """Ordered components of a version string: '2.4.49' -> (2,4,49),
    '7.6p1' -> (7,6,1). An OpenSSL-style trailing letter release is its own
    component ('1.0.1f' -> (1,0,1,6), '1.0.1g' -> (1,0,1,7)) so a fixed letter
    release is never mistaken for the vulnerable one before it."""
    parts = [int(x) for x in re.findall(r"\d+", version)[:4]]
    m = re.search(r"\d([a-z])(?![a-z0-9])", version.lower())
    if m:
        parts.append(ord(m.group(1)) - 96)
    return tuple(parts)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple, tuple]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _le(a: str, b: str) -> bool:
    ta, tb = _pad(_nums(a), _nums(b))
    return ta <= tb


def _lt(a: str, b: str) -> bool:
    ta, tb = _pad(_nums(a), _nums(b))
    return ta < tb


def _matches(spec: tuple, version: str) -> bool:
    op = spec[0]
    if op == "<":
        return _lt(version, spec[1])
    if op == "<=":
        return _le(version, spec[1])
    if op == "==":
        return _nums(version) == _nums(spec[1])
    if op == "in":
        return any(_nums(version) == _nums(v) for v in spec[1])
    if op == "range":  # inclusive low..high
        low, high = spec[1]
        return _le(low, version) and _le(version, high)
    return False


# product (lowercase) -> list of (version-spec, VulnHit). Only high-signal,
# widely-known issues that are reliably version-identifiable from a banner.
_DB: dict[str, list[tuple[tuple, VulnHit]]] = {
    "openssh": [
        (("<", "7.7"), VulnHit(
            "CVE-2018-15473", "medium",
            "OpenSSH < 7.7 allows remote enumeration of valid usernames.",
            "Upgrade OpenSSH to 7.7 or later.")),
        (("<", "7.4"), VulnHit(
            "CVE-2016-10009", "high",
            "OpenSSH < 7.4 is vulnerable to agent-forwarding code loading (and related issues).",
            "Upgrade OpenSSH to 7.4 or later.")),
    ],
    "vsftpd": [
        (("==", "2.3.4"), VulnHit(
            "CVE-2011-2523", "critical",
            "vsftpd 2.3.4 ships a backdoor that opens a root shell on TCP/6200.",
            "Replace with a clean vsftpd build (>= 3.0.x) from a trusted source.")),
    ],
    "proftpd": [
        (("==", "1.3.5"), VulnHit(
            "CVE-2015-3306", "critical",
            "ProFTPD 1.3.5 mod_copy allows unauthenticated remote command execution.",
            "Upgrade ProFTPD to 1.3.5a/1.3.6 or disable mod_copy.")),
    ],
    "apache": [
        (("in", ["2.4.49"]), VulnHit(
            "CVE-2021-41773", "critical",
            "Apache httpd 2.4.49 path traversal allowing file disclosure and RCE.",
            "Upgrade Apache httpd to 2.4.51 or later.")),
        (("in", ["2.4.50"]), VulnHit(
            "CVE-2021-42013", "critical",
            "Apache httpd 2.4.50 path traversal / RCE (incomplete fix for CVE-2021-41773).",
            "Upgrade Apache httpd to 2.4.51 or later.")),
    ],
    "nginx": [
        (("range", ("0.5.6", "1.13.2")), VulnHit(
            "CVE-2017-7529", "medium",
            "nginx 0.5.6-1.13.2 integer overflow in the range filter (information disclosure).",
            "Upgrade nginx to 1.13.3 or later.")),
        (("range", ("0.6.18", "1.20.0")), VulnHit(
            "CVE-2021-23017", "medium",
            "nginx 0.6.18-1.20.0 resolver off-by-one memory overwrite; exploitable when the "
            "'resolver' directive is configured.",
            "Upgrade nginx to 1.20.1 / 1.21.0 or later.")),
    ],
    "exim": [
        (("<", "4.92"), VulnHit(
            "CVE-2019-10149", "critical",
            "Exim < 4.92 allows remote command execution ('Return of the WIZard').",
            "Upgrade Exim to 4.92 or later.")),
        (("<", "4.94.2"), VulnHit(
            "CVE-2020-28018", "critical",
            "Exim < 4.94.2 is affected by the '21Nails' remote code execution and "
            "privilege-escalation flaws (CVE-2020-28018 and related).",
            "Upgrade Exim to 4.94.2 or later.")),
    ],
    "openssl": [
        (("range", ("1.0.1", "1.0.1f")), VulnHit(
            "CVE-2014-0160", "high",
            "OpenSSL 1.0.1-1.0.1f is vulnerable to Heartbleed memory disclosure.",
            "Upgrade OpenSSL to 1.0.1g or later and rotate exposed keys.")),
        (("range", ("3.0.0", "3.0.6")), VulnHit(
            "CVE-2022-3602", "high",
            "OpenSSL 3.0.0-3.0.6 X.509 email-address buffer overflow during certificate verification.",
            "Upgrade OpenSSL to 3.0.7 or later.")),
    ],
    "dropbear": [
        (("<", "2016.74"), VulnHit(
            "CVE-2016-7406", "high",
            "Dropbear SSH < 2016.74 has a format-string vulnerability (RCE).",
            "Upgrade Dropbear to 2016.74 or later.")),
    ],
    "microsoft-iis": [
        (("in", ["6.0"]), VulnHit(
            "CVE-2017-7269", "high",
            "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow (RCE).",
            "Retire IIS 6.0 / Windows Server 2003 or disable WebDAV.")),
    ],
    "webmin": [
        (("in", ["1.890"]), VulnHit(
            "CVE-2019-15107", "critical",
            "Webmin 1.890 contains an unauthenticated remote command execution backdoor.",
            "Upgrade Webmin to 1.930 or later.")),
    ],
}


def lookup(product: str | None, version: str | None) -> list[VulnHit]:
    """Return known CVEs affecting this product+version (possibly empty)."""
    if not product or not version:
        return []
    entries = _DB.get(product.lower())
    if not entries:
        return []
    if not re.search(r"\d", version):
        return []
    return [hit for spec, hit in entries if _matches(spec, version)]


def known_products() -> list[str]:
    return sorted(_DB)
