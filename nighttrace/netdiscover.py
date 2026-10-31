"""Local network host discovery (pre-engagement reconnaissance).

Before you have a scope, you need to know what is actually on the network the
organizers put you on. This module answers one question: which hosts are live on
the local subnet right now? It is deliberately *non-destructive* and needs no
administrator rights -- it uses ordinary TCP connect probes plus the operating
system's ARP cache, never raw sockets or ICMP. Discovery is confined to a
private subnet (a /24 by default, or a CIDR you pass); it refuses to sweep
public address space.

The results are meant to be turned into a scope file (`write_scope`), which the
engine then runs against under the Scope Guard. Discovery is the one step that
happens *outside* the guard, because its whole job is to help you draw the scope
in the first place.
"""
from __future__ import annotations

import errno
import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from nighttrace import osfp

# A small TCP port list used only to decide "is this host up?" and to hint at
# what it is. A connect() that succeeds (open) or is actively refused (RST) both
# prove the host is alive; a timeout proves nothing.
LIVENESS_PORTS = [
    80, 443, 22, 445, 139, 135, 3389, 8080, 8000, 8443,
    53, 23, 21, 25, 3306, 5432, 6379, 5900, 62078,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    62078: "apple-sync",
}

# A refused or reset connection still proves the host exists. errno values
# differ across platforms (Windows uses the WSA* range), so cover both.
_REFUSED = {
    getattr(errno, "ECONNREFUSED", 111), getattr(errno, "ECONNRESET", 104),
    111, 104, 10061, 10054,
}

_MAC_RE = re.compile(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


# -- interface discovery -----------------------------------------------------
def _local_ips() -> list[str]:
    ips: list[str] = []
    # The interface that reaches the default gateway (no packet is actually sent
    # for a UDP socket; connect() just picks the route).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(info[4][0])
    except OSError:
        pass
    return list(dict.fromkeys(ips))  # de-dup, keep order


def local_networks() -> list[dict]:
    """The machine's private IPv4 networks, as /24s -- used to prefill the UI."""
    nets: list[dict] = []
    seen: set[str] = set()
    for ip in _local_ips():
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not addr.is_private or addr.is_loopback:
            continue
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        if str(net) in seen:
            continue
        seen.add(str(net))
        nets.append({"ip": ip, "cidr": str(net), "hosts": net.num_addresses - 2})
    return nets


# -- the sweep ---------------------------------------------------------------
def _probe_host(ip: str, ports: list[int], timeout: float) -> dict | None:
    open_ports: list[int] = []
    alive = False
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))
            if rc == 0:
                open_ports.append(port)
                alive = True
            elif rc in _REFUSED:
                alive = True
        except OSError:
            pass
    if not alive:
        return None
    return {"ip": ip, "open_ports": open_ports}


def arp_table() -> dict[str, str]:
    """Parse the OS ARP cache: hosts answered at layer 2 even if every TCP port
    was filtered. The TCP sweep above populates this cache as a side effect."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table: dict[str, str] = {}
    for line in out.splitlines():
        ipm, macm = _IP_RE.search(line), _MAC_RE.search(line)
        if not ipm or not macm:
            continue
        mac = macm.group(0).lower().replace("-", ":")
        if (mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
                or mac.startswith(("01:00:5e", "33:33"))):  # broadcast / multicast
            continue
        table[ipm.group(1)] = mac
    return table


def _rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def scan_network(cidr: str, ports: list[int] | None = None, timeout: float = 0.3,
                 max_workers: int = 128, resolve: bool = True) -> dict:
    """Non-destructive host discovery across one private subnet.

    Returns {"cidr", "count", "hosts": [{ip, mac, hostname, open_ports,
    services, is_self}]}. Raises ValueError for non-private or oversized ranges.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if not net.is_private:
        raise ValueError("discovery is LAN-only; refusing to scan a public network")
    if net.num_addresses > 4096:
        raise ValueError("network too large; use a /20 or smaller")
    ports = ports or LIVENESS_PORTS
    candidates = [str(h) for h in net.hosts()]

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_probe_host, ip, ports, timeout): ip for ip in candidates}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                results[r["ip"]] = r

    # Merge L2-only hosts (up, but every probed port filtered).
    arp = arp_table()
    candidate_set = set(candidates)
    for ip in arp:
        if ip not in results and ip in candidate_set:
            results[ip] = {"ip": ip, "open_ports": []}

    local = set(_local_ips())

    def _decorate(item: tuple[str, dict]) -> dict:
        ip, r = item
        r["mac"] = arp.get(ip)
        r["hostname"] = _rdns(ip) if resolve else None
        r["services"] = [{"port": p, "service": SERVICE_NAMES.get(p)}
                         for p in sorted(r["open_ports"])]
        r["is_self"] = ip in local
        # OS fingerprint from TTL + open ports + MAC (non-destructive, no admin).
        ttl = osfp.ttl_ping(ip)
        guess = osfp.fingerprint(ttl=ttl, open_ports=r["open_ports"], mac=r["mac"])
        r["os"] = guess["os"]
        r["os_family"] = guess["family"]
        r["os_confidence"] = guess["confidence"]
        r["os_reasons"] = guess["reasons"]
        r["ttl"] = ttl
        return r

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        hosts = list(ex.map(_decorate, results.items()))
    hosts.sort(key=lambda r: tuple(int(o) for o in r["ip"].split(".")))
    return {"cidr": str(net), "count": len(hosts), "hosts": hosts}


# -- scope generation --------------------------------------------------------
def build_scope(ips, cidr=None, engagement="hackathon-engagement", tier="breach",
                exclude=None, ports=None) -> dict:
    """Assemble a scope dict the engine's loader understands."""
    return {
        "engagement": engagement,
        "tier": tier,
        "scope": {
            "networks": [cidr] if cidr else [],
            "hosts": list(ips),
            "binaries": [],
            "exclude": list(exclude or []),
            "ports": list(ports or []),
        },
        "limits": {"max_runtime_minutes": 20, "rate_limit_pps": 50, "destructive": False},
        "flags": {"pattern": r"FLAG\{.*?\}"},
    }


def write_scope(path, ips, **kwargs) -> str:
    """Write a scope file (YAML) from selected hosts; returns the text written."""
    import yaml
    text = yaml.safe_dump(build_scope(ips, **kwargs), sort_keys=False)
    Path(path).write_text(text, encoding="utf-8")
    return text


if __name__ == "__main__":  # quick manual check: python -m nighttrace.netdiscover
    import json
    nets = local_networks()
    print("local networks:", json.dumps(nets, indent=2))
    if nets:
        res = scan_network(nets[0]["cidr"])
        print(f"\n{res['count']} live host(s) on {res['cidr']}:")
        for h in res["hosts"]:
            svc = ",".join(str(s["port"]) for s in h["services"]) or "-"
            os_s = f"{h['os']} ({int(h['os_confidence'] * 100)}%)" if h.get("os_family") != "unknown" else "?"
            print(f"  {h['ip']:<16} {h.get('mac') or '':<18} "
                  f"{h.get('hostname') or '':<24} {os_s:<28} ports:{svc}"
                  f"{'  (this machine)' if h['is_self'] else ''}")
