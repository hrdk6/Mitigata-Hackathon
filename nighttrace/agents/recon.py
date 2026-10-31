"""Recon agent (PTES: Intelligence Gathering).

Non-destructive TCP connect scan to find live hosts, open ports and a service
guess. Each web port it finds becomes a web task handed to the Web agent —
that hand-off is the coordination the PRD asks for.
"""
from __future__ import annotations

import ipaddress

from nighttrace import netdiscover, netservices, osfp, tools
from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, AssetRec, FindingRec, Ptes, Surface, TaskSpec
from nighttrace.reasoning import hypothesis

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "smb", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8000: "http", 8008: "http", 8080: "http", 8081: "http", 8443: "https",
    8888: "http", 9000: "http", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


def guess_service(port: int, banner: str) -> str:
    if port in SERVICES:
        return SERVICES[port]
    if banner and "HTTP" in banner.upper():
        return "http"
    return "unknown"


class ReconAgent(Agent):
    name = "recon"

    def handle(self, task: dict) -> AgentResult:
        target = task.get("target", {})
        res = AgentResult()
        hosts: list[str] = []
        if target.get("host"):
            hosts = [target["host"]]  # explicitly listed: always full-scanned
        elif target.get("network"):
            try:
                net = ipaddress.ip_network(target["network"], strict=False)
                candidates = [str(h) for h in list(net.hosts())[:256]]
            except ValueError:
                candidates = []
            # For a real range, clear dead addresses with a quick liveness sweep
            # first, so a mostly-empty subnet does not pay a full port scan per
            # host. A single-address range (/32) skips the gate.
            if len(candidates) > 1:
                hosts = tools.filter_live(self.guard, candidates)
                self.emit("liveness", Ptes.INTEL_GATHERING.value,
                          f"{target['network']}: {len(hosts)} live host(s) of "
                          f"{len(candidates)} addresses — scanning the live ones")
            else:
                hosts = candidates

        ports = self.config.scope.ports or None
        via = "nmap" if tools.has_nmap() else "connect-scan"
        arp = netdiscover.arp_table()  # best-effort MAC map for OS fingerprinting
        for host in hosts:
            open_ports = tools.discover(self.guard, host, ports,
                                        timeout=self.config.limits.connect_timeout)
            if open_ports:
                listing = ", ".join(str(d["port"]) for d in open_ports)
                self.emit("port_scan", Ptes.INTEL_GATHERING.value,
                          f"{host}: {len(open_ports)} open port(s) via {via}: {listing}")
            else:
                self.emit("port_scan", Ptes.INTEL_GATHERING.value,
                          f"{host}: no open ports found in scope")

            # Resolve the service per port first, so we can read an HTTP Server
            # header (one signal into OS fingerprinting) and reuse the result.
            resolved: list[dict] = []
            http_server = None
            for d in open_ports:
                port = d["port"]
                banner = d.get("banner") or ""
                svc = d.get("service") or guess_service(port, banner)
                if not svc or svc == "unknown":  # actively confirm HTTP on non-standard ports
                    if tools.http_request(self.guard, f"http://{host}:{port}/") is not None:
                        svc = "http"
                if http_server is None and svc in ("http", "https"):
                    resp = tools.http_request(self.guard, tools.base_url_for(host, port))
                    if resp:
                        http_server = resp.get("headers", {}).get("server")
                resolved.append({"port": port, "banner": banner, "svc": svc,
                                 "product": d.get("product")})

            # Fingerprint the OS once per host from the signals gathered above.
            ttl = tools.ping_ttl(self.guard, host)
            os_guess = osfp.fingerprint(ttl=ttl, open_ports=[r["port"] for r in resolved],
                                        http_server=http_server, mac=arp.get(host))
            host_os = {"os": os_guess["os"], "os_family": os_guess["family"],
                       "os_confidence": os_guess["confidence"],
                       "os_reasons": os_guess["reasons"], "ttl": ttl,
                       "os_tactics": osfp.suggested_tactics(os_guess["family"])}
            if os_guess["family"] != "unknown":
                self.emit("os_fingerprint", Ptes.INTEL_GATHERING.value,
                          f"{host}: OS guess {os_guess['os']} "
                          f"({int(os_guess['confidence'] * 100)}% confidence) — "
                          f"{'; '.join(os_guess['reasons'][:2])}")

            for r in resolved:
                port, banner, svc = r["port"], r["banner"], r["svc"]
                srv = http_server if svc in ("http", "https") else None
                # Fingerprint product+version from whatever we have — the raw
                # banner, the HTTP Server header, or nmap's product string — so the
                # report names the software and the CVE checks have something to match.
                ident_text = " ".join(t for t in (banner, r["product"]) if t)
                fp_prod, fp_ver = netservices.identify(svc, ident_text, srv)
                product = (f"{fp_prod} {fp_ver}" if fp_prod and fp_ver
                           else (r["product"] or (banner or None)))
                res.assets.append(AssetRec(
                    host=host, port=port, service=svc, product=product,
                    surface=Surface.NETWORK.value,
                    data={"banner": banner, "product": product, **host_os}))

                # Run the declarative network-service checks against this port:
                # version->CVE correlation, unauthenticated exposure, TLS audit.
                net_target = {"host": host, "port": port, "service": svc,
                              "banner": banner, "http_server": srv,
                              "product": fp_prod, "version": fp_ver,
                              "tls": port in tools.TLS_PORTS}
                net_ctx = {"service": svc, "port": port, "tls": port in tools.TLS_PORTS}
                self._run_net_checks(res, self.engine.applicable("network", net_ctx),
                                     net_target, host, port)

                if (svc and "http" in svc) or svc == "https":
                    res.followups.append(TaskSpec(
                        type="web", ptes=Ptes.VULN_ANALYSIS.value,
                        target={"host": host, "port": port},
                        dedupe_key=f"web:{host}:{port}"))
                    # A live web root is a strong signal for exposed config/VCS
                    # secrets — formulate the hypothesis so the web pass prioritises it.
                    res.hypotheses.extend(
                        h.as_dict() for h in
                        hypothesis.generate_hypotheses("http_alive", f"{host}:{port}"))

            # SNMP is UDP, so it never appears in the TCP scan: probe it once per
            # host (unless the scan is pinned to a port list that leaves out 161).
            if not ports or 161 in ports:
                snmp_checks = [c for c in self.engine.applicable(
                                   "network", {"service": "snmp", "port": 161, "tls": False})
                               if (c.get("when") or {}).get("service") == "snmp"]
                if self._run_net_checks(res, snmp_checks,
                                        {"host": host, "port": 161, "service": "snmp"}, host, 161):
                    res.assets.append(AssetRec(
                        host=host, port=161, service="snmp", surface=Surface.NETWORK.value,
                        data={"protocol": "udp", **host_os}))
        return res

    def _run_net_checks(self, res: AgentResult, checks: list[dict], target: dict,
                        host: str, port: int) -> int:
        """Probe one network target with each check. Every hit becomes a Suspected
        finding the orchestrator sends to the verifier. Returns how many were found."""
        found = 0
        for check in checks:
            ptes = check.get("ptes_phase", Ptes.VULN_ANALYSIS.value)
            for o in self.engine.probe(check, target, self.guard):
                found += 1
                res.findings.append(FindingRec(
                    title=o.title, type=o.type, surface=Surface.NETWORK.value, ptes=ptes,
                    severity=o.severity, description=o.description, fix=o.fix,
                    asset_host=host, asset_port=port, check_id=check.get("id"),
                    evidence=[{"kind": "probe", "content": o.evidence}], data=o.data))
                self.emit("finding", ptes, f"{host}:{port}: suspected {o.type} — {o.title}")
        return found
