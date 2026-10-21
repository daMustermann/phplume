#!/usr/bin/env python3
"""phplume: a dependency-free, non-exploit PHP exposure inventory."""
from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import datetime as dt
import html
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urlsplit
import webbrowser

VERSION = "0.1.0"
REVIEWED = "2026-10-22"
REPO = "https://github.com/daMustermann/phplume"
ADVISORIES = [
    {"id": "CVE-2026-109618", "title": "RCE via OOM corruption", "cvss": 9.2,
     "url": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"},
    {"id": "CVE-2026-109619", "title": "RCE via stale global state", "cvss": 9.2,
     "url": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"},
]
FIXES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"))
LABELS = {"potentially_affected": "POTENTIALLY AFFECTED", "fixed_version": "FIX VERSION SEEN",
          "review": "NEEDS REVIEW", "no_php_evidence": "NO PHP EVIDENCE", "unreachable": "UNREACHABLE"}
COLORS = {"potentially_affected": 31, "fixed_version": 32, "review": 33,
          "no_php_evidence": 36, "unreachable": 90}
VERSION_RE = re.compile(r"(?<![\w.])(\d+\.\d+\.\d+(?:[-+~]?[A-Za-z][A-Za-z0-9.+:~_-]*|[-+~][0-9][A-Za-z0-9.+:~_-]*)?)(?![\w.])")
PHP_RE = re.compile(r"\bPHP[/\s]+(\d+\.\d+\.\d+(?:[A-Za-z0-9.+:~_-]*))", re.I)
MAX_BODY = 65536


def clean(value: object, limit: int = 500) -> str:
    """Strip terminal controls and keep remote evidence bounded."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))[:limit]


def assess(version: str | None) -> dict:
    result = {"state": "review", "version": version, "cves": [], "fixed_in": None,
              "explanation": "PHP was indicated, but its exact version is unknown. Check the serving runtime or vendor advisory."}
    if not version:
        return result
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", version.strip())
    if not match:
        result["explanation"] = "The version could not be interpreted reliably. Verify it on the server."
        return result
    major, minor, patch = map(int, match.group(1, 2, 3))
    suffix = match.group(4)
    branch = major, minor
    if branch not in FIXES:
        if major < 5 or branch > (8, 5):
            result["explanation"] = "This branch is outside the reviewed catalog. Consult upstream and your vendor; no safety conclusion is available."
            return result
        result.update(state="potentially_affected", cves=[a["id"] for a in ADVISORIES],
                      explanation="This upstream branch is end of life. Upgrade to a supported fixed branch, or verify both CVE backports with your vendor.")
        return result
    fixed = f"{major}.{minor}.{FIXES[branch]}"
    result["fixed_in"] = fixed
    if patch < FIXES[branch]:
        result.update(state="potentially_affected", cves=[a["id"] for a in ADVISORIES],
                      explanation=f"The upstream version predates {fixed}. Vendor backports may exist: verify the full package revision against both CVEs before concluding it is vulnerable.")
    elif re.search(r"(?:dev|alpha|beta|RC|snapshot)", suffix, re.I):
        result["explanation"] = f"This is a prerelease or development build. Verify inclusion of both complete patches; the stable fix is {fixed}."
    else:
        result.update(state="fixed_version", explanation=f"The advertised version meets the {fixed} fix floor for these two CVEs. This is version evidence, not proof of patch deployment or overall security.")
    return result


def local_address(address: str) -> bool:
    addr = ipaddress.ip_address(address)
    # IPv4-mapped addresses must pass the IPv4 policy, too.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not addr.is_multicast and not addr.is_unspecified and any(
        addr.version == net.version and addr in net for net in NETWORKS)


def resolve(host: str) -> list[str]:
    try:
        addresses = []
        for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            address = info[4][0]
            if info[0] == socket.AF_INET6 and info[4][3] and "%" not in address:
                address += f"%{info[4][3]}"
            if address not in addresses:
                addresses.append(address)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {clean(host)}: {clean(exc)}") from exc
    if not addresses or not all(local_address(a) for a in addresses):
        raise ValueError(f"{clean(host)} resolves outside private, link-local or loopback space. This tool scans local networks only.")
    return addresses


def port_list(value: str) -> list[int]:
    try:
        ports = list(dict.fromkeys(int(p.strip()) for p in value.split(",")))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use comma-separated ports, for example 80,443,8080.") from exc
    if not ports or len(ports) > 32 or any(p < 1 or p > 65535 for p in ports):
        raise argparse.ArgumentTypeError("Choose 1 to 32 ports between 1 and 65535.")
    return ports


def path_value(value: str) -> str:
    if not value.startswith("/") or value.startswith("//") or "#" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Paths must begin with one / and contain no fragments or control characters.")
    return quote(value, safe="/%?=&:+,;@!$'()*[]~-")


def endpoint(host: str, ip: str, port: int, scheme: str, path: str) -> dict:
    display_host = f"[{host}]" if ":" in host else host
    return {"host": host, "ip": ip, "port": port, "scheme": scheme, "path": path,
            "url": f"{scheme}://{display_host}:{port}{path}"}


def plan_targets(targets: list[str], ports: list[int], paths: list[str], max_hosts: int,
                 tls_ports: list[int]) -> list[dict]:
    planned: dict[tuple, dict] = {}
    seen_hosts: set[str] = set()

    def add(host, addresses, selected_ports, schemes=None, selected_paths=None):
        seen_hosts.update(addresses)
        if len(seen_hosts) > max_hosts:
            raise ValueError(f"Scope exceeds --max-hosts {max_hosts}. Split the network or increase the explicit limit (maximum 4096).")
        for address in addresses:
            for port in selected_ports:
                scheme = schemes or ("https" if port in tls_ports else "http")
                for path in (selected_paths or paths):
                    key = host, address, port, scheme, path
                    planned[key] = endpoint(host, address, port, scheme, path)
                    if len(planned) > 32768:
                        raise ValueError("Scope exceeds 32768 requests. Split this scan into smaller scopes.")

    for raw in targets:
        if any(ord(c) < 32 or ord(c) == 127 for c in raw):
            raise ValueError("Targets cannot contain control characters.")
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        if any(ord(c) < 33 for c in raw):
            raise ValueError("Targets cannot contain spaces or control characters.")
        if "://" in raw:
            parts = urlsplit(raw)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.fragment:
                raise ValueError("URLs must use HTTP(S), with no credentials or fragment.")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if port < 1 or port > 65535:
                raise ValueError("URL port must be between 1 and 65535.")
            path = path_value((parts.path or "/") + ("?" + parts.query if parts.query else ""))
            add(parts.hostname, resolve(parts.hostname), [port], parts.scheme, [path])
        elif "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            if net.num_addresses > max_hosts + (2 if net.version == 4 and net.prefixlen < 31 else 0):
                raise ValueError(f"{net} exceeds the host limit. Use a smaller subnet; no automatic /24 guessing is performed.")
            addresses = [str(a) for a in net.hosts()]
            if not all(local_address(a) for a in addresses):
                raise ValueError(f"{net} is outside supported local address space.")
            for address in addresses:
                add(address, [address], ports)
        else:
            host = raw.strip("[]")
            if ":" in host:
                try:
                    ipaddress.ip_address(host)
                except ValueError as exc:
                    raise ValueError("For a host with a port use http://host:port or https://host:port.") from exc
            add(host, resolve(host), ports)
    return list(planned.values())


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, target: dict, timeout: float, insecure: bool):
        super().__init__(target["host"], target["port"], timeout=timeout)
        self.target = target
        self.insecure = insecure

    def connect(self):
        # Connect only to the address validated during planning. Preserve Host and TLS SNI.
        self.sock = socket.create_connection((self.target["ip"], self.port), self.timeout)
        if self.target["scheme"] == "https":
            context = ssl.create_default_context()
            if self.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)


def fingerprint(headers: list[tuple[str, str]], body: str) -> tuple[list[str], list[str]]:
    versions: set[str] = set()
    evidence: list[str] = []
    for key, value in headers:
        lower = key.lower()
        if lower in ("server", "x-powered-by"):
            if re.search(r"\bphp\b", value, re.I):
                evidence.append(f"{key}: {clean(value)}")
                versions.update(m.group(1) for m in PHP_RE.finditer(value))
        if lower == "set-cookie" and re.match(r"\s*PHPSESSID=", value, re.I):
            evidence.append("PHPSESSID cookie name (value omitted; weak PHP indicator)")
    if re.search(r"(?:href|action)\s*=\s*['\"][^'\"]{0,300}\.php(?:[?'\"])", body, re.I):
        evidence.append("A .php link or form action appears in the response (weak indicator)")
    if re.search(r"(?:wp-content/|wp-includes/|name=['\"]generator['\"][^>]{0,150}(?:WordPress|Drupal|Joomla))", body, re.I):
        evidence.append("A PHP application marker appears in the response (may be static or proxied)")
    return sorted(versions), list(dict.fromkeys(evidence))


def probe(target: dict, timeout: float, insecure: bool = False) -> dict:
    started = time.monotonic()
    result = {"kind": "network", "target": target["url"], "address": target["ip"], "state": "unreachable",
              "versions": [], "evidence": [], "cves": [], "assessments": [], "status_code": None,
              "tls_verified": target["scheme"] == "https" and not insecure,
              "explanation": "No HTTP response was received. Closed ports, filtering, protocol mismatch or timeouts do not rule out PHP."}
    conn = PinnedHTTP(target, timeout, insecure)
    def expire():
        sock = conn.sock
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        conn.request("GET", target["path"], headers={"User-Agent": f"phplume/{VERSION} (+{REPO})",
                     "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                     "Accept-Encoding": "identity", "Connection": "close"})
        response = conn.getresponse()
        result["status_code"] = response.status
        headers = response.getheaders()
        # Small bounded reads enforce a whole-response deadline even on slow trickle bodies.
        content = bytearray()
        body_error = None
        deadline = started + timeout
        try:
            while len(content) < MAX_BODY and time.monotonic() < deadline:
                if conn.sock:
                    conn.sock.settimeout(max(0.05, deadline - time.monotonic()))
                chunk = response.read1(min(4096, MAX_BODY - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
        except (OSError, http.client.HTTPException) as exc:
            body_error = f"Body incomplete: {clean(exc)}"
        versions, evidence = fingerprint(headers, content.decode("utf-8", "replace"))
        result.update(versions=versions, evidence=evidence)
        assessments = [assess(v) for v in versions]
        result["assessments"] = assessments
        if assessments:
            states = {a["state"] for a in assessments}
            state = "potentially_affected" if "potentially_affected" in states else "review" if "review" in states else "fixed_version"
            if len(versions) > 1 and state == "fixed_version":
                state = "review"
            result.update(state=state, cves=sorted({c for a in assessments for c in a["cves"]}),
                          explanation=" ".join(dict.fromkeys(a["explanation"] for a in assessments)))
            if len(versions) > 1:
                result["explanation"] += " Multiple versions were advertised; investigate proxy headers and backend pools."
        elif evidence:
            result.update(state="review", explanation=assess(None)["explanation"])
        else:
            result.update(state="no_php_evidence", explanation="This response did not identify PHP. Hidden versions, virtual hosts, authentication, other paths and reverse proxies may conceal it. This is not a clean bill of health.")
        if 300 <= response.status < 400:
            location = response.getheader("Location")
            result["redirect"] = clean(location or "(missing Location)")
            result["explanation"] += " Redirect not followed; scan the destination explicitly if it belongs to your scope."
            if result["state"] in ("no_php_evidence", "fixed_version"):
                result["state"] = "review"
        if response.status in (401, 403, 407) or response.status >= 500:
            result["explanation"] += " Access was restricted or an error page was returned; backend coverage is incomplete."
            if result["state"] in ("no_php_evidence", "fixed_version"):
                result["state"] = "review"
        if body_error:
            result["evidence"].append(body_error)
            if result["state"] == "no_php_evidence":
                result["state"] = "review"
    except ssl.SSLCertVerificationError:
        result.update(state="review", explanation="TLS certificate verification failed. Supply a trusted CA with --ca-file, or explicitly use --insecure for a known internal endpoint.")
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result["error"] = clean(exc)
    finally:
        timer.cancel()
        conn.close()
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def local_inventory(binaries: list[str]) -> list[dict]:
    candidates = list(binaries)
    for name in ["php", *[f"php{a}.{b}" for a, b in FIXES]]:
        found = shutil.which(name)
        if found:
            candidates.append(found)
    results = []
    seen = set()
    for binary in candidates:
        path = str(Path(binary).expanduser().resolve())
        if os.path.normcase(path) in seen:
            continue
        seen.add(os.path.normcase(path))
        try:
            # -n avoids loading application INI files and their auto_prepend directives.
            run = subprocess.run([path, "-n", "-v"], capture_output=True, text=True, timeout=5,
                                 errors="replace", check=False)
            match = PHP_RE.search(run.stdout[:8192])
            if run.returncode or not match:
                raise ValueError("The command did not return a PHP version.")
            version = match.group(1)
            assessment = assess(version)
            results.append({"kind": "local", "target": path, "address": None, **assessment,
                            "versions": [version], "assessments": [assessment],
                            "evidence": ["Local php -n -v; only this CLI executable was inspected."],
                            "explanation": assessment["explanation"] + " The CLI binary may differ from FPM, Apache, containers or appliance runtimes. Confirm the serving runtime and restart workers after updating."})
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            results.append({"kind": "local", "target": path, "state": "review", "versions": [],
                            "evidence": [], "cves": [], "assessments": [],
                            "explanation": f"Unable to inspect this executable: {clean(exc)}"})
    return results


def run_command(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=8, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def discover_networks() -> list[tuple[str, str]]:
    """Read actual interface masks; never infer /24 from an address."""
    found: set[tuple[str, str]] = set()
    if sys.platform == "win32":
        raw = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                           "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress"])
        try:
            entries = json.loads(raw)
            for entry in (entries if isinstance(entries, list) else [entries]):
                interface = ipaddress.ip_interface(f"{entry['IPAddress']}/{entry['PrefixLength']}")
                if local_address(str(interface.ip)) and not interface.ip.is_loopback and not interface.ip.is_link_local:
                    found.add((str(entry["InterfaceAlias"]), str(interface.network)))
        except (ValueError, KeyError, TypeError):
            pass
    elif sys.platform.startswith("linux"):
        try:
            for entry in json.loads(run_command(["ip", "-j", "-4", "address", "show", "up"])):
                for info in entry.get("addr_info", []):
                    interface = ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}")
                    if local_address(str(interface.ip)) and not interface.ip.is_loopback and not interface.ip.is_link_local:
                        found.add((entry["ifname"], str(interface.network)))
        except (ValueError, KeyError, TypeError):
            pass
    else:
        name = "interface"
        for line in run_command(["ifconfig"]).splitlines():
            if line and not line[0].isspace():
                name = line.split(":")[0]
            match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-f]+|[\d.]+)", line, re.I)
            if match:
                try:
                    mask = match.group(2)
                    if mask.startswith("0x"):
                        mask = str(ipaddress.IPv4Address(int(mask, 16)))
                    interface = ipaddress.ip_interface(f"{match.group(1)}/{mask}")
                    if local_address(str(interface.ip)) and not interface.ip.is_loopback and not interface.ip.is_link_local:
                        found.add((name, str(interface.network)))
                except ValueError:
                    pass
    return sorted(found)


class Console:
    def __init__(self, color: bool = True, quiet: bool = False):
        self.color = color and sys.stderr.isatty() and "NO_COLOR" not in os.environ
        self.quiet = quiet
        if self.color and sys.platform == "win32":
            try:
                handle = ctypes.windll.kernel32.GetStdHandle(-12)
                mode = ctypes.c_ulong()
                ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 4)
            except (AttributeError, OSError):
                self.color = False

    def say(self, text: str = "", color: int | None = None):
        if not self.quiet:
            prefix = f"\033[{color}m" if self.color and color else ""
            suffix = "\033[0m" if prefix else ""
            print(prefix + text + suffix, file=sys.stderr, flush=True)

    def banner(self):
        self.say("\n  /p  phplume", 36)
        self.say(f"      Find the PHP you need to fix.                    v{VERSION}")
        self.say(f"      LOCAL NETWORK INVENTORY  /  ADVISORIES {REVIEWED}\n")

    def finding(self, result: dict):
        self.say(f"  {LABELS[result['state']]:<22}  {clean(result['target'], 180)}", COLORS[result["state"]])
        if result["versions"]:
            self.say("    PHP " + ", ".join(clean(v) for v in result["versions"]))
        if result["state"] in ("potentially_affected", "review", "fixed_version"):
            self.say("    " + result["explanation"])


def wizard(console: Console) -> list[str]:
    console.say("  What would you like to inspect?")
    console.say("  [1] This computer       Check PHP executables on PATH")
    console.say("  [2] My local network    Choose an interface and scan web ports")
    console.say("  [3] Specific systems    Enter local IPs, CIDRs or URLs\n")
    choice = input("  Choose [1]: ").strip() or "1"
    if choice == "1":
        return []
    if choice == "2":
        networks = discover_networks()
        if networks:
            for index, (name, network) in enumerate(networks, 1):
                console.say(f"  [{index}] {clean(name)}  {network}")
            selected = input("  Interface number (or enter a CIDR): ").strip()
            if selected.isdigit() and 1 <= int(selected) <= len(networks):
                return [networks[int(selected) - 1][1]]
            if selected:
                return [selected]
        else:
            console.say("  Could not read interface masks. Enter your actual subnet, for example 192.168.1.0/24.")
            return input("  Local network CIDR: ").strip().split()
    if choice in ("2", "3"):
        return input("  Local IPs, CIDRs or URLs (space separated): ").strip().split()
    raise ValueError("Choose 1, 2 or 3, or use --help for command-line options.")


def next_steps(state: str) -> str:
    if state == "potentially_affected":
        return "Verify the serving runtime and full vendor package revision for both CVEs. Apply the complete PHP/vendor update, rebuild affected containers, restart all web workers, then rescan. Prioritize externally reachable services."
    if state == "fixed_version":
        return "Confirm that all backend workers run the patched build and were restarted. Check vendor bulletins and other runtimes; this catalog covers only the two listed CVEs."
    if state == "unreachable":
        return "Check the host, firewall, port and protocol. A service may use another port, interface, virtual host or IPv6 address."
    return "Check the application's serving PHP version in its admin panel or on the server. Include virtual hosts, FPM pools, containers and appliances; compare vendor package revisions with both CVEs."


def stale_catalog() -> bool:
    return (dt.datetime.now(dt.timezone.utc).date() - dt.date.fromisoformat(REVIEWED)).days > 7


def make_report(results: list[dict], planned: int, elapsed: float, args, local_checked: bool) -> dict:
    return {"schema_version": 1, "tool": "phplume", "tool_version": VERSION,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "catalog_reviewed": REVIEWED,
            "catalog_stale": stale_catalog(), "advisories": ADVISORIES,
            "fix_versions": [f"{a}.{b}.{p}" for (a, b), p in FIXES.items()],
            "scope": {"targets": args.targets, "planned_requests": planned, "completed_requests": sum(r["kind"] == "network" for r in results),
                      "local_inventory_requested": local_checked, "local_executables_found": sum(r["kind"] == "local" for r in results),
                      "ports": args.ports, "tls_ports": args.tls_ports, "paths": args.paths,
                      "tls_verification_disabled": args.insecure, "workers": args.workers,
                      "timeout_seconds": args.timeout},
            "duration_seconds": round(elapsed, 2),
            "summary": {state: sum(r["state"] == state for r in results) for state in LABELS},
            "limitations": "Version-based inventory for two CVEs, not an exploitation test or security certification. Vendor backports, hidden PHP, proxies, virtual hosts, unscanned ports and other runtimes require manual verification. No PHP evidence does not mean unaffected.",
            "results": results}


def render_html(report: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    summary = report["summary"]
    cards = "".join(f'<div class="stat"><b>{summary[state]}</b><span>{esc(LABELS[state])}</span></div>' for state in ("potentially_affected", "review", "fixed_version", "no_php_evidence", "unreachable"))
    rows = []
    for result in sorted(report["results"], key=lambda r: (list(LABELS).index(r["state"]), r["target"])):
        evidence = "".join(f"<li>{esc(e)}</li>" for e in result["evidence"])
        rows.append(f'''<article class="finding" data-state="{esc(result['state'])}">
<div class="finding-head"><span class="badge {esc(result['state'])}">{esc(LABELS[result['state']])}</span><span class="meta">{esc(result['kind'].upper())} {esc(result.get('address') or '')}</span></div>
<h3>{esc(result['target'])}</h3><p class="version">{esc('PHP ' + ', '.join(result['versions']) if result['versions'] else 'PHP version not established')}</p>
<p>{esc(result['explanation'])}</p><details><summary>Evidence &amp; next steps</summary><ul>{evidence or '<li>No PHP indicator was observed.</li>'}</ul><p>{esc(next_steps(result['state']))}</p>{'<p>Connection detail: ' + esc(result['error']) + '</p>' if result.get('error') else ''}</details></article>''')
    sources = "".join(f'<li><a href="{esc(a["url"])}">{esc(a["id"])} — {esc(a["title"])}</a> · CVSS 4.0 {a["cvss"]}</li>' for a in ADVISORIES)
    scope = report["scope"]
    notices = '<p class="notice">Catalog is over seven days old. Get the latest tool and consult the linked advisories.</p>' if report["catalog_stale"] else ''
    if report.get("demo"):
        notices += '<p class="notice"><strong>DEMO REPORT.</strong> All findings are synthetic. No systems were contacted.</p>'
    if scope["tls_verification_disabled"]:
        notices += '<p class="notice">TLS certificate verification was disabled for this scan. HTTPS identity was not authenticated.</p>'
    if scope["local_inventory_requested"] and not scope["local_executables_found"]:
        notices += '<p class="notice">No local PHP CLI executable was found. Web workers, containers and bundled PHP may still be present.</p>'
    css = '''*{box-sizing:border-box}body{margin:0;background:#f7f6f3;color:#2f3437;font:16px/1.65 "Helvetica Neue",Arial,sans-serif}main{max-width:1120px;margin:auto;padding:40px 32px 80px}nav{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #dddcd6;padding-bottom:22px}.brand{font-size:23px;font-weight:750;letter-spacing:-1px;display:flex;gap:12px;align-items:center}.brand svg{width:32px;height:40px}.meta,.eyebrow{font:12px/1.5 Consolas,monospace;color:#65645f;letter-spacing:.04em}.hero{padding:68px 0 44px;max-width:820px}.eyebrow{text-transform:uppercase}h1{font:clamp(48px,7vw,80px)/1.02 Georgia,serif;letter-spacing:-.045em;margin:20px 0 25px;color:#202720}.hero p{max-width:680px}.stats{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid #eaeaea;background:#fff;margin-bottom:36px}.stat{padding:24px 18px;border-right:1px solid #eaeaea}.stat:last-child{border:0}.stat b{display:block;font:44px/1.2 Georgia,serif}.stat span{display:block;font:10px/1.5 Consolas,monospace;letter-spacing:.04em;margin-top:12px}.toolbar{display:flex;justify-content:space-between;gap:18px;align-items:center;margin:42px 0 22px}h2{font:32px/1.15 Georgia,serif;margin:0}select,input{font:inherit;border:1px solid #b8b9b1;background:#fff;border-radius:4px;padding:10px;max-width:100%;color:inherit}.filters{display:flex;gap:8px}.finding{border:1px solid #eaeaea;background:white;border-radius:8px;padding:28px 32px;margin:12px 0}.finding-head{display:flex;justify-content:space-between;gap:12px;align-items:center}.badge{background:#fbf3db;color:#785200;padding:4px 8px;font:10px/1.5 Consolas,monospace;letter-spacing:.04em}.potentially_affected{background:#fdebec;color:#9f2f2d}.fixed_version{background:#edf3ec;color:#346538}.no_php_evidence{background:#e1f3fe;color:#1f6c9f}.unreachable{background:#f0f0ed;color:#65645f}h3{font:19px/1.5 Consolas,monospace;overflow-wrap:anywhere;margin:18px 0 4px}.version{font:13px/1.6 Consolas,monospace;color:#65645f;margin:0 0 18px}details{border-top:1px solid #eaeaea;margin-top:22px;padding-top:16px}summary{cursor:pointer;font-weight:600}a{color:#346538;text-underline-offset:3px}.notice{background:#fbf3db;border-left:3px solid #956400;padding:15px 20px}footer{border-top:1px solid #dddcd6;margin-top:56px;padding-top:32px}footer h2{margin-bottom:20px}code{font-family:Consolas,monospace}.scope{overflow-wrap:anywhere}#empty{padding:32px 0;color:#65645f}[hidden]{display:none!important}:focus-visible{outline:3px solid #346538;outline-offset:3px}@media(max-width:720px){main{padding:24px 18px}.hero{padding:42px 0 28px}.stats{grid-template-columns:repeat(2,1fr)}.stat{border-bottom:1px solid #eaeaea}.toolbar{align-items:flex-start;flex-direction:column}.filters{flex-wrap:wrap}.finding{padding:22px}.finding-head{align-items:flex-start;flex-direction:column}nav>.meta{max-width:150px;text-align:right}}@media print{body{background:white}.filters{display:none}.finding{break-inside:avoid}details>*{display:block!important}main{max-width:none}}'''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'"><title>phplume — PHP exposure report</title><style>{css}</style></head>
<body><main><nav><div class="brand"><svg viewBox="0 0 40 48" aria-hidden="true"><path d="M7 44V16L20 4l13 12v16L20 44V25l-7 7" fill="none" stroke="#346538" stroke-width="5" stroke-linejoin="miter"/></svg>phplume</div><span class="meta">LOCAL NETWORK INVENTORY<br>v{esc(VERSION)} / {esc(report['catalog_reviewed'])}</span></nav>
<header class="hero"><span class="eyebrow">Your PHP exposure, explained.</span><h1>Know what<br>needs your attention.</h1><p>PHP security updates start with knowing what you run. This report inventories visible versions and points you to the systems that need verification.</p><p class="meta">{esc(report['generated_at'])} · {report['duration_seconds']}s · {scope['completed_requests']} of {scope['planned_requests']} network requests</p></header>
{notices}<div class="stats">{cards}</div><p class="scope"><strong>Scope:</strong> {esc(', '.join(scope['targets']) or 'Local CLI inventory only')} · {scope['local_executables_found']} local executable(s)</p><p><strong>Read this first.</strong> {esc(report['limitations'])}</p>
<section aria-labelledby="findings"><div class="toolbar"><h2 id="findings">The findings</h2><div class="filters"><input id="search" aria-label="Search findings" placeholder="Find a system…" type="search"><select id="filter" aria-label="Filter by result"><option value="all">All results</option>{''.join(f'<option value="{s}">{esc(label.title())}</option>' for s, label in LABELS.items())}</select></div></div>
{''.join(rows) or '<p>No endpoints or PHP executables were inspected. Check the scan scope.</p>'}<p id="empty" hidden>No findings match your filter.</p></section>
<footer><h2>Close the loop.</h2><p>Verify the serving runtime and vendor package revision, apply both fixes, restart every worker and run the inventory again. A version banner alone cannot confirm a vendor backport or that every backend was updated.</p><p>Upstream fix floors: <code>{esc(' / '.join(report['fix_versions']))}</code>. Update to a current supported release or the vendor package fixing both CVEs.</p><ul>{sources}</ul><p class="meta">Catalog reviewed {esc(REVIEWED)}. Covers the two October 2026 advisories only. Reports stay on your device; this file loads no external resources.</p></footer></main>
<script>const filter=document.getElementById('filter'),search=document.getElementById('search');function update(){{let visible=0;document.querySelectorAll('.finding').forEach(row=>{{row.hidden=(filter.value!=='all'&&row.dataset.state!==filter.value)||!row.textContent.toLowerCase().includes(search.value.toLowerCase());if(!row.hidden)visible++}});document.getElementById('empty').hidden=visible>0}}filter.addEventListener('change',update);search.addEventListener('input',update);</script></body></html>'''


def write_private(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids clobbering previous inventories or following symlinks.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Find PHP exposure on your local network. No exploit payloads, no dependencies.",
                                epilog="Examples: phplume.py --local | phplume.py 192.168.1.0/24 | phplume.py https://nas.lan:8443 --insecure")
    p.add_argument("targets", nargs="*", help="Local IPs, CIDRs, hostnames or HTTP(S) URLs")
    p.add_argument("--local", action="store_true", help="Also inspect PHP CLI executables on this computer")
    p.add_argument("--php-bin", action="append", default=[], help="Additional trusted local PHP executable (repeatable)")
    p.add_argument("--targets-file", type=Path, help="UTF-8 file, one target per line; # comments allowed")
    p.add_argument("--ports", type=port_list, default=port_list("80,443,8080,8443"), help="Ports for bare hosts/CIDRs (default: 80,443,8080,8443)")
    p.add_argument("--tls-ports", type=port_list, default=port_list("443,8443"), help="Ports using HTTPS; URLs override this (default: 443,8443)")
    p.add_argument("--path", action="append", dest="paths", help="Known application path for bare hosts/CIDRs; repeatable (default: /)")
    p.add_argument("--workers", type=int, default=16, help="Parallel requests, 1–64 (default: 16)")
    p.add_argument("--timeout", type=float, default=3, help="Socket/body timeout in seconds, 0.2–30 (default: 3)")
    p.add_argument("--max-hosts", type=int, default=1024, help="Host cap, 1–4096 (default: 1024)")
    p.add_argument("--insecure", action="store_true", help="Explicitly skip HTTPS certificate validation")
    p.add_argument("--ca-file", type=Path, help="Trusted PEM CA bundle for internal HTTPS")
    p.add_argument("--output-dir", type=Path, default=Path.cwd() / "phplume-reports", help="Report directory (default: ./phplume-reports)")
    p.add_argument("--json", action="store_true", help="Write JSON to stdout; progress stays on stderr")
    p.add_argument("--no-report", action="store_true", help="Do not save HTML/JSON report files")
    p.add_argument("--open", action="store_true", help="Open the saved HTML report in your browser")
    p.add_argument("--quiet", action="store_true", help="Suppress progress and terminal findings")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors (also respects NO_COLOR)")
    p.add_argument("--demo", action="store_true", help="Create a clearly labeled sample report without contacting any systems")
    p.add_argument("--version", action="version", version=f"phplume {VERSION}")
    return p


def demo_results() -> list[dict]:
    results = []
    for host, version in (("http://nas.example:80/", "8.3.35"), ("https://wiki.example:443/", "8.4.27"), ("https://router.example:443/", None)):
        assessment = assess(version)
        results.append({"kind": "network", "target": "[DEMO] " + host, "address": "192.168.50.10",
                        **assessment, "versions": [version] if version else [], "evidence": ["Synthetic sample data. No system was contacted."],
                        "assessments": [assessment]})
    return results


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    console = Console(not args.no_color, args.quiet)
    console.banner()
    if not (1 <= args.workers <= 64 and 1 <= args.max_hosts <= 4096 and math.isfinite(args.timeout) and 0.2 <= args.timeout <= 30):
        p.error("workers must be 1–64, max-hosts 1–4096, timeout 0.2–30 seconds.")
    if args.open and args.no_report:
        p.error("--open requires saved reports; remove --no-report.")
    if args.ca_file and args.insecure:
        p.error("Choose --ca-file or --insecure, not both.")
    if args.ca_file:
        # OpenSSL honors this bundle without modifying the system trust store.
        try:
            ssl.create_default_context(cafile=str(args.ca_file.resolve()))
        except (OSError, ssl.SSLError) as exc:
            p.error(f"Cannot load CA file: {clean(exc)}")
        os.environ["SSL_CERT_FILE"] = str(args.ca_file.resolve())
    started = time.monotonic()
    try:
        args.paths = [path_value(path) for path in (args.paths or ["/"]) ]
        if args.targets_file:
            if args.targets_file.stat().st_size > 1024 * 1024:
                raise ValueError("Target file exceeds 1 MiB; split it into smaller files.")
            args.targets.extend(line.strip() for line in args.targets_file.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        if not args.targets and not args.local and not args.php_bin and not args.demo:
            if sys.stdin.isatty() and not args.json and not args.quiet:
                args.targets = wizard(console)
                args.local = True
            else:
                args.local = True
        if stale_catalog():
            console.say("  Catalog is over seven days old. Download the latest tool and check upstream advisories.", 33)
        if args.insecure:
            console.say("  HTTPS certificate validation disabled. Results cannot authenticate server identity.", 33)
        if args.demo:
            console.say("  DEMO — synthetic findings only. No network or executable inspection.", 33)
            results = demo_results()
            args.targets = ["DEMO / synthetic data"]
            planned = []
        else:
            planned = plan_targets(args.targets, args.ports, args.paths, args.max_hosts, args.tls_ports)
            if args.targets and not planned:
                raise ValueError("The supplied scope contains no targets.")
            local_requested = args.local or bool(args.php_bin)
            results = local_inventory(args.php_bin) if local_requested else []
            if local_requested and not results:
                console.say("  No PHP CLI executable found on PATH. Bundled PHP, web workers and containers may still be present.", 33)
            for result in results:
                console.finding(result)
            if planned:
                console.say(f"  Scope: {len({t['ip'] for t in planned})} address(es), {len(planned)} GET request(s), {args.workers} worker(s).")
                console.say("  Scanning local web services. Only scan systems you own or are authorized to inspect.\n")
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                    tasks = {pool.submit(probe, target, args.timeout, args.insecure): target for target in planned}
                    last_progress = time.monotonic()
                    completed = 0
                    try:
                        for task in concurrent.futures.as_completed(tasks):
                            result = task.result()
                            results.append(result)
                            completed += 1
                            if result["state"] != "unreachable":
                                console.finding(result)
                            if completed == len(planned) or time.monotonic() - last_progress >= 2:
                                console.say(f"  Progress  {completed}/{len(planned)} requests checked")
                                last_progress = time.monotonic()
                    except KeyboardInterrupt:
                        for task in tasks:
                            task.cancel()
                        raise
        report = make_report(results, len(planned), time.monotonic() - started, args, (args.local or bool(args.php_bin)) and not args.demo)
        report["demo"] = args.demo
        if args.demo:
            report["scope"]["planned_requests"] = 0
            report["scope"]["completed_requests"] = 0
        console.say("\n  INVENTORY COMPLETE", 36)
        for state, count in report["summary"].items():
            console.say(f"  {count:>4}  {LABELS[state]}", COLORS[state])
        console.say("\n  " + report["limitations"])
        if not args.no_report:
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            directory = args.output_dir.expanduser().resolve()
            json_path = directory / f"phplume-{stamp}.json"
            html_path = directory / f"phplume-{stamp}.html"
            write_private(json_path, json.dumps(report, indent=2, ensure_ascii=True) + "\n")
            write_private(html_path, render_html(report))
            console.say(f"\n  HTML report  {html_path}\n  JSON report  {json_path}")
            if args.open:
                webbrowser.open(html_path.as_uri())
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=True))
        if report["summary"]["potentially_affected"]:
            return 1
        if report["catalog_stale"] or report["summary"]["review"] or report["summary"]["no_php_evidence"] or report["summary"]["unreachable"] or not results:
            return 2
        return 0
    except (ValueError, OSError) as exc:
        console.say(f"  Could not finish: {clean(exc)}", 31)
        return 3
    except (KeyboardInterrupt, EOFError):
        console.say("\n  Stopped. This scan is incomplete; no complete report was generated.", 33)
        return 130


if __name__ == "__main__":
    sys.exit(main())
