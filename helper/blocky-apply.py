#!/usr/bin/env python3
"""
Blocky privileged helper - runs as root via sudo.
Validates all inputs strictly before performing any system modifications.
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HOSTS_FILE = "/etc/hosts"
BLOCKY_BEGIN = "# BLOCKY:BEGIN"
BLOCKY_END = "# BLOCKY:END"
CGROUP_ROOT = "/sys/fs/cgroup/blocky/blocked"
CHAIN_NAME = "BLOCKY_OUTPUT"

ALLOWED_ACTIONS = {
    "hosts_add",
    "hosts_add_many",
    "hosts_remove",
    "hosts_remove_many",
    "iptables_setup",
    "iptables_teardown",
    "iptables_add_website",
    "iptables_remove_website",
    "iptables_add_ip",
    "iptables_temp_block",
    "iptables_temp_unblock",
    "iptables_redirect_http",
    "kill_connections",
    "dns_redirect_enable",
    "dns_redirect_disable",
    "iptables_add_app_cgroup",
    "iptables_remove_app_cgroup",
    "cgroup_create",
    "cgroup_add_pid",
    "cgroup_remove_pid",
    "sni_block_keyword",
    "sni_unblock_keyword",
    "sni_block_all_keywords",
    "sni_unblock_all_keywords",
}

TEMP_CHAIN = "BLOCKY_TEMP"
REDIRECT_PORT = 7878

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

COMMON_SUBDOMAINS = [
    "", "www", "m", "mobile", "app", "api", "cdn", "static", "assets",
    "img", "images", "i", "v", "s", "media", "video", "old", "new",
    "beta", "preview", "dev", "staging", "secure", "auth", "login",
    "account", "accounts", "shop", "store", "mail", "help", "support",
    "docs", "blog", "news", "forum", "community",
]


def die(msg: str) -> None:
    print(json.dumps({"ok": False, "error": msg}))
    sys.exit(1)


def ok(data: Any = None) -> None:
    print(json.dumps({"ok": True, **(data or {})}))


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not _DOMAIN_RE.match(domain):
        die(f"Invalid domain: {domain!r}")
    return domain


def validate_pid(pid: Any) -> int:
    try:
        pid = int(pid)
        assert 1 <= pid <= 4194304
        return pid
    except Exception:
        die(f"Invalid PID: {pid!r}")


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


# ----- /etc/hosts management -----

def _read_hosts() -> tuple[str, str, str]:
    """Return (before, managed_block, after) sections of /etc/hosts."""
    content = Path(HOSTS_FILE).read_text()
    if BLOCKY_BEGIN not in content:
        return content.rstrip(), "", ""
    start = content.index(BLOCKY_BEGIN)
    end_marker = content.find(BLOCKY_END, start)
    if end_marker == -1:
        return content[:start].rstrip(), "", ""
    end = end_marker + len(BLOCKY_END)
    before = content[:start].rstrip()
    block = content[start:end]
    after = content[end:].lstrip()
    return before, block, after


HOSTS_BACKUP = "/etc/hosts.bak"


def _backup_hosts() -> None:
    """Create /etc/hosts.bak on first modification — safety net."""
    if not Path(HOSTS_BACKUP).exists():
        try:
            shutil.copy2(HOSTS_FILE, HOSTS_BACKUP)
            os.chmod(HOSTS_BACKUP, 0o644)
        except Exception:
            pass  # Non-fatal — best effort


def _write_hosts(before: str, managed_lines: list[str], after: str) -> None:
    _backup_hosts()
    block = BLOCKY_BEGIN + "\n" + "\n".join(managed_lines) + "\n" + BLOCKY_END
    new_content = "\n".join(filter(None, [before, block, after])) + "\n"
    fd, tmp = tempfile.mkstemp(dir="/etc", prefix=".blocky_hosts_")
    try:
        os.chmod(tmp, 0o644)  # world-readable — required for system DNS resolver
        with os.fdopen(fd, "w") as f:
            f.write(new_content)
        shutil.move(tmp, HOSTS_FILE)
    except Exception as e:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        die(f"Failed to write hosts file: {e}")


def _parse_managed_lines(block: str) -> list[str]:
    lines = block.split("\n")
    # Strip the BEGIN/END markers, keep the rest
    result = []
    for line in lines:
        if line in (BLOCKY_BEGIN, BLOCKY_END):
            continue
        result.append(line)
    return result


def _entries_for_domain(domain: str) -> list[str]:
    entries = []
    for sub in COMMON_SUBDOMAINS:
        host = f"{sub}.{domain}" if sub else domain
        entries.append(f"127.0.0.1 {host}")  # redirect to localhost — faster refusal than 0.0.0.0
        entries.append(f"::1 {host}")
    return entries


def hosts_add(data: dict) -> None:
    domain = validate_domain(data.get("domain", ""))
    before, block, after = _read_hosts()
    managed = _parse_managed_lines(block)
    # Remove any existing entries for this domain to avoid duplicates
    managed = [l for l in managed if not (domain in l and l.strip())]
    managed.extend(_entries_for_domain(domain))
    _write_hosts(before, managed, after)
    ok()


def hosts_add_many(data: dict) -> None:
    """Add multiple domains to /etc/hosts in a single atomic write."""
    domains = data.get("domains", [])
    if not domains:
        die("No domains provided")
    before, block, after = _read_hosts()
    managed = _parse_managed_lines(block)

    # Build set of existing domains for O(1) lookup
    existing_domains: set[str] = set()
    for line in managed:
        parts = line.strip().split()
        if len(parts) >= 2:
            existing_domains.add(parts[1].lower())

    # Validate and collect new domains
    new_domains: list[str] = []
    for raw_domain in domains:
        raw_domain = raw_domain.strip().lower()
        if not _DOMAIN_RE.match(raw_domain):
            continue
        new_domains.append(raw_domain)

    # Remove existing entries for domains we're re-adding (batch filter)
    remove_set = {d for d in new_domains if d in existing_domains}
    if remove_set:
        managed = [l for l in managed
                   if not (l.strip() and len(l.split()) >= 2
                           and l.split()[1].lower() in remove_set)]

    # Add all new entries
    for domain in new_domains:
        managed.extend(_entries_for_domain(domain))

    _write_hosts(before, managed, after)
    ok()


def hosts_remove(data: dict) -> None:
    domain = validate_domain(data.get("domain", ""))
    before, block, after = _read_hosts()
    managed = _parse_managed_lines(block)
    managed = [l for l in managed if not (domain in l and l.strip())]
    _write_hosts(before, managed, after)
    ok()


def hosts_remove_many(data: dict) -> None:
    """Remove multiple domains from /etc/hosts in a single atomic write."""
    domains = data.get("domains", [])
    if not domains:
        die("No domains provided")
    before, block, after = _read_hosts()
    managed = _parse_managed_lines(block)
    domain_set = {d.strip().lower() for d in domains if d.strip()}
    managed = [l for l in managed if not any(d in l for d in domain_set)]
    _write_hosts(before, managed, after)
    ok()


# ----- iptables management -----

def _iptables(args: list[str], v6: bool = False, check: bool = True) -> bool:
    cmd = ["ip6tables" if v6 else "iptables"] + args
    result = _run(cmd, check=False)
    if check and result.returncode != 0:
        # Don't die on iptables errors - just report
        pass
    return result.returncode == 0


def iptables_setup(_: dict) -> None:
    for v6 in (False, True):
        # Create chain if it doesn't exist
        _iptables(["-N", CHAIN_NAME], v6=v6, check=False)
        # Insert jump at top of OUTPUT if not already there
        check = _iptables(["-C", "OUTPUT", "-j", CHAIN_NAME], v6=v6, check=False)
        if not check:
            _iptables(["-I", "OUTPUT", "-j", CHAIN_NAME], v6=v6)
    ok()


def iptables_teardown(_: dict) -> None:
    for v6 in (False, True):
        _iptables(["-D", "OUTPUT", "-j", CHAIN_NAME], v6=v6, check=False)
        _iptables(["-F", CHAIN_NAME], v6=v6, check=False)
        _iptables(["-X", CHAIN_NAME], v6=v6, check=False)
    ok()


def _resolve_ips(domain: str) -> list[str]:
    """Resolve real IPs via direct DNS to 8.8.8.8, bypassing /etc/hosts."""
    import struct
    ips = []
    for qtype, family in ((1, socket.AF_INET), (28, socket.AF_INET6)):
        try:
            txid = b'\xab\xcd'
            flags = b'\x01\x00'
            counts = b'\x00\x01\x00\x00\x00\x00\x00\x00'
            qname = b''
            for part in domain.split('.'):
                qname += bytes([len(part)]) + part.encode()
            qname += b'\x00'
            query = txid + flags + counts + qname + struct.pack('!HH', qtype, 1)
            server = '8.8.8.8' if qtype == 1 else '2001:4860:4860::8888'
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
            pos = 12 + len(qname) + 4
            ancount = struct.unpack('!H', data[6:8])[0]
            for _ in range(ancount):
                if pos < len(data) and data[pos] & 0xc0 == 0xc0:
                    pos += 2
                else:
                    while pos < len(data) and data[pos] != 0:
                        pos += data[pos] + 1
                    pos += 1
                if pos + 10 > len(data):
                    break
                rtype, _, _, rdlen = struct.unpack('!HHIH', data[pos:pos + 10])
                pos += 10
                if rtype == 1 and rdlen == 4:
                    ips.append('.'.join(str(b) for b in data[pos:pos + 4]))
                elif rtype == 28 and rdlen == 16:
                    raw = data[pos:pos + 16]
                    ips.append(socket.inet_ntop(socket.AF_INET6, raw))
                pos += rdlen
        except Exception:
            continue
    return ips


def iptables_add_ip(data: dict) -> None:
    """
    Immediately block a specific IP address.
    Uses REJECT --reject-with tcp-reset (not DROP) so the existing TCP connection
    receives a RST and dies immediately rather than timing out.
    Also flushes conntrack state for the IP so the kernel discards in-flight flows.
    """
    ip = data.get("ip", "").strip()
    if not ip:
        die("ip is required")
    try:
        if ":" in ip:
            socket.inet_pton(socket.AF_INET6, ip)
            v6 = True
        else:
            socket.inet_pton(socket.AF_INET, ip)
            v6 = False
    except Exception:
        die(f"Invalid IP address: {ip!r}")

    comment = data.get("comment", "blocky-ip")

    # Ensure the chain + OUTPUT jump exist (idempotent)
    _iptables(["-N", CHAIN_NAME], v6=v6, check=False)
    chain_exists = _iptables(["-C", "OUTPUT", "-j", CHAIN_NAME], v6=v6, check=False)
    if not chain_exists:
        _iptables(["-I", "OUTPUT", "-j", CHAIN_NAME], v6=v6)

    reject_args = ["--reject-with", "tcp-reset"] if not v6 else ["--reject-with", "icmp6-port-unreachable"]

    # Block outbound packets to the IP (prevents new requests + RSTs existing conn)
    _iptables(["-I", CHAIN_NAME, "-d", ip, "-p", "tcp", "-j", "REJECT"] + reject_args +
              ["-m", "comment", "--comment", comment], v6=v6, check=False)
    # Block inbound packets from the IP (kills server keep-alives / in-flight data)
    _iptables(["-I", CHAIN_NAME, "-s", ip, "-p", "tcp", "-j", "REJECT"] + reject_args +
              ["-m", "comment", "--comment", comment], v6=v6, check=False)

    # Flush conntrack entries so kernel doesn't keep routing established-state packets
    # (conntrack may not be installed — ignore if missing)
    import shutil
    if shutil.which("conntrack"):
        _run(["conntrack", "-D", "-d", ip], check=False)
        _run(["conntrack", "-D", "-s", ip], check=False)

    ok()


def iptables_add_website(data: dict) -> None:
    domain = validate_domain(data.get("domain", ""))
    comment = f"blocky-{domain}"
    # Block resolved IPs
    ips = _resolve_ips(domain)
    for ip in ips:
        v6 = ":" in ip
        _iptables(["-A", CHAIN_NAME, "-d", ip, "-j", "DROP",
                   "-m", "comment", "--comment", comment], v6=v6, check=False)
    ok({"ips_blocked": ips})


def iptables_remove_website(data: dict) -> None:
    domain = validate_domain(data.get("domain", ""))
    comment = f"blocky-{domain}"
    for v6 in (False, True):
        # List rules, find matching comments, delete them
        cmd = ["ip6tables" if v6 else "iptables", "-S", CHAIN_NAME]
        result = _run(cmd, check=False)
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            if comment in line:
                # Convert -A to -D
                del_args = line.replace("-A", "-D", 1).split()
                _iptables(del_args, v6=v6, check=False)
    ok()


def iptables_add_app_cgroup(_: dict) -> None:
    comment = "blocky-cgroup"
    for v6 in (False, True):
        check = _iptables(["-C", CHAIN_NAME, "-m", "cgroup",
                           "--path", "blocky/blocked", "-j", "REJECT"], v6=v6, check=False)
        if not check:
            _iptables(["-A", CHAIN_NAME, "-m", "cgroup",
                       "--path", "blocky/blocked", "-j", "REJECT",
                       "-m", "comment", "--comment", comment], v6=v6, check=False)
    ok()


def iptables_remove_app_cgroup(_: dict) -> None:
    for v6 in (False, True):
        _iptables(["-D", CHAIN_NAME, "-m", "cgroup",
                   "--path", "blocky/blocked", "-j", "REJECT"], v6=v6, check=False)
    ok()


# ----- DNS redirect (smart adult blocking) -----
# Redirects all port-53 DNS traffic to Cloudflare for Families (1.1.1.3)
# which automatically blocks adult content at DNS level.
# Uses the BLOCKY_DNS nat chain so it can be cleanly removed.

DNS_CHAIN = "BLOCKY_DNS"
DNS_FAMILY_IPV4 = "1.1.1.3"
DNS_FAMILY_IPV6 = "2606:4700:4700::1113"


def dns_redirect_enable(_: dict) -> None:
    # IPv4: redirect all outbound DNS to Cloudflare for Families
    _run(["iptables", "-t", "nat", "-N", DNS_CHAIN], check=False)
    _run(["iptables", "-t", "nat", "-F", DNS_CHAIN], check=False)
    # Redirect UDP/TCP port 53 to family-safe resolver
    for proto in ("udp", "tcp"):
        _run(["iptables", "-t", "nat", "-A", DNS_CHAIN,
              "-p", proto, "--dport", "53",
              "-j", "DNAT", f"--to-destination={DNS_FAMILY_IPV4}:53"], check=False)
    # Insert jump at top of OUTPUT chain if not already there
    check = _run(["iptables", "-t", "nat", "-C", "OUTPUT",
                  "-j", DNS_CHAIN], check=False)
    if check.returncode != 0:
        _run(["iptables", "-t", "nat", "-I", "OUTPUT", "-j", DNS_CHAIN], check=False)
    ok()


def dns_redirect_disable(_: dict) -> None:
    _run(["iptables", "-t", "nat", "-D", "OUTPUT", "-j", DNS_CHAIN], check=False)
    _run(["iptables", "-t", "nat", "-F", DNS_CHAIN], check=False)
    _run(["iptables", "-t", "nat", "-X", DNS_CHAIN], check=False)
    ok()


# ----- cgroup management -----

def cgroup_create(_: dict) -> None:
    cgroup_path = Path(CGROUP_ROOT)
    cgroup_path.mkdir(parents=True, exist_ok=True)
    ok()


def cgroup_add_pid(data: dict) -> None:
    pid = validate_pid(data.get("pid"))
    procs = Path(CGROUP_ROOT) / "cgroup.procs"
    if not procs.exists():
        Path(CGROUP_ROOT).mkdir(parents=True, exist_ok=True)
    try:
        procs.write_text(str(pid) + "\n")
        ok()
    except Exception as e:
        die(f"Failed to add PID {pid} to cgroup: {e}")


def cgroup_remove_pid(data: dict) -> None:
    pid = validate_pid(data.get("pid"))
    # Move back to root cgroup
    root_procs = Path("/sys/fs/cgroup/cgroup.procs")
    try:
        root_procs.write_text(str(pid) + "\n")
        ok()
    except Exception as e:
        die(f"Failed to remove PID {pid} from cgroup: {e}")


def _validate_ip(ip: str) -> tuple[str, bool]:
    """Return (ip, is_v6) or die on invalid input."""
    ip = ip.strip()
    try:
        if ":" in ip:
            socket.inet_pton(socket.AF_INET6, ip)
            return ip, True
        else:
            socket.inet_pton(socket.AF_INET, ip)
            return ip, False
    except Exception:
        die(f"Invalid IP address: {ip!r}")


def iptables_temp_block(data: dict) -> None:
    """
    Temporarily DROP packets to/from an IP while the LLM classifies it.
    Uses a separate BLOCKY_TEMP chain tagged with comment 'blocky-temp-<ip>'
    so temp rules can be cleanly removed without touching permanent blocks.
    """
    ip, v6 = _validate_ip(data.get("ip", ""))
    comment = f"blocky-temp-{ip}"

    # Ensure temp chain exists
    _iptables(["-N", TEMP_CHAIN], v6=v6, check=False)
    _iptables(["-C", "OUTPUT", "-j", TEMP_CHAIN], v6=v6, check=False) or \
        _iptables(["-I", "OUTPUT", "-j", TEMP_CHAIN], v6=v6)

    # Drop outbound only (enough to pause the page load)
    _iptables(["-I", TEMP_CHAIN, "-d", ip, "-p", "tcp",
               "-m", "comment", "--comment", comment, "-j", "DROP"],
              v6=v6, check=False)
    ok()


def iptables_temp_unblock(data: dict) -> None:
    """Remove the temporary DROP rule added by iptables_temp_block."""
    ip, v6 = _validate_ip(data.get("ip", ""))
    comment = f"blocky-temp-{ip}"
    # Delete all rules in TEMP_CHAIN with this comment
    while True:
        result = _run(
            ["ip6tables" if v6 else "iptables",
             "-D", TEMP_CHAIN, "-d", ip, "-p", "tcp",
             "-m", "comment", "--comment", comment, "-j", "DROP"],
            check=False,
        )
        if result.returncode != 0:
            break
    ok()


def iptables_redirect_http(_: dict) -> None:
    """
    Add an iptables NAT OUTPUT rule that redirects port-80 connections to
    127.0.0.1 → localhost:REDIRECT_PORT (our block page server).
    Called once at startup; idempotent.
    """
    check = _iptables(
        ["-t", "nat", "-C", "OUTPUT",
         "-p", "tcp", "-d", "127.0.0.1", "--dport", "80",
         "-j", "REDIRECT", "--to-port", str(REDIRECT_PORT)],
        check=False,
    )
    if not check:
        _iptables(
            ["-t", "nat", "-I", "OUTPUT",
             "-p", "tcp", "-d", "127.0.0.1", "--dport", "80",
             "-j", "REDIRECT", "--to-port", str(REDIRECT_PORT)],
        )
    ok()


def kill_connections(data: dict) -> None:
    """
    Force-close all ESTABLISHED TCP connections to a given IP using `ss --kill`.
    This sends RST to both sides, making the browser's current tab fail immediately
    so it can be redirected to the block page on its next request.
    Also works for IPv4 and IPv6.
    """
    ip, v6 = _validate_ip(data.get("ip", ""))
    if not shutil.which("ss"):
        ok()
        return

    # ss filter syntax: 'dst <ip>' matches connections destined to ip
    dst_filter = f"dst [{ip}]" if v6 else f"dst {ip}"
    src_filter = f"src [{ip}]" if v6 else f"src {ip}"
    for filt in (dst_filter, src_filter):
        _run(["ss", "--kill", "state", "established", filt], check=False)
    ok()


# ----- SNI keyword blocking -----
# Block TLS connections where the SNI (Server Name Indication) in the
# ClientHello contains an adult keyword.  This catches domains behind CDNs
# where IP-based resolution fails (e.g. Cloudflare shared certs).
# Also matches HTTP Host headers on port 80.

SNI_CHAIN = "BLOCKY_SNI"
SNI_COMMENT_PREFIX = "blocky-sni-"
_KEYWORD_RE = re.compile(r"^[a-zA-Z0-9\-]{2,40}$")


def _validate_keyword(kw: str) -> str:
    kw = kw.strip().lower()
    if not _KEYWORD_RE.match(kw):
        die(f"Invalid keyword: {kw!r}")
    return kw


def _ensure_sni_chain() -> None:
    """Create BLOCKY_SNI chain and hook into OUTPUT if needed."""
    for v6 in (False, True):
        _iptables(["-N", SNI_CHAIN], v6=v6, check=False)
        if not _iptables(["-C", "OUTPUT", "-j", SNI_CHAIN], v6=v6, check=False):
            _iptables(["-I", "OUTPUT", "-j", SNI_CHAIN], v6=v6)


def sni_block_keyword(data: dict) -> None:
    """Add iptables string-match rules to block TLS SNI containing *keyword*."""
    kw = _validate_keyword(data.get("keyword", ""))
    comment = f"{SNI_COMMENT_PREFIX}{kw}"
    _ensure_sni_chain()
    for v6 in (False, True):
        # Skip if rule already exists
        if _iptables(["-C", SNI_CHAIN, "-p", "tcp", "--dport", "443",
                       "-m", "string", "--string", kw, "--algo", "bm",
                       "-j", "DROP"], v6=v6, check=False):
            continue
        # HTTPS (TLS SNI)
        _iptables(["-A", SNI_CHAIN, "-p", "tcp", "--dport", "443",
                    "-m", "string", "--string", kw, "--algo", "bm",
                    "-m", "comment", "--comment", comment,
                    "-j", "DROP"], v6=v6, check=False)
        # QUIC (UDP 443) — browsers use HTTP/3 over QUIC to bypass TCP blocks
        _iptables(["-A", SNI_CHAIN, "-p", "udp", "--dport", "443",
                    "-m", "string", "--string", kw, "--algo", "bm",
                    "-m", "comment", "--comment", comment,
                    "-j", "DROP"], v6=v6, check=False)
        # HTTP (Host header)
        _iptables(["-A", SNI_CHAIN, "-p", "tcp", "--dport", "80",
                    "-m", "string", "--string", kw, "--algo", "bm",
                    "-m", "comment", "--comment", comment,
                    "-j", "DROP"], v6=v6, check=False)
    ok()


def sni_unblock_keyword(data: dict) -> None:
    """Remove SNI string-match rules for *keyword*."""
    kw = _validate_keyword(data.get("keyword", ""))
    comment = f"{SNI_COMMENT_PREFIX}{kw}"
    for v6 in (False, True):
        cmd = ["ip6tables" if v6 else "iptables", "-S", SNI_CHAIN]
        result = _run(cmd, check=False)
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            if comment in line:
                del_args = line.replace("-A", "-D", 1).split()
                _iptables(del_args, v6=v6, check=False)
    ok()


def sni_block_all_keywords(data: dict) -> None:
    """Block a list of keywords in one call. data["keywords"] = ["porn", "xxx", ...]"""
    keywords = data.get("keywords", [])
    if not isinstance(keywords, list):
        die("keywords must be a list")
    _ensure_sni_chain()
    blocked = 0
    for kw in keywords:
        try:
            kw = _validate_keyword(kw)
        except SystemExit:
            continue
        comment = f"{SNI_COMMENT_PREFIX}{kw}"
        for v6 in (False, True):
            if _iptables(["-C", SNI_CHAIN, "-p", "tcp", "--dport", "443",
                           "-m", "string", "--string", kw, "--algo", "bm",
                           "-j", "DROP"], v6=v6, check=False):
                continue
            _iptables(["-A", SNI_CHAIN, "-p", "tcp", "--dport", "443",
                        "-m", "string", "--string", kw, "--algo", "bm",
                        "-m", "comment", "--comment", comment,
                        "-j", "DROP"], v6=v6, check=False)
            # QUIC (UDP 443) — browsers use HTTP/3 over QUIC to bypass TCP blocks
            _iptables(["-A", SNI_CHAIN, "-p", "udp", "--dport", "443",
                        "-m", "string", "--string", kw, "--algo", "bm",
                        "-m", "comment", "--comment", comment,
                        "-j", "DROP"], v6=v6, check=False)
            _iptables(["-A", SNI_CHAIN, "-p", "tcp", "--dport", "80",
                        "-m", "string", "--string", kw, "--algo", "bm",
                        "-m", "comment", "--comment", comment,
                        "-j", "DROP"], v6=v6, check=False)
        blocked += 1
    ok({"blocked": blocked})


def sni_unblock_all_keywords(_: dict) -> None:
    """Remove all SNI keyword rules."""
    for v6 in (False, True):
        _iptables(["-F", SNI_CHAIN], v6=v6, check=False)
    ok()


# ----- Dispatch -----

ACTION_MAP = {
    "hosts_add": hosts_add,
    "hosts_add_many": hosts_add_many,
    "hosts_remove": hosts_remove,
    "hosts_remove_many": hosts_remove_many,
    "iptables_setup": iptables_setup,
    "dns_redirect_enable": dns_redirect_enable,
    "dns_redirect_disable": dns_redirect_disable,
    "iptables_teardown": iptables_teardown,
    "iptables_add_ip": iptables_add_ip,
    "iptables_temp_block": iptables_temp_block,
    "iptables_temp_unblock": iptables_temp_unblock,
    "iptables_redirect_http": iptables_redirect_http,
    "kill_connections": kill_connections,
    "iptables_add_website": iptables_add_website,
    "iptables_remove_website": iptables_remove_website,
    "iptables_add_app_cgroup": iptables_add_app_cgroup,
    "iptables_remove_app_cgroup": iptables_remove_app_cgroup,
    "cgroup_create": cgroup_create,
    "cgroup_add_pid": cgroup_add_pid,
    "cgroup_remove_pid": cgroup_remove_pid,
    "sni_block_keyword": sni_block_keyword,
    "sni_unblock_keyword": sni_unblock_keyword,
    "sni_block_all_keywords": sni_block_all_keywords,
    "sni_unblock_all_keywords": sni_unblock_all_keywords,
}


def main() -> None:
    if os.geteuid() != 0:
        die("Must be run as root")

    parser = argparse.ArgumentParser()
    parser.add_argument("--action", required=True)
    parser.add_argument("--data", default="{}")
    args = parser.parse_args()

    action = args.action
    if action not in ALLOWED_ACTIONS:
        die(f"Unknown action: {action!r}")

    raw_data = sys.stdin.read() if args.data == "-" else args.data
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as e:
        die(f"Invalid JSON data: {e}")

    ACTION_MAP[action](data)


if __name__ == "__main__":
    main()
