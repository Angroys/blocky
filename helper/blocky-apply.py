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
    "hosts_remove",
    "iptables_setup",
    "iptables_teardown",
    "iptables_add_website",
    "iptables_remove_website",
    "iptables_add_ip",
    "dns_redirect_enable",
    "dns_redirect_disable",
    "iptables_add_app_cgroup",
    "iptables_remove_app_cgroup",
    "cgroup_create",
    "cgroup_add_pid",
    "cgroup_remove_pid",
}

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


def hosts_remove(data: dict) -> None:
    domain = validate_domain(data.get("domain", ""))
    before, block, after = _read_hosts()
    managed = _parse_managed_lines(block)
    managed = [l for l in managed if not (domain in l and l.strip())]
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
    """Block a specific IP address directly (bypasses /etc/hosts resolution)."""
    ip = data.get("ip", "").strip()
    if not ip:
        die("ip is required")
    # Basic IP validation
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
    _iptables(["-A", CHAIN_NAME, "-d", ip, "-j", "DROP",
               "-m", "comment", "--comment", comment], v6=v6, check=False)
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


# ----- Dispatch -----

ACTION_MAP = {
    "hosts_add": hosts_add,
    "hosts_remove": hosts_remove,
    "iptables_setup": iptables_setup,
    "dns_redirect_enable": dns_redirect_enable,
    "dns_redirect_disable": dns_redirect_disable,
    "iptables_teardown": iptables_teardown,
    "iptables_add_ip": iptables_add_ip,
    "iptables_add_website": iptables_add_website,
    "iptables_remove_website": iptables_remove_website,
    "iptables_add_app_cgroup": iptables_add_app_cgroup,
    "iptables_remove_app_cgroup": iptables_remove_app_cgroup,
    "cgroup_create": cgroup_create,
    "cgroup_add_pid": cgroup_add_pid,
    "cgroup_remove_pid": cgroup_remove_pid,
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

    try:
        data = json.loads(args.data)
    except json.JSONDecodeError as e:
        die(f"Invalid JSON data: {e}")

    ACTION_MAP[action](data)


if __name__ == "__main__":
    main()
