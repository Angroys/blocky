import re
from typing import Optional

COMMON_SUBDOMAINS = [
    "", "www", "m", "mobile", "app", "api", "cdn", "static", "assets",
    "img", "images", "i", "v", "s", "media", "video", "old", "new",
    "beta", "preview", "dev", "staging", "secure", "auth", "login",
    "account", "accounts", "shop", "store", "mail", "help", "support",
    "docs", "blog", "news", "forum", "community",
]

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1].split("/")[0]
    return bool(_DOMAIN_RE.match(domain))


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]
    # Strip www. prefix so we store the bare domain
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def enumerate_subdomains(domain: str) -> list[str]:
    """Return a list of host entries to block for a given base domain."""
    entries = []
    for sub in COMMON_SUBDOMAINS:
        if sub:
            entries.append(f"{sub}.{domain}")
        else:
            entries.append(domain)
    return entries


def hosts_entries_for_domain(domain: str) -> list[str]:
    """Return /etc/hosts lines (0.0.0.0 and ::) for all subdomains."""
    lines = []
    for host in enumerate_subdomains(domain):
        lines.append(f"0.0.0.0 {host}")
        lines.append(f":: {host}")
    return lines
