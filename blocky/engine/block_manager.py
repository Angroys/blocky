import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import psutil

from blocky.data.categories import CATEGORIES, get_category
from blocky.db.database import Database
from blocky.engine.helper_client import HelperError, run_helper
from blocky.engine.process_watcher import ProcessWatcher
from blocky.models.block_rule import BlockRule, BlockStatus, BlockType
from blocky.scheduler.scheduler import is_schedule_in_window

logger = logging.getLogger(__name__)


class StrictScheduleError(Exception):
    """Raised when trying to deactivate/delete a rule locked by a strict schedule."""
    pass


class BlockManager:
    """
    Central orchestrator. All blocking operations go through here.

    App block modes:
      network — cgroup network isolation only
      kill    — process termination only
      strict  — cgroup isolation + kill entire process tree (recommended)
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self._on_status_change: Optional[Callable[[], None]] = None
        self._watcher = ProcessWatcher(
            on_new_pid=self._handle_new_pid,
            on_kill_pid=self._handle_kill_pid,
        )
        self._llm_scanner = None
        self._block_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="blocker")

    def set_status_callback(self, cb: Callable[[], None]) -> None:
        self._on_status_change = cb

    def _notify(self) -> None:
        if self._on_status_change:
            self._on_status_change()

    def start(self) -> None:
        try:
            run_helper("iptables_setup")
        except HelperError as e:
            logger.warning("iptables_setup failed: %s", e)
        try:
            run_helper("cgroup_create")
        except HelperError as e:
            logger.warning("cgroup_create failed: %s", e)

        # Start the local block page server (port 7878) so blocked HTTP domains
        # redirect to a friendly "Site Blocked" page instead of a connection error.
        from blocky.engine import block_page_server
        block_page_server.start()
        try:
            run_helper("iptables_redirect_http")
        except HelperError as e:
            logger.warning("iptables_redirect_http failed: %s", e)

        self._watcher.start()
        self.reload_all()
        self._restore_categories()

    def stop(self) -> None:
        self._watcher.stop()
        self.disable_llm_detection()
        from blocky.engine import block_page_server
        block_page_server.stop()

    def reload_all(self) -> None:
        self._watcher.clear_all_rules()
        rules = self.db.get_active_rules()

        # Batch all website domains into a single hosts_add_many call
        website_domains: list[str] = []
        ip_block_domains: list[str] = []
        for rule in rules:
            if rule.block_type == BlockType.WEBSITE:
                for domain in [rule.domain] + rule.extra_domains:
                    if domain:
                        website_domains.append(domain)
                if rule.block_ip_layer and rule.domain:
                    ip_block_domains.append(rule.domain)
            elif rule.block_type == BlockType.APP:
                self._apply_app(rule)

        if website_domains:
            try:
                run_helper("hosts_add_many", timeout=30, domains=website_domains)
                logger.info("Batch-restored %d website domains", len(website_domains))
            except HelperError as e:
                logger.warning("Batch hosts_add_many failed: %s — falling back to sequential", e)
                for domain in website_domains:
                    try:
                        run_helper("hosts_add", domain=domain)
                    except HelperError as e:
                        logger.error("Failed to block %s: %s", domain, e)

        # IP-layer blocking in background with concurrency
        if ip_block_domains:
            def _ip_block():
                from concurrent.futures import ThreadPoolExecutor as _Pool
                with _Pool(max_workers=20, thread_name_prefix="ip-block") as pool:
                    pool.map(self._block_domain_ips, ip_block_domains)
            threading.Thread(target=_ip_block, daemon=True, name="reload-ip-block").start()

        logger.info("Reloaded all active rules")

    def _restore_categories(self) -> None:
        """Re-apply category blocks that were active (e.g. after reboot)."""
        for cat in self.db.get_active_categories():
            cat_id = cat["category_id"]
            smart = bool(cat["smart_detect"])
            self._apply_category(cat_id, smart_detect=smart, save=False)
            logger.info("Restored category block: %s (smart=%s)", cat_id, smart)

        # Restore LLM detection if it was enabled
        if self.db.get_setting("llm_enabled", "0") == "1":
            self.enable_llm_detection()

        # Restore SNI keyword blocking if adult category was active
        if self.is_category_active("adult"):
            self.enable_sni_keyword_blocking()

    # ── Schedule lock helpers ────────────────────────────────────────────────

    def is_rule_locked(self, rule: BlockRule) -> bool:
        """True if the rule is under an active strict schedule right now."""
        if not rule.schedule_id:
            return False
        schedule = self.db.get_schedule(rule.schedule_id)
        if not schedule or not schedule.strict:
            return False
        return is_schedule_in_window(schedule)

    # ── Block rule CRUD ──────────────────────────────────────────────────────

    def activate_rule(self, rule: BlockRule) -> None:
        self._apply_rule(rule)
        rule.status = BlockStatus.ACTIVE
        self.db.set_rule_status(rule.id, BlockStatus.ACTIVE)
        self.db.log_activity(rule.id, rule.name, "activated")
        self._notify()

    def deactivate_rule(self, rule: BlockRule) -> None:
        if self.is_rule_locked(rule):
            raise StrictScheduleError(
                f"Cannot deactivate '{rule.name}' — locked by strict schedule"
            )
        self._unapply_rule(rule)
        rule.status = BlockStatus.PAUSED
        self.db.set_rule_status(rule.id, BlockStatus.PAUSED)
        self.db.log_activity(rule.id, rule.name, "paused")
        self._notify()

    def delete_rule(self, rule: BlockRule) -> None:
        if self.is_rule_locked(rule):
            raise StrictScheduleError(
                f"Cannot delete '{rule.name}' — locked by strict schedule"
            )
        self._unapply_rule(rule)
        self.db.delete_rule(rule.id)
        self.db.log_activity(rule.id, rule.name, "deleted")
        self._notify()

    def _apply_rule(self, rule: BlockRule, notify: bool = False) -> None:
        if rule.block_type == BlockType.WEBSITE:
            self._apply_website(rule)
        elif rule.block_type == BlockType.APP:
            self._apply_app(rule)
        if notify:
            self._notify()

    def _unapply_rule(self, rule: BlockRule) -> None:
        if rule.block_type == BlockType.WEBSITE:
            self._unapply_website(rule)
        elif rule.block_type == BlockType.APP:
            self._unapply_app(rule)

    # ── Website blocking ─────────────────────────────────────────────────────

    def _apply_website(self, rule: BlockRule) -> None:
        for domain in [rule.domain] + rule.extra_domains:
            if not domain:
                continue
            try:
                run_helper("hosts_add", domain=domain)
                logger.info("Blocked: %s", domain)
            except HelperError as e:
                logger.error("Failed to block %s: %s", domain, e)

        if rule.block_ip_layer and rule.domain:
            self._block_domain_ips(rule.domain)

    # Shared CDN IP ranges — blocking these would take down unrelated sites
    _SHARED_CDN_PREFIXES = (
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",  # Cloudflare
        "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
        "172.64.", "172.66.", "172.67.",  # Cloudflare
        "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",  # Cloudflare
        "185.199.",  # GitHub Pages / raw.githubusercontent.com
        "140.82.",   # GitHub
        "151.101.",  # Fastly (Reddit, npm, PyPI, etc.)
        "13.107.",   # Microsoft/Azure CDN
    )

    def _block_domain_ips(self, domain: str) -> None:
        """Resolve real IPs (bypassing /etc/hosts) and add iptables DROP rules."""
        import struct, socket as _socket
        ips = []
        for qtype, family, server in (
            (1, _socket.AF_INET, '8.8.8.8'),
            (28, _socket.AF_INET6, '2001:4860:4860::8888'),
        ):
            try:
                qname = b''.join(bytes([len(p)]) + p.encode() for p in domain.split('.')) + b'\x00'
                query = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + struct.pack('!HH', qtype, 1)
                sock = _socket.socket(family, _socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(query, (server, 53))
                data, _ = sock.recvfrom(512)
                sock.close()
                pos = 12 + len(qname) + 4
                for _ in range(struct.unpack('!H', data[6:8])[0]):
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
                        ips.append(_socket.inet_ntop(_socket.AF_INET6, data[pos:pos + 16]))
                    pos += rdlen
            except Exception:
                continue

        for ip in ips:
            if any(ip.startswith(pfx) for pfx in self._SHARED_CDN_PREFIXES):
                logger.debug("Skipping shared CDN IP %s for %s", ip, domain)
                continue
            try:
                run_helper("iptables_add_ip", ip=ip, comment=f"blocky-{domain}")
                logger.info("IP-blocked %s → %s", domain, ip)
            except HelperError as e:
                logger.warning("iptables_add_ip failed for %s: %s", ip, e)

    def _unapply_website(self, rule: BlockRule) -> None:
        for domain in [rule.domain] + rule.extra_domains:
            if not domain:
                continue
            try:
                run_helper("hosts_remove", domain=domain)
            except HelperError as e:
                logger.error("Failed to unblock %s: %s", domain, e)

        if rule.block_ip_layer and rule.domain:
            try:
                run_helper("iptables_remove_website", domain=rule.domain)
            except HelperError as e:
                logger.warning("iptables website unblock failed: %s", e)

    # ── App blocking ─────────────────────────────────────────────────────────

    def _apply_app(self, rule: BlockRule) -> None:
        mode = rule.block_mode  # "network" | "kill" | "strict"
        pname = rule.process_name or ""

        if mode in ("network", "strict"):
            try:
                run_helper("iptables_add_app_cgroup")
            except HelperError as e:
                logger.warning("cgroup iptables rule failed (kill will still apply): %s", e)

        if mode == "strict":
            self._kill_tree_for_name(pname)  # kill existing immediately
            self._watcher.add_strict_rule(rule.id, pname)  # watch for re-launches

        elif mode == "network":
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if proc.info.get("name") == pname:
                        self._handle_new_pid(proc.pid, pname)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self._watcher.add_network_rule(rule.id, pname)

        elif mode == "kill":
            self._watcher.add_kill_rule(rule.id, pname)
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if proc.info.get("name") == pname:
                        self._handle_kill_pid(proc.pid, pname)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

    def _unapply_app(self, rule: BlockRule) -> None:
        mode = rule.block_mode
        pname = rule.process_name or ""

        if mode == "strict":
            self._watcher.remove_strict_rule(pname)
        elif mode == "network":
            self._watcher.remove_network_rule(pname)
        elif mode == "kill":
            self._watcher.remove_kill_rule(pname)

        # Remove cgroup iptables rule only when no other network/strict apps remain
        if mode in ("network", "strict"):
            active = self.db.get_active_rules()
            still_active = [
                r for r in active
                if r.block_type == BlockType.APP
                and r.block_mode in ("network", "strict")
                and r.id != rule.id
            ]
            if not still_active:
                try:
                    run_helper("iptables_remove_app_cgroup")
                except HelperError as e:
                    logger.warning("Failed to remove cgroup iptables rule: %s", e)

    def _kill_tree_for_name(self, process_name: str) -> None:
        """Immediately kill all processes matching process_name and their children."""
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info.get("name") != process_name:
                    continue
                targets = [proc]
                try:
                    targets.extend(proc.children(recursive=True))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                for p in targets:
                    try:
                        self._handle_new_pid(p.pid, "")  # cgroup (best effort)
                    except Exception:
                        pass
                    try:
                        self._handle_kill_pid(p.pid, process_name)  # always kill
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ── Category blocking ────────────────────────────────────────────────────

    def activate_category(self, category_id: str, smart_detect: bool = False) -> None:
        """Block all domains in a category. Optionally enable DNS-level smart detection."""
        self._apply_category(category_id, smart_detect=smart_detect, save=True)
        if category_id == "adult":
            self.enable_sni_keyword_blocking()
        self.db.log_activity(None, f"[Category] {category_id}", "activated")
        self._notify()

    def deactivate_category(self, category_id: str) -> None:
        """Unblock all domains in a category and disable smart detection."""
        cat = get_category(category_id)
        if not cat:
            return

        domains = list(cat["domains"])
        try:
            run_helper("hosts_remove_many", timeout=30, domains=domains)
            logger.info("Category %s: batch-unblocked %d domains", category_id, len(domains))
        except HelperError:
            for domain in domains:
                try:
                    run_helper("hosts_remove", domain=domain)
                except HelperError as e:
                    logger.error("Category unblock failed for %s: %s", domain, e)

        # Disable DNS redirect if it was on for this category
        db_cat = self.db.get_category(category_id)
        if db_cat and db_cat.get("smart_detect"):
            try:
                run_helper("dns_redirect_disable")
            except HelperError as e:
                logger.warning("dns_redirect_disable failed: %s", e)

        if category_id == "adult":
            self.disable_sni_keyword_blocking()

        self.db.set_category_active(category_id, False)
        self.db.log_activity(None, f"[Category] {category_id}", "paused")
        self._notify()

    def _apply_category(
        self, category_id: str, smart_detect: bool = False, save: bool = True
    ) -> None:
        cat = get_category(category_id)
        if not cat:
            logger.warning("Unknown category: %s", category_id)
            return

        domains = list(cat["domains"])
        try:
            # Batch add — single helper call for all domains
            run_helper("hosts_add_many", timeout=30, domains=domains)
            logger.info("Category %s: batch-blocked %d domains", category_id, len(domains))
        except HelperError:
            # Fallback to one-by-one if batch not available (old helper)
            logger.info("Batch add unavailable, falling back to sequential")
            for domain in domains:
                try:
                    run_helper("hosts_add", domain=domain)
                except HelperError as e:
                    logger.error("Category block failed for %s: %s", domain, e)

        if smart_detect:
            try:
                run_helper("dns_redirect_enable")
                logger.info("DNS redirect enabled for smart adult detection")
            except HelperError as e:
                logger.warning("dns_redirect_enable failed: %s", e)

        if save:
            self.db.set_category_active(category_id, True, smart_detect)

    def is_category_active(self, category_id: str) -> bool:
        cat = self.db.get_category(category_id)
        return bool(cat and cat.get("active"))

    def is_smart_detect_active(self, category_id: str) -> bool:
        cat = self.db.get_category(category_id)
        return bool(cat and cat.get("smart_detect"))

    # ── SNI keyword blocking ─────────────────────────────────────────────────

    def enable_sni_keyword_blocking(self) -> None:
        """Block TLS connections whose SNI contains adult keywords.

        Runs in a background thread because adding 250+ iptables rules
        takes several seconds.
        """
        def _apply():
            from blocky.llm.keyword_filter import get_sni_keywords

            keywords = get_sni_keywords()

            # Also extract base names from blocked website rules for variant blocking.
            # e.g. if xhamster.com is blocked, add "xhamster" so xhamster.desi is also caught.
            for rule in self.db.get_all_rules():
                if rule.block_type == BlockType.WEBSITE and rule.domain:
                    base = rule.domain.split(".")[0]
                    if len(base) >= 4 and base not in keywords:
                        keywords.append(base)

            keywords = sorted(set(keywords))
            try:
                run_helper("sni_block_all_keywords", timeout=120, keywords=keywords)
                logger.info("SNI keyword blocking enabled (%d keywords)", len(keywords))
            except HelperError as e:
                logger.error("SNI keyword blocking failed: %s", e)

        threading.Thread(target=_apply, daemon=True, name="sni-keywords").start()

    def disable_sni_keyword_blocking(self) -> None:
        """Remove all SNI keyword iptables rules."""
        try:
            run_helper("sni_unblock_all_keywords")
            logger.info("SNI keyword blocking disabled")
        except HelperError as e:
            logger.error("Failed to disable SNI keyword blocking: %s", e)

    # ── LLM content detection ────────────────────────────────────────────────

    def enable_llm_detection(self) -> None:
        """Start the LLM background scanner."""
        if self._llm_scanner and self._llm_scanner.is_alive():
            logger.debug("LLM scanner already running")
            return

        provider_name = self.db.get_setting("llm_provider", "anthropic") or "anthropic"
        api_key = self.db.get_setting("llm_api_key", "") or ""
        threshold = float(self.db.get_setting("llm_confidence_threshold", "0.85") or "0.85")
        prescan_limit = int(self.db.get_setting("llm_prescan_limit", "5") or "5")

        # Image scanner settings
        image_enabled = self.db.get_setting("nsfw_image_scan_enabled", "0") == "1"
        image_threshold = float(self.db.get_setting("nsfw_image_threshold", "0.75") or "0.75")
        image_max = int(self.db.get_setting("nsfw_image_max_per_page", "5") or "5")

        # Build LLM agent if API key is available
        agent = None
        if api_key:
            from blocky.llm.providers import get_provider
            from blocky.llm.models import make_agent

            provider = get_provider(provider_name)
            if provider:
                try:
                    agent = make_agent(provider_name, provider.model_id, api_key, provider.base_url)
                except Exception as e:
                    logger.error("LLM detection: failed to create agent: %s", e)

        # Need at least one detection method
        if not agent and not image_enabled:
            logger.warning("LLM detection: no API key and image scanner disabled — nothing to do")
            return

        from blocky.llm.scanner import DomainScanner

        self._llm_scanner = DomainScanner(
            db=self.db,
            agent=agent,
            provider_name=provider_name,
            confidence_threshold=threshold,
            on_adult=self._auto_block_domain,
            prescan_limit=prescan_limit,
            image_scanner_enabled=image_enabled,
            image_confidence_threshold=image_threshold,
            image_max_per_page=image_max,
        )
        self._llm_scanner.start()
        logger.info(
            "LLM detection enabled (provider=%s, threshold=%.2f, image=%s)",
            provider_name, threshold, image_enabled,
        )

    def disable_llm_detection(self) -> None:
        """Stop the LLM background scanner."""
        if self._llm_scanner:
            self._llm_scanner.stop()
            self._llm_scanner = None
            logger.info("LLM detection disabled")

    def is_llm_detection_active(self) -> bool:
        return self._llm_scanner is not None and self._llm_scanner.is_alive()

    def restart_llm_detection(self) -> None:
        """Restart the scanner with current DB settings (call after changing provider/key/threshold)."""
        if self.is_llm_detection_active():
            self.disable_llm_detection()
            self.enable_llm_detection()

    # Domains that must never be auto-blocked by the scanner.
    # These are critical infrastructure / developer resources.
    _NEVER_BLOCK = frozenset({
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "github.com",
        "api.github.com",
        "gist.githubusercontent.com",
        "camo.githubusercontent.com",
        "avatars.githubusercontent.com",
    })

    def _auto_block_domain(self, domain: str, reason: str, ip: str | None = None) -> None:
        """Called by scanner when a domain is classified as adult.

        Fast path (synchronous): DB write + immediate IP reject.
        Slow path (async via thread pool): hosts_add, DNS resolution,
        iptables IP blocking, SNI keyword, browser refresh.
        """
        from datetime import datetime as _dt
        from gi.repository import GLib

        # Never block critical infrastructure domains
        if domain in self._NEVER_BLOCK:
            logger.info("Skipping auto-block for protected domain: %s", domain)
            return

        # Guard: check not already blocked
        for rule in self.db.get_all_rules():
            if rule.domain == domain:
                return

        # ── Fast path: immediate IP reject + DB write ─────────────────────
        if ip:
            try:
                run_helper("iptables_add_ip", ip=ip, comment=f"blocky-{domain}")
                logger.info("Dropped live connection to %s (%s)", ip, domain)
            except HelperError as e:
                logger.warning("iptables_add_ip failed for %s: %s", ip, e)

        rule = BlockRule(
            name=domain,
            block_type=BlockType.WEBSITE,
            domain=domain,
            block_ip_layer=True,
            status=BlockStatus.ACTIVE,
            created_at=_dt.now(),
        )
        rule_id = self.db.add_rule(rule)
        rule.id = rule_id
        self.db.log_activity(rule_id, domain, f"LLM auto-blocked: {reason}")

        # ── Slow path: dispatch to thread pool ────────────────────────────
        self._block_pool.submit(self._finalize_block, rule, domain, reason, ip)
        GLib.idle_add(self._notify)

    def _finalize_block(self, rule: BlockRule, domain: str, reason: str, ip: str | None) -> None:
        """Heavy blocking work — runs in thread pool, not on scanner thread."""
        from gi.repository import GLib

        # 1. /etc/hosts + resolve all IPs + iptables
        self._apply_website(rule)

        # 2. Browser refresh (kill socket + F5)
        if ip:
            self._force_browser_refresh(domain, ip)

        # 3. SNI keyword for variant TLD blocking
        base = domain.split(".")[0]
        if len(base) >= 4 and self.is_category_active("adult"):
            try:
                run_helper("sni_block_keyword", keyword=base)
                logger.info("SNI keyword added for variant blocking: %s", base)
            except HelperError:
                pass

        GLib.idle_add(self._notify)

    def _force_browser_refresh(self, domain: str, ip: str) -> None:
        """
        After blocking a domain:
          1. ss --kill  — force-closes the kernel TCP socket (sends RST to
             both sides so the browser tab shows an error immediately).
          2. xdotool    — finds browser windows whose title contains the
             domain name and sends F5, triggering a reload.  On reload the
             domain resolves to 127.0.0.1 (via /etc/hosts) and our block-page
             server responds with the "Site Blocked" page.
        Runs in a daemon thread so it never blocks the main flow.
        """
        import shutil
        import subprocess

        # ── 1. Kill TCP socket immediately ────────────────────────────────────
        try:
            run_helper("kill_connections", ip=ip)
            logger.info("Force-closed TCP connections to %s (%s)", ip, domain)
        except Exception as e:
            logger.debug("kill_connections failed for %s: %s", ip, e)

        # ── 2. Trigger browser refresh via xdotool (X11/XWayland) ────────────
        if not shutil.which("xdotool"):
            return
        try:
            # Search windows whose title contains the apex domain
            result = subprocess.run(
                ["xdotool", "search", "--name", domain],
                capture_output=True, text=True, timeout=3,
            )
            wids = result.stdout.strip().split()
            for wid in wids[:10]:
                # Send F5 to refresh — browser will reload and hit our block page
                subprocess.run(
                    ["xdotool", "key", "--window", wid, "F5"],
                    capture_output=True, timeout=2,
                )
                logger.info("Sent F5 to browser window %s (blocked domain: %s)", wid, domain)
        except Exception as e:
            logger.debug("xdotool refresh failed for %s: %s", domain, e)

    def _kill_browser_tabs_for_ip(self, ip: str) -> None:
        """
        Find processes with an open TCP socket to *ip* and SIGTERM them.

        For Chromium/Brave/Vivaldi each tab runs as a separate renderer
        subprocess — terminating it closes only that tab (shows 'Aw, Snap!').
        For Firefox the web-content process for that tab is terminated.
        Other tabs and the browser chrome remain untouched.
        """
        import glob
        import os
        import socket as _sock

        # Convert dotted-decimal IPv4 → 8-char little-endian hex (for /proc/net/tcp)
        try:
            packed = _sock.inet_aton(ip)
            hex_ip = packed[::-1].hex().upper()
        except OSError:
            return  # IPv6 or invalid — skip for now

        # ── 1. Find socket inodes for ESTABLISHED connections to this IP ──────
        inodes: set[str] = set()
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as fh:
                    next(fh)  # skip header
                    for line in fh:
                        cols = line.split()
                        if len(cols) < 10:
                            continue
                        if cols[3] != "01":  # 01 = ESTABLISHED
                            continue
                        remote_hex = cols[2].split(":")[0].upper()
                        if hex_ip in remote_hex:
                            inodes.add(cols[9])
            except OSError:
                pass

        if not inodes:
            return

        # ── 2. Walk /proc/PID/fd to find which PIDs own those inodes ─────────
        pids: set[int] = set()
        for fd_path in glob.iglob("/proc/*/fd/*"):
            try:
                target = os.readlink(fd_path)
                if target.startswith("socket:["):
                    inode = target[8:-1]
                    if inode in inodes:
                        pids.add(int(fd_path.split("/")[2]))
            except (OSError, ValueError):
                pass

        # ── 3. SIGTERM each matching process ──────────────────────────────────
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                proc.terminate()
                logger.info(
                    "Closed browser tab: terminated process %d (%s) connected to %s",
                    pid, name, ip,
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    # ── Process event handlers ───────────────────────────────────────────────

    def _handle_new_pid(self, pid: int, exe: str) -> None:
        try:
            run_helper("cgroup_add_pid", pid=pid)
            logger.info("Added PID %d (%s) to blocked cgroup", pid, exe)
        except HelperError as e:
            logger.warning("cgroup_add_pid failed for PID %d: %s", pid, e)

    def _handle_kill_pid(self, pid: int, exe: str) -> None:
        try:
            proc = psutil.Process(pid)
            proc.kill()  # SIGKILL — no grace period in strict mode
            logger.info("Killed process %d (%s)", pid, exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug("Could not kill PID %d: %s", pid, e)
