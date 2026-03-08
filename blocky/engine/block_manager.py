import logging
from typing import Callable, Optional

import psutil

from blocky.data.categories import CATEGORIES, get_category
from blocky.db.database import Database
from blocky.engine.helper_client import HelperError, run_helper
from blocky.engine.process_watcher import ProcessWatcher
from blocky.models.block_rule import BlockRule, BlockStatus, BlockType

logger = logging.getLogger(__name__)


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

        self._watcher.start()
        self.reload_all()
        self._restore_categories()

    def stop(self) -> None:
        self._watcher.stop()

    def reload_all(self) -> None:
        self._watcher.clear_all_rules()
        for rule in self.db.get_active_rules():
            self._apply_rule(rule, notify=False)
        logger.info("Reloaded all active rules")

    def _restore_categories(self) -> None:
        """Re-apply category blocks that were active (e.g. after reboot)."""
        for cat in self.db.get_active_categories():
            cat_id = cat["category_id"]
            smart = bool(cat["smart_detect"])
            self._apply_category(cat_id, smart_detect=smart, save=False)
            logger.info("Restored category block: %s (smart=%s)", cat_id, smart)

    # ── Block rule CRUD ──────────────────────────────────────────────────────

    def activate_rule(self, rule: BlockRule) -> None:
        self._apply_rule(rule)
        rule.status = BlockStatus.ACTIVE
        self.db.set_rule_status(rule.id, BlockStatus.ACTIVE)
        self.db.log_activity(rule.id, rule.name, "activated")
        self._notify()

    def deactivate_rule(self, rule: BlockRule) -> None:
        self._unapply_rule(rule)
        rule.status = BlockStatus.PAUSED
        self.db.set_rule_status(rule.id, BlockStatus.PAUSED)
        self.db.log_activity(rule.id, rule.name, "paused")
        self._notify()

    def delete_rule(self, rule: BlockRule) -> None:
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
        self.db.log_activity(None, f"[Category] {category_id}", "activated")
        self._notify()

    def deactivate_category(self, category_id: str) -> None:
        """Unblock all domains in a category and disable smart detection."""
        cat = get_category(category_id)
        if not cat:
            return

        for domain in cat["domains"]:
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

        for domain in cat["domains"]:
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
