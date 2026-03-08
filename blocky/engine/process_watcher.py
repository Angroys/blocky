import logging
import threading
import time
from typing import Callable

import psutil

logger = logging.getLogger(__name__)


class ProcessWatcher(threading.Thread):
    """
    Background thread that monitors running processes and enforces app block rules.

    Matching strategy: process name is the primary key (e.g. "zen-bin").
    exe_path is optional and used as a fallback/supplement.

    Block modes:
      network — add process PIDs to blocked cgroup (internet denied)
      kill    — terminate the process
      strict  — kill entire process tree + add all PIDs to cgroup
    """

    def __init__(
        self,
        on_new_pid: Callable[[int, str], None],
        on_kill_pid: Callable[[int, str], None],
    ) -> None:
        super().__init__(daemon=True, name="ProcessWatcher")
        self._on_new_pid = on_new_pid
        self._on_kill_pid = on_kill_pid
        self._lock = threading.Lock()

        # process_name -> rule_id  (primary key for all modes)
        self._network_names: dict[str, int] = {}
        self._kill_names: dict[str, int] = {}
        self._strict_names: dict[str, int] = {}

        self._known_pids: set[int] = set()
        self._running = False

    # ── Rule registration ────────────────────────────────────────────────────

    def add_network_rule(self, rule_id: int, process_name: str) -> None:
        with self._lock:
            self._network_names[process_name] = rule_id

    def remove_network_rule(self, process_name: str) -> None:
        with self._lock:
            self._network_names.pop(process_name, None)

    def add_kill_rule(self, rule_id: int, process_name: str) -> None:
        with self._lock:
            self._kill_names[process_name] = rule_id

    def remove_kill_rule(self, process_name: str) -> None:
        with self._lock:
            self._kill_names.pop(process_name, None)

    def add_strict_rule(self, rule_id: int, process_name: str) -> None:
        """Strict = kill entire process tree + cgroup, matched by name."""
        with self._lock:
            self._strict_names[process_name] = rule_id

    def remove_strict_rule(self, process_name: str) -> None:
        with self._lock:
            self._strict_names.pop(process_name, None)

    def clear_all_rules(self) -> None:
        with self._lock:
            self._network_names.clear()
            self._kill_names.clear()
            self._strict_names.clear()
            self._known_pids.clear()

    def stop(self) -> None:
        self._running = False

    # ── Thread main loop ─────────────────────────────────────────────────────

    def run(self) -> None:
        self._running = True
        while self._running:
            try:
                self._scan()
            except Exception as e:
                logger.warning("ProcessWatcher scan error: %s", e)
            with self._lock:
                has_strict = bool(self._strict_names)
            time.sleep(1 if has_strict else 2)

    def _scan(self) -> None:
        with self._lock:
            network_names = dict(self._network_names)
            kill_names = dict(self._kill_names)
            strict_names = dict(self._strict_names)

        if not network_names and not kill_names and not strict_names:
            return

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info.get("name") or ""
                pid = proc.info["pid"]

                # Network mode: add to blocked cgroup
                if name in network_names and pid not in self._known_pids:
                    self._known_pids.add(pid)
                    try:
                        self._on_new_pid(pid, name)
                    except Exception as e:
                        logger.warning("Failed to cgroup PID %d (%s): %s", pid, name, e)

                # Kill mode: terminate
                if name in kill_names:
                    try:
                        self._on_kill_pid(pid, name)
                    except Exception as e:
                        logger.debug("Failed to kill PID %d (%s): %s", pid, name, e)

                # Strict mode: kill tree + cgroup
                if name in strict_names:
                    self._enforce_strict(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Clean up dead PIDs
        dead = {p for p in self._known_pids if not psutil.pid_exists(p)}
        self._known_pids -= dead

    def _enforce_strict(self, proc: psutil.Process) -> None:
        """Kill the entire process tree and add all PIDs to blocked cgroup."""
        try:
            targets = [proc]
            try:
                targets.extend(proc.children(recursive=True))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            for p in targets:
                pid = p.pid
                if pid not in self._known_pids:
                    self._known_pids.add(pid)
                    try:
                        self._on_new_pid(pid, "")
                    except Exception:
                        pass
                try:
                    self._on_kill_pid(pid, "")
                except Exception:
                    pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
