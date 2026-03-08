"""
TrayManager — spawns tray_helper.py as a GTK3 subprocess and bridges events
back to the GTK4 application.
"""
import json
import logging
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable

from gi.repository import GLib

logger = logging.getLogger(__name__)

_HELPER = Path(__file__).parent / "tray_helper.py"


class TrayManager:
    def __init__(
        self,
        on_toggle: Callable[[], None],
        on_quit: Callable[[], None],
    ) -> None:
        self._on_toggle = on_toggle
        self._on_quit = on_quit
        self._proc: subprocess.Popen | None = None

    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Spawn the tray helper subprocess.  Returns True on success."""
        try:
            self._proc = subprocess.Popen(
                [sys.executable, str(_HELPER)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            logger.warning("Could not start tray helper: %s", exc)
            return False

        # Read events in a daemon thread
        t = threading.Thread(target=self._read_events, daemon=True)
        t.start()
        logger.debug("Tray helper started (pid %d)", self._proc.pid)
        return True

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._send({"cmd": "quit"})
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def set_status(self, active: bool) -> None:
        self._send({"cmd": "status", "active": active})

    # ------------------------------------------------------------------
    def _send(self, obj: dict) -> None:
        if self._proc and self._proc.poll() is None and self._proc.stdin:
            try:
                self._proc.stdin.write(json.dumps(obj) + "\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def _read_events(self) -> None:
        if not self._proc or not self._proc.stdout:
            return
        for raw in self._proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = ev.get("event")
            if event == "toggle":
                GLib.idle_add(self._on_toggle)
            elif event == "quit":
                GLib.idle_add(self._on_quit)
