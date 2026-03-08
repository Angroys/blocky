#!/usr/bin/env python3
"""
Standalone GTK3 tray icon subprocess.
Communicates with parent via JSON lines on stdin/stdout.

Parent → child (stdin):
  {"cmd": "quit"}
  {"cmd": "status", "active": true}

Child → parent (stdout):
  {"event": "toggle"}   — user clicked Show/Hide
  {"event": "quit"}     — user chose Quit from menu
"""
import json
import signal
import sys
import threading

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3, GLib, Gtk  # noqa: E402

APP_ID = "io.github.blocky"
ICON_ACTIVE   = "security-high-symbolic"
ICON_INACTIVE = "security-low-symbolic"


def _send(obj: dict) -> None:
    print(json.dumps(obj), flush=True)


def main() -> None:
    indicator = AyatanaAppIndicator3.Indicator.new(
        APP_ID,
        ICON_ACTIVE,
        AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS,
    )
    indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
    indicator.set_title("Blocky")

    # ---- menu ----
    menu = Gtk.Menu()

    item_show = Gtk.MenuItem(label="Show / Hide Blocky")
    item_show.connect("activate", lambda _: _send({"event": "toggle"}))
    menu.append(item_show)

    menu.append(Gtk.SeparatorMenuItem())

    item_quit = Gtk.MenuItem(label="Quit Blocky")
    def _do_quit(_):
        _send({"event": "quit"})
        Gtk.main_quit()
    item_quit.connect("activate", _do_quit)
    menu.append(item_quit)

    menu.show_all()
    indicator.set_menu(menu)

    # ---- read commands from parent on a daemon thread ----
    def _read_stdin() -> None:
        for raw in sys.stdin:
            line = raw.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError:
                continue
            if cmd.get("cmd") == "quit":
                GLib.idle_add(Gtk.main_quit)
                break
            elif cmd.get("cmd") == "status":
                icon = ICON_ACTIVE if cmd.get("active", True) else ICON_INACTIVE
                GLib.idle_add(indicator.set_icon_full, icon, "Blocky")

    t = threading.Thread(target=_read_stdin, daemon=True)
    t.start()

    # Exit cleanly when parent dies
    signal.signal(signal.SIGTERM, lambda *_: Gtk.main_quit())
    signal.signal(signal.SIGINT,  lambda *_: Gtk.main_quit())

    Gtk.main()


if __name__ == "__main__":
    main()
