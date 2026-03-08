import subprocess
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from blocky.engine.helper_client import HELPER_PATH, is_helper_available


class SettingsPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()

    def _build_ui(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        prefs = Adw.PreferencesPage()

        # ── Permissions group ────────────────────────────
        perm_group = Adw.PreferencesGroup()
        perm_group.set_title("Permissions")
        perm_group.set_description(
            "Blocky requires a privileged helper script to modify /etc/hosts and iptables."
        )

        helper_row = Adw.ActionRow()
        helper_row.set_title("Helper script")
        helper_row.set_subtitle(HELPER_PATH)

        status_icon = "emblem-ok-symbolic" if is_helper_available() else "dialog-error-symbolic"
        status_img = Gtk.Image.new_from_icon_name(status_icon)
        helper_row.add_suffix(status_img)
        perm_group.add(helper_row)

        install_row = Adw.ActionRow()
        install_row.set_title("Install helper")
        install_row.set_subtitle("Run install.sh to set up the privileged helper and sudoers drop-in")
        install_btn = Gtk.Button(label="Install...")
        install_btn.set_valign(Gtk.Align.CENTER)
        install_btn.add_css_class("suggested-action")
        install_btn.connect("clicked", self._run_installer)
        install_row.add_suffix(install_btn)
        perm_group.add(install_row)

        prefs.add(perm_group)

        # ── Blocking group ───────────────────────────────
        block_group = Adw.PreferencesGroup()
        block_group.set_title("Blocking")

        ip_row = Adw.ActionRow()
        ip_row.set_title("Deep block by default")
        ip_row.set_subtitle("Also add iptables IP rules when blocking websites")
        ip_switch = Gtk.Switch()
        ip_switch.set_valign(Gtk.Align.CENTER)
        db = self.window.get_db()
        if db:
            ip_switch.set_active(db.get_setting("deep_block_default", "0") == "1")
        ip_switch.connect("state-set", self._on_deep_block_toggle)
        ip_row.add_suffix(ip_switch)
        block_group.add(ip_row)

        prefs.add(block_group)

        # ── About group ──────────────────────────────────
        about_group = Adw.PreferencesGroup()
        about_group.set_title("About")

        version_row = Adw.ActionRow()
        version_row.set_title("Blocky")
        version_row.set_subtitle("v0.1.0 — App and website blocker for Linux")
        about_group.add(version_row)

        data_row = Adw.ActionRow()
        data_row.set_title("Data directory")
        from blocky.db.database import DB_PATH
        data_row.set_subtitle(str(DB_PATH))
        about_group.add(data_row)

        prefs.add(about_group)

        scroll.set_child(prefs)
        self.append(scroll)

    def refresh(self) -> None:
        pass

    def _run_installer(self, *_) -> None:
        install_sh = Path(__file__).parents[3] / "install.sh"
        if not install_sh.exists():
            self.window.show_toast("install.sh not found")
            return
        try:
            subprocess.Popen(["bash", str(install_sh)], start_new_session=True)
            self.window.show_toast("Installer launched in terminal")
        except Exception as e:
            self.window.show_toast(f"Failed to launch installer: {e}")

    def _on_deep_block_toggle(self, switch, state) -> bool:
        db = self.window.get_db()
        if db:
            db.set_setting("deep_block_default", "1" if state else "0")
        return False
