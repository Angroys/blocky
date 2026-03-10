import subprocess
import threading
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from blocky.engine.helper_client import HELPER_PATH, is_helper_available
from blocky.llm.providers import PROVIDER_ORDER, PROVIDERS


class SettingsPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()

    def _build_ui(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

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

        # ── Appearance group ─────────────────────────────
        appearance_group = Adw.PreferencesGroup()
        appearance_group.set_title("Appearance")

        theme_row = Adw.ActionRow()
        theme_row.set_title("Theme")
        theme_row.set_subtitle("Switch between Neo-Tactile dark and Soft Neumorphic light themes")
        theme_strings = Gtk.StringList.new(["Neo-Tactile Dark", "Soft Neumorphic"])
        theme_combo = Gtk.DropDown(model=theme_strings)
        theme_combo.set_valign(Gtk.Align.CENTER)
        current_theme = (db.get_setting("ui_theme", "dark") or "dark") if db else "dark"
        theme_combo.set_selected(1 if current_theme == "light" else 0)
        theme_combo.connect("notify::selected", self._on_theme_changed)
        theme_row.add_suffix(theme_combo)
        self._theme_combo = theme_combo
        appearance_group.add(theme_row)

        prefs.add(appearance_group)

        # ── LLM Content Detection group ──────────────────
        llm_group = Adw.PreferencesGroup()
        llm_group.set_title("LLM Content Detection")
        llm_group.set_description(
            "Experimental: AI analyzes live web traffic to auto-block adult domains. "
            "Requires an API key from your chosen provider."
        )

        # Provider picker
        display_names = [PROVIDERS[p].display_name for p in PROVIDER_ORDER]
        provider_strings = Gtk.StringList.new(display_names)
        provider_row = Adw.ComboRow()
        provider_row.set_title("Provider")
        provider_row.set_subtitle("AI provider for content classification")
        provider_row.set_model(provider_strings)

        current_provider = (db.get_setting("llm_provider", "anthropic") or "anthropic") if db else "anthropic"
        selected_idx = PROVIDER_ORDER.index(current_provider) if current_provider in PROVIDER_ORDER else 0
        provider_row.set_selected(selected_idx)
        provider_row.connect("notify::selected", self._on_provider_changed)
        llm_group.add(provider_row)
        self._provider_row = provider_row

        # API Key
        api_key_row = Adw.PasswordEntryRow()
        api_key_row.set_title("API Key")
        if db:
            api_key_row.set_text(db.get_setting("llm_api_key", "") or "")
        api_key_row.connect("changed", self._on_api_key_changed)
        llm_group.add(api_key_row)
        self._api_key_row = api_key_row

        # Confidence threshold
        adj = Gtk.Adjustment.new(0.85, 0.70, 1.00, 0.05, 0.10, 0)
        threshold_row = Adw.SpinRow.new(adj, 0.05, 2)
        threshold_row.set_title("Confidence Threshold")
        threshold_row.set_subtitle("Minimum AI confidence to auto-block (0.70–1.00)")
        threshold_val = float((db.get_setting("llm_confidence_threshold", "0.85") or "0.85")) if db else 0.85
        threshold_row.set_value(threshold_val)
        threshold_row.connect("notify::value", self._on_threshold_changed)
        llm_group.add(threshold_row)
        self._threshold_row = threshold_row

        # Pre-scan unlimited toggle (default: limited to 5)
        prescan_row = Adw.ActionRow()
        prescan_row.set_title("Unlimited pre-scan")
        prescan_row.set_subtitle("Scan all linked domains per page (uses more API quota)")
        prescan_switch = Gtk.Switch()
        prescan_switch.set_valign(Gtk.Align.CENTER)
        unlimited = (db.get_setting("llm_prescan_limit", "5") or "5") == "0" if db else False
        prescan_switch.set_active(unlimited)
        prescan_switch.connect("state-set", self._on_prescan_limit_toggle)
        prescan_row.add_suffix(prescan_switch)
        llm_group.add(prescan_row)

        # Clear AI cache
        cache_row = Adw.ActionRow()
        cache_row.set_title("Clear AI cache")
        cache_row.set_subtitle("Force re-classification of all previously scanned domains")
        clear_btn = Gtk.Button(label="Clear")
        clear_btn.set_valign(Gtk.Align.CENTER)
        clear_btn.add_css_class("destructive-action")
        clear_btn.connect("clicked", self._on_clear_llm_cache)
        cache_row.add_suffix(clear_btn)
        llm_group.add(cache_row)

        # Test connection button
        test_row = Adw.ActionRow()
        test_row.set_title("Test Connection")
        test_row.set_subtitle("Classify a benign text snippet to verify the API key works")
        test_btn = Gtk.Button(label="Test")
        test_btn.set_valign(Gtk.Align.CENTER)
        test_btn.add_css_class("suggested-action")
        test_btn.connect("clicked", self._on_test_llm)
        test_row.add_suffix(test_btn)
        llm_group.add(test_row)

        prefs.add(llm_group)

        # ── Local Image Detection group ───────────────────
        img_group = Adw.PreferencesGroup()
        img_group.set_title("Local Image Detection")
        img_group.set_description(
            "NSFW image classifier using a local ONNX model (~10 MB). "
            "No API key required — runs entirely on CPU."
        )

        img_enable_row = Adw.ActionRow()
        img_enable_row.set_title("Enable image scanning")
        img_enable_row.set_subtitle("Download and classify images from visited pages")
        img_enable_switch = Gtk.Switch()
        img_enable_switch.set_valign(Gtk.Align.CENTER)
        if db:
            img_enable_switch.set_active(db.get_setting("nsfw_image_scan_enabled", "0") == "1")
        img_enable_switch.connect("state-set", self._on_image_scan_toggle)
        img_enable_row.add_suffix(img_enable_switch)
        img_group.add(img_enable_row)

        img_thresh_adj = Gtk.Adjustment.new(0.75, 0.50, 1.00, 0.05, 0.10, 0)
        img_thresh_row = Adw.SpinRow.new(img_thresh_adj, 0.05, 2)
        img_thresh_row.set_title("Image Confidence Threshold")
        img_thresh_row.set_subtitle("Minimum NSFW score to trigger blocking (0.50–1.00)")
        img_thresh_val = float((db.get_setting("nsfw_image_threshold", "0.75") or "0.75")) if db else 0.75
        img_thresh_row.set_value(img_thresh_val)
        img_thresh_row.connect("notify::value", self._on_image_threshold_changed)
        img_group.add(img_thresh_row)

        img_max_adj = Gtk.Adjustment.new(5, 1, 20, 1, 5, 0)
        img_max_row = Adw.SpinRow.new(img_max_adj, 1, 0)
        img_max_row.set_title("Max images per page")
        img_max_row.set_subtitle("Number of images to download and classify per page")
        img_max_val = int((db.get_setting("nsfw_image_max_per_page", "5") or "5")) if db else 5
        img_max_row.set_value(img_max_val)
        img_max_row.connect("notify::value", self._on_image_max_changed)
        img_group.add(img_max_row)

        img_model_row = Adw.ActionRow()
        img_model_row.set_title("NSFW model")
        img_model_row.set_subtitle("MobileNet v2 — downloaded on first use to ~/.local/share/blocky/models/")
        from blocky.llm.image_scanner import MODEL_PATH
        if MODEL_PATH.exists():
            size_mb = MODEL_PATH.stat().st_size // (1024 * 1024)
            model_status = Gtk.Label(label=f"Ready ({size_mb} MB)")
            model_status.add_css_class("success")
        else:
            model_status = Gtk.Label(label="Not downloaded")
            model_status.add_css_class("muted")
        model_status.set_valign(Gtk.Align.CENTER)
        img_model_row.add_suffix(model_status)
        img_group.add(img_model_row)

        prefs.add(img_group)

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
        self._show_install_auth_dialog(install_sh)

    def _show_install_auth_dialog(self, install_sh: Path) -> None:
        """Show a password prompt dialog and run the installer via sudo -S."""
        dialog = Adw.AlertDialog()
        dialog.set_heading("Install Helper")
        dialog.set_body(
            "Enter your sudo password to install the Blocky helper script.\n"
            "This copies blocky-apply.py to /usr/local/lib/blocky/ and adds a sudoers entry."
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("install", "Install")
        dialog.set_response_appearance("install", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("install")
        dialog.set_close_response("cancel")

        pw_entry = Gtk.PasswordEntry()
        pw_entry.set_show_peek_icon(True)
        pw_entry.set_hexpand(True)
        pw_entry.set_property("placeholder-text", "Password")
        dialog.set_extra_child(pw_entry)

        def on_response(d, response_id):
            if response_id != "install":
                return
            password = pw_entry.get_text()
            self.window.show_toast("Installing…")
            threading.Thread(
                target=self._do_install,
                args=(install_sh, password),
                daemon=True,
            ).start()

        dialog.connect("response", on_response)
        dialog.present(self.window)

    def _do_install(self, install_sh: Path, password: str) -> None:
        import shutil
        from gi.repository import GLib

        # Try pkexec first (no password needed — polkit shows its own dialog)
        if shutil.which("pkexec"):
            try:
                result = subprocess.run(
                    ["pkexec", "bash", str(install_sh)],
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    GLib.idle_add(self.window.show_toast, "Helper installed successfully")
                    return
                # pkexec cancelled or denied — fall through to sudo -S
            except Exception:
                pass

        # Fallback: sudo -S with password piped to stdin
        try:
            result = subprocess.run(
                ["sudo", "-S", "bash", str(install_sh)],
                input=password + "\n",
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                GLib.idle_add(self.window.show_toast, "Helper installed successfully")
            else:
                err = (result.stderr or "unknown error").strip().splitlines()[-1]
                GLib.idle_add(self.window.show_toast, f"Install failed: {err}")
        except subprocess.TimeoutExpired:
            GLib.idle_add(self.window.show_toast, "Install timed out")
        except Exception as e:
            GLib.idle_add(self.window.show_toast, f"Install error: {e}")

    def _on_deep_block_toggle(self, switch, state) -> bool:
        db = self.window.get_db()
        if db:
            db.set_setting("deep_block_default", "1" if state else "0")
        return False

    def _on_theme_changed(self, combo, _param) -> None:
        theme = "light" if combo.get_selected() == 1 else "dark"
        app = self.window.get_application()
        if app and hasattr(app, "apply_theme"):
            app.apply_theme(theme)

    def _on_provider_changed(self, combo_row, _param) -> None:
        db = self.window.get_db()
        if not db:
            return
        idx = combo_row.get_selected()
        if not (0 <= idx < len(PROVIDER_ORDER)):
            return
        provider_name = PROVIDER_ORDER[idx]
        db.set_setting("llm_provider", provider_name)
        # Prompt for the API key for the newly chosen provider
        self._show_api_key_dialog(provider_name)
        self._restart_scanner()

    def _show_api_key_dialog(self, provider_name: str) -> None:
        """Show a dialog prompting the user to paste an API key for the chosen provider."""
        provider_cfg = PROVIDERS.get(provider_name)
        display_name = provider_cfg.display_name if provider_cfg else provider_name.capitalize()

        dialog = Adw.AlertDialog()
        dialog.set_heading(f"Enter {display_name} API Key")
        dialog.set_body(
            f"Paste your {display_name} API key below.\n"
            "It will be stored locally in the Blocky database."
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.set_close_response("cancel")

        entry = Gtk.Entry()
        entry.set_placeholder_text("Paste your API key here…")
        entry.set_visibility(True)
        entry.set_hexpand(True)

        # Pre-fill existing key if any
        db = self.window.get_db()
        if db:
            existing = db.get_setting("llm_api_key", "") or ""
            if existing:
                entry.set_text(existing)

        dialog.set_extra_child(entry)

        def on_response(d, response_id):
            if response_id == "save":
                key = entry.get_text().strip()
                if key and db:
                    db.set_setting("llm_api_key", key)
                    # Sync to the visible PasswordEntryRow
                    self._api_key_row.set_text(key)
                    self.window.show_toast(f"{display_name} API key saved")

        dialog.connect("response", on_response)
        dialog.present(self.window)

    def _on_api_key_changed(self, entry_row) -> None:
        db = self.window.get_db()
        if db:
            db.set_setting("llm_api_key", entry_row.get_text().strip())
        # Don't restart on every keystroke — scanner picks up new key on next restart

    def _on_threshold_changed(self, spin_row, _param) -> None:
        db = self.window.get_db()
        if db:
            db.set_setting("llm_confidence_threshold", f"{spin_row.get_value():.2f}")
        self._restart_scanner()

    def _on_clear_llm_cache(self, *_) -> None:
        db = self.window.get_db()
        if not db:
            return
        n = db.clear_llm_cache()
        bm = self.window.get_block_manager()
        if bm and bm.is_llm_detection_active():
            bm._llm_scanner._seen_pairs.clear()
            bm._llm_scanner._links_extracted.clear()
        self.window.show_toast(f"Cleared {n} cached classifications — re-scanning now")

    def _on_prescan_limit_toggle(self, switch, state) -> bool:
        db = self.window.get_db()
        if db:
            # state=True → unlimited (0), state=False → limited (5)
            db.set_setting("llm_prescan_limit", "0" if state else "5")
        self._restart_scanner()
        return False

    def _on_image_scan_toggle(self, switch, state) -> bool:
        db = self.window.get_db()
        if db:
            db.set_setting("nsfw_image_scan_enabled", "1" if state else "0")
        self._restart_scanner()
        return False

    def _on_image_threshold_changed(self, spin_row, _param) -> None:
        db = self.window.get_db()
        if db:
            db.set_setting("nsfw_image_threshold", f"{spin_row.get_value():.2f}")
        self._restart_scanner()

    def _on_image_max_changed(self, spin_row, _param) -> None:
        db = self.window.get_db()
        if db:
            db.set_setting("nsfw_image_max_per_page", str(int(spin_row.get_value())))
        self._restart_scanner()

    def _restart_scanner(self) -> None:
        bm = self.window.get_block_manager()
        if bm:
            bm.restart_llm_detection()

    def _on_test_llm(self, *_) -> None:
        db = self.window.get_db()
        if not db:
            self.window.show_toast("Database not available")
            return

        idx = self._provider_row.get_selected()
        if not (0 <= idx < len(PROVIDER_ORDER)):
            return
        provider_name = PROVIDER_ORDER[idx]
        api_key = self._api_key_row.get_text().strip()

        if not api_key:
            self.window.show_toast("Enter an API key first")
            return

        self.window.show_toast("Testing LLM connection…")

        def _run() -> None:
            try:
                from blocky.llm.providers import get_provider
                from blocky.llm.models import make_agent
                import asyncio

                provider = get_provider(provider_name)
                if not provider:
                    GLib.idle_add(self.window.show_toast, f"Unknown provider: {provider_name}")
                    return

                agent = make_agent(provider_name, provider.model_id, api_key, provider.base_url)

                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(
                        agent.run(
                            "This page contains cooking recipes for pasta and vegetable dishes."
                        )
                    )
                finally:
                    loop.close()

                cls = result.output
                GLib.idle_add(
                    self.window.show_toast,
                    f"OK — is_adult={cls.is_adult}, confidence={cls.confidence:.2f}",
                )
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Test failed: {e}")

        threading.Thread(target=_run, daemon=True).start()
