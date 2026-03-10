import threading

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from blocky.data.categories import CATEGORIES, CATEGORY_COLORS


class CategoriesPage(Gtk.Box):
    """
    One-click category blocking: Adult, Gambling, Social, Gaming, etc.
    Each category also offers an optional 'Smart Detection' mode (experimental)
    that enables DNS-level filtering to catch sites not in the predefined list.
    The adult category additionally supports LLM-based live traffic detection.
    """

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Category grid (2 columns)
        self.grid = Gtk.FlowBox()
        self.grid.set_selection_mode(Gtk.SelectionMode.NONE)
        self.grid.set_homogeneous(True)
        self.grid.set_min_children_per_line(1)
        self.grid.set_max_children_per_line(2)
        self.grid.set_column_spacing(12)
        self.grid.set_row_spacing(12)
        content.append(self.grid)

        scroll.set_child(content)
        self.append(scroll)

        self._cards: dict[str, dict] = {}

    def refresh(self) -> None:
        bm = self.window.get_block_manager()

        # Clear grid
        while True:
            child = self.grid.get_child_at_index(0)
            if child is None:
                break
            self.grid.remove(child)

        self._cards.clear()

        for cat_id, cat in CATEGORIES.items():
            is_active = bm.is_category_active(cat_id) if bm else False
            is_smart = bm.is_smart_detect_active(cat_id) if bm else False
            is_llm = bm.is_llm_detection_active() if bm and cat_id == "adult" else False
            has_api_key = bool(bm.db.get_setting("llm_api_key", "")) if bm and cat_id == "adult" else False
            is_image = (bm.db.get_setting("nsfw_image_scan_enabled", "0") == "1") if bm and cat_id == "adult" else False
            card, refs = self._make_category_card(cat_id, cat, is_active, is_smart, is_llm, has_api_key, is_image)
            self._cards[cat_id] = refs
            self.grid.append(card)

    def _make_category_card(
        self,
        cat_id: str,
        cat: dict,
        is_active: bool,
        is_smart: bool,
        is_llm: bool = False,
        has_api_key: bool = False,
        is_image: bool = False,
    ) -> tuple:
        color = cat.get("color", "cyan")
        accent, bg, border = CATEGORY_COLORS.get(color, CATEGORY_COLORS["cyan"])

        outer = Gtk.Box()  # FlowBox child wrapper
        outer.set_hexpand(True)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.add_css_class("blocky-card")
        if is_active:
            card.add_css_class("active")
        card.set_hexpand(True)

        # ── Top row: icon + name + toggle ──────────────────
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

        icon = Gtk.Image.new_from_icon_name(cat.get("icon", "dialog-information-symbolic"))
        icon.set_pixel_size(20)
        top.append(icon)

        name_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        name_box.set_hexpand(True)
        name_lbl = Gtk.Label(label=cat["name"], xalign=0)
        name_lbl.add_css_class("app-name-label")
        name_box.append(name_lbl)
        count_lbl = Gtk.Label(label=f"{len(cat['domains']):,} domains", xalign=0)
        count_lbl.add_css_class("muted")
        name_box.append(count_lbl)
        top.append(name_box)

        # Status dot
        dot = Gtk.Box()
        dot.set_size_request(8, 8)
        dot.add_css_class("status-dot")
        dot.add_css_class("blocked" if is_active else "paused")
        top.append(dot)

        # Main toggle
        toggle = Gtk.Switch()
        toggle.set_active(is_active)
        toggle.set_valign(Gtk.Align.CENTER)
        toggle.connect("state-set", self._on_toggle, cat_id, card, dot)
        top.append(toggle)

        card.append(top)

        # ── Domain list (expandable, truncated for large lists) ──
        num_domains = len(cat["domains"])
        expander = Gtk.Expander()
        expander.set_label(f"{num_domains:,} blocked domains")
        expander.add_css_class("muted")

        domain_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        domain_box.set_margin_top(4)
        domain_box.set_margin_start(8)

        MAX_DISPLAY = 50
        sorted_domains = sorted(cat["domains"])[:MAX_DISPLAY]
        for domain in sorted_domains:
            dl = Gtk.Label(label=domain, xalign=0)
            dl.add_css_class("domain-label")
            domain_box.append(dl)

        if num_domains > MAX_DISPLAY:
            more = Gtk.Label(
                label=f"… and {num_domains - MAX_DISPLAY:,} more domains",
                xalign=0,
            )
            more.add_css_class("muted")
            domain_box.append(more)

        expander.set_child(domain_box)
        card.append(expander)

        # ── Smart Detection (adult only) ─────────────────────
        smart_row = None
        smart_toggle = None
        llm_row = None
        llm_toggle = None

        if cat_id == "adult":
            sep = Gtk.Separator()
            card.append(sep)

            smart_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            smart_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            smart_info.set_hexpand(True)
            smart_title = Gtk.Label(label="Smart Detection", xalign=0)
            smart_title.add_css_class("app-name-label")
            smart_info.append(smart_title)
            smart_sub = Gtk.Label(
                label="DNS redirect to Cloudflare for Families",
                xalign=0,
                wrap=True,
            )
            smart_sub.add_css_class("muted")
            smart_info.append(smart_sub)
            smart_box.append(smart_info)

            smart_toggle = Gtk.Switch()
            smart_toggle.set_active(is_smart)
            smart_toggle.set_valign(Gtk.Align.CENTER)
            smart_toggle.set_sensitive(is_active)
            smart_toggle.connect("state-set", self._on_smart_toggle, cat_id)
            smart_box.append(smart_toggle)

            card.append(smart_box)
            smart_row = smart_toggle

            # ── LLM Detection (adult only) ────────────────────
            llm_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            llm_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            llm_info.set_hexpand(True)
            llm_title_lbl = Gtk.Label(label="LLM Detection", xalign=0)
            llm_title_lbl.add_css_class("app-name-label")
            llm_info.append(llm_title_lbl)
            llm_sub = Gtk.Label(
                label="AI scans live traffic to auto-block adult domains",
                xalign=0,
                wrap=True,
            )
            llm_sub.add_css_class("muted")
            llm_info.append(llm_sub)
            llm_box.append(llm_info)

            llm_toggle = Gtk.Switch()
            llm_toggle.set_active(is_llm)
            llm_toggle.set_valign(Gtk.Align.CENTER)
            llm_toggle.set_sensitive(is_active)
            llm_toggle.connect("state-set", self._on_llm_toggle, cat_id)
            llm_box.append(llm_toggle)

            card.append(llm_box)
            llm_row = llm_toggle

            # ── Image Detection (adult only) ──────────────────
            img_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            img_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            img_info.set_hexpand(True)
            img_title_lbl = Gtk.Label(label="Image Detection", xalign=0)
            img_title_lbl.add_css_class("app-name-label")
            img_info.append(img_title_lbl)
            img_sub = Gtk.Label(
                label="Local NSFW model scans images on pages",
                xalign=0,
                wrap=True,
            )
            img_sub.add_css_class("muted")
            img_info.append(img_sub)
            img_box.append(img_info)

            img_toggle = Gtk.Switch()
            img_toggle.set_active(is_image)
            img_toggle.set_valign(Gtk.Align.CENTER)
            img_toggle.set_sensitive(is_active)
            img_toggle.connect("state-set", self._on_image_toggle)
            img_box.append(img_toggle)

            card.append(img_box)

        outer.append(card)
        refs = {
            "card": card,
            "dot": dot,
            "toggle": toggle,
            "smart_toggle": smart_row,
            "llm_toggle": llm_row,
            "img_toggle": img_toggle if cat_id == "adult" else None,
        }
        return outer, refs

    def _on_toggle(self, switch, state, cat_id: str, card, dot) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            self.window.show_toast("Helper not installed — run install.sh first")
            switch.set_active(False)
            return True

        refs = self._cards.get(cat_id, {})
        smart_tog = refs.get("smart_toggle")
        llm_tog = refs.get("llm_toggle")
        img_tog = refs.get("img_toggle")

        # Optimistic UI update
        if state:
            card.add_css_class("active")
            dot.remove_css_class("paused")
            dot.add_css_class("blocked")
            if smart_tog:
                smart_tog.set_sensitive(True)
            if llm_tog:
                llm_tog.set_sensitive(True)
            if img_tog:
                img_tog.set_sensitive(True)
        else:
            if llm_tog and llm_tog.get_active():
                llm_tog.set_active(False)
            if llm_tog:
                llm_tog.set_sensitive(False)
            if img_tog and img_tog.get_active():
                img_tog.set_active(False)
            if img_tog:
                img_tog.set_sensitive(False)
            card.remove_css_class("active")
            dot.remove_css_class("blocked")
            dot.add_css_class("paused")
            if smart_tog:
                smart_tog.set_active(False)
                smart_tog.set_sensitive(False)

        def _work():
            try:
                if state:
                    smart = smart_tog.get_active() if smart_tog else False
                    bm.activate_category(cat_id, smart_detect=smart)
                    GLib.idle_add(self.window.show_toast, f"Category blocked: {CATEGORIES[cat_id]['name']}")
                else:
                    if llm_tog:
                        bm.disable_llm_detection()
                        bm.db.set_setting("llm_enabled", "0")
                    bm.deactivate_category(cat_id)
                    GLib.idle_add(self.window.show_toast, f"Category unblocked: {CATEGORIES[cat_id]['name']}")
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Error: {e}")
                # Revert UI on failure
                GLib.idle_add(switch.set_active, not state)

        threading.Thread(target=_work, daemon=True).start()
        return False

    def _on_smart_toggle(self, switch, state, cat_id: str) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            return True

        def _work():
            try:
                if state:
                    bm._apply_category(cat_id, smart_detect=True, save=True)
                    GLib.idle_add(self.window.show_toast, "Smart Detection ON")
                else:
                    from blocky.engine.helper_client import run_helper
                    run_helper("dns_redirect_disable")
                    bm.db.set_category_active(cat_id, True, False)
                    GLib.idle_add(self.window.show_toast, "Smart Detection OFF")
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Smart Detection error: {e}")
                GLib.idle_add(switch.set_active, not state)

        threading.Thread(target=_work, daemon=True).start()
        return False

    def _on_llm_toggle(self, switch, state, cat_id: str) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            return True

        if not state:
            def _disable():
                try:
                    bm.disable_llm_detection()
                    bm.db.set_setting("llm_enabled", "0")
                    GLib.idle_add(self.window.show_toast, "LLM Detection OFF")
                except Exception as e:
                    GLib.idle_add(self.window.show_toast, f"LLM Detection error: {e}")
            threading.Thread(target=_disable, daemon=True).start()
            return False

        # Turning ON — check for API key first
        api_key = bm.db.get_setting("llm_api_key", "") or ""
        if not api_key:
            switch.set_active(False)
            self._show_api_key_dialog(
                bm,
                on_saved=lambda: self._enable_llm_after_key(switch, bm),
            )
            return True

        def _enable():
            try:
                bm.enable_llm_detection()
                bm.db.set_setting("llm_enabled", "1")
                GLib.idle_add(self.window.show_toast, "LLM Detection ON")
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"LLM Detection error: {e}")
                GLib.idle_add(switch.set_active, False)
        threading.Thread(target=_enable, daemon=True).start()
        return False

    def _enable_llm_after_key(self, switch: Gtk.Switch, bm) -> None:
        """Called after an API key is saved via the dialog."""
        def _work():
            try:
                bm.enable_llm_detection()
                bm.db.set_setting("llm_enabled", "1")
                GLib.idle_add(switch.set_active, True)
                GLib.idle_add(self.window.show_toast, "LLM Detection ON")
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"LLM Detection error: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _on_image_toggle(self, switch, state) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            return True

        def _work():
            try:
                bm.db.set_setting("nsfw_image_scan_enabled", "1" if state else "0")
                bm.restart_llm_detection()
                msg = "Image Detection ON" if state else "Image Detection OFF"
                GLib.idle_add(self.window.show_toast, msg)
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Image Detection error: {e}")
                GLib.idle_add(switch.set_active, not state)

        threading.Thread(target=_work, daemon=True).start()
        return False

    def _show_api_key_dialog(self, bm, on_saved=None) -> None:
        """Show a dialog prompting the user to paste their LLM API key."""
        from blocky.llm.providers import PROVIDER_ORDER, PROVIDERS

        provider_name = bm.db.get_setting("llm_provider", "anthropic") or "anthropic"
        provider_cfg = PROVIDERS.get(provider_name)
        display_name = provider_cfg.display_name if provider_cfg else provider_name.capitalize()

        dialog = Adw.AlertDialog()
        dialog.set_heading(f"Enter {display_name} API Key")
        dialog.set_body(
            f"Paste your {display_name} API key below.\n"
            "It will be stored locally in the Blocky database."
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save & Enable")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.set_close_response("cancel")

        entry = Gtk.Entry()
        entry.set_placeholder_text("sk-ant-… or similar")
        entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        entry.set_visibility(True)  # visible so user can confirm paste
        entry.set_hexpand(True)

        # Pre-fill if a key already exists
        existing = bm.db.get_setting("llm_api_key", "") or ""
        if existing:
            entry.set_text(existing)

        dialog.set_extra_child(entry)

        def on_response(d, response_id):
            if response_id == "save":
                key = entry.get_text().strip()
                if key:
                    bm.db.set_setting("llm_api_key", key)
                    # Also update the settings page entry if it's loaded
                    if on_saved:
                        on_saved()
                else:
                    self.window.show_toast("No API key entered — LLM Detection not enabled")

        dialog.connect("response", on_response)
        dialog.present(self.window)
