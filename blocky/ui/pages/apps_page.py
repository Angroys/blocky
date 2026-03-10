import threading

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from blocky.models.block_rule import BlockRule, BlockStatus, BlockType
from blocky.utils.app_discovery import AppProfile


class AppsPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.set_margin_top(12)
        toolbar.set_margin_bottom(6)
        toolbar.set_margin_start(16)
        toolbar.set_margin_end(16)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Filter apps...")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._on_search)
        toolbar.append(self.search_entry)

        add_btn = Gtk.Button(label="+ Add App")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._show_add_dialog)
        toolbar.append(add_btn)

        self.append(toolbar)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.set_margin_start(16)
        self.list_box.set_margin_end(16)
        self.list_box.set_margin_bottom(16)
        self.list_box.set_filter_func(self._filter_func)

        scroll.set_child(self.list_box)
        self.append(scroll)

        self._search_text = ""

    def _filter_func(self, row) -> bool:
        if not self._search_text:
            return True
        rule = getattr(row, "rule", None)
        if not rule:
            return True
        return self._search_text in rule.name.lower() or \
               self._search_text in (rule.process_name or "").lower()

    def _on_search(self, entry) -> None:
        self._search_text = entry.get_text().lower()
        self.list_box.invalidate_filter()

    def refresh(self) -> None:
        db = self.window.get_db()
        if not db:
            return

        child = self.list_box.get_first_child()
        while child:
            next_c = child.get_next_sibling()
            self.list_box.remove(child)
            child = next_c

        rules = [r for r in db.get_all_rules() if r.block_type == BlockType.APP]
        if not rules:
            placeholder = Gtk.Label(label="No apps blocked yet.\nClick '+ Add App' to get started.")
            placeholder.set_justify(Gtk.Justification.CENTER)
            placeholder.add_css_class("muted")
            placeholder.set_margin_top(64)
            row = Gtk.ListBoxRow()
            row.set_child(placeholder)
            row.set_selectable(False)
            self.list_box.append(row)
            return

        for rule in rules:
            row = self._make_rule_row(rule)
            self.list_box.append(row)

    def _make_rule_row(self, rule: BlockRule) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.rule = rule
        row.set_selectable(False)
        row.set_margin_bottom(4)

        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        card.add_css_class("blocky-card")
        if rule.status == BlockStatus.ACTIVE:
            card.add_css_class("active")
        else:
            card.add_css_class("paused")

        # Status dot
        dot = Gtk.Box()
        dot.set_size_request(8, 8)
        dot.add_css_class("status-dot")
        dot.add_css_class("blocked" if rule.status == BlockStatus.ACTIVE else "paused")
        card.append(dot)

        # App icon
        icon = Gtk.Image.new_from_icon_name("application-x-executable-symbolic")
        icon.set_pixel_size(24)
        card.append(icon)

        # Info
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        info.set_hexpand(True)

        name_lbl = Gtk.Label(label=rule.name, xalign=0)
        name_lbl.add_css_class("app-name-label")
        info.append(name_lbl)

        proc_lbl = Gtk.Label(label=rule.process_name or rule.exe_path or "", xalign=0)
        proc_lbl.add_css_class("domain-label")
        info.append(proc_lbl)

        card.append(info)

        # Mode badge
        mode_colors = {"strict": "website", "network": "app", "kill": "scheduled"}
        mode_badge = Gtk.Label(label=rule.block_mode.upper())
        mode_badge.add_css_class("badge")
        mode_badge.add_css_class(mode_colors.get(rule.block_mode, "app"))
        card.append(mode_badge)

        # Toggle
        toggle = Gtk.Switch()
        toggle.set_active(rule.status == BlockStatus.ACTIVE)
        toggle.set_valign(Gtk.Align.CENTER)
        toggle.connect("state-set", self._on_toggle, rule)
        card.append(toggle)

        # Delete
        del_btn = Gtk.Button(icon_name="user-trash-symbolic")
        del_btn.add_css_class("destructive-action")
        del_btn.set_valign(Gtk.Align.CENTER)
        del_btn.connect("clicked", self._on_delete, rule)
        card.append(del_btn)

        row.set_child(card)
        return row

    def _on_toggle(self, switch, state, rule: BlockRule) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            return False

        def _work():
            try:
                if state:
                    bm.activate_rule(rule)
                    GLib.idle_add(self.window.show_toast, f"Blocking: {rule.name}")
                else:
                    bm.deactivate_rule(rule)
                    GLib.idle_add(self.window.show_toast, f"Paused: {rule.name}")
                GLib.idle_add(self.refresh)
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Error: {e}")
                GLib.idle_add(switch.set_active, not state)

        threading.Thread(target=_work, daemon=True).start()
        return False

    def _on_delete(self, _btn, rule: BlockRule) -> None:
        bm = self.window.get_block_manager()

        def _work():
            try:
                if bm:
                    bm.delete_rule(rule)
                GLib.idle_add(self.window.show_toast, f"Removed: {rule.name}")
                GLib.idle_add(self.refresh)
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Error: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def _show_add_dialog(self, *_) -> None:
        dialog = AppPickerDialog(self.window)
        dialog.present()
        dialog.connect("response", self._on_add_dialog_response, dialog)

    def _on_add_dialog_response(self, dialog, response: str, dlg) -> None:
        if response != "block":
            return
        profile = dlg.selected_profile
        custom_name_entry = dlg.custom_exe_entry.get_text().strip()
        name = dlg.name_entry.get_text().strip()

        if profile:
            process_name = profile.process_name
            if not name:
                name = profile.display_name
        elif custom_name_entry:
            # Accept process name or path
            import os
            process_name = os.path.basename(custom_name_entry)
            if not name:
                name = process_name
        else:
            self.window.show_toast("Please select an app or enter a process name")
            return
        if dlg.kill_radio.get_active():
            block_mode = "kill"
        elif dlg.strict_radio.get_active():
            block_mode = "strict"
        else:
            block_mode = "network"

        rule = BlockRule(
            name=name,
            block_type=BlockType.APP,
            process_name=process_name,
            block_mode=block_mode,
            status=BlockStatus.ACTIVE,
        )

        db = self.window.get_db()
        bm = self.window.get_block_manager()
        rule_id = db.add_rule(rule)
        rule.id = rule_id

        def _work():
            try:
                if bm:
                    bm.activate_rule(rule)
                GLib.idle_add(self.window.show_toast, f"Blocking app: {name}")
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Saved, but blocking failed: {e}")
            GLib.idle_add(self.refresh)

        threading.Thread(target=_work, daemon=True).start()


class AppPickerDialog(Adw.MessageDialog):
    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window,
            heading="Block Application",
            body="Search and select an installed application.",
        )
        self.selected_profile: AppProfile | None = None

        self.add_response("cancel", "Cancel")
        self.add_response("block", "Block App")
        self.set_response_appearance("block", Adw.ResponseAppearance.DESTRUCTIVE)
        self.set_default_response("block")
        self.set_close_response("cancel")

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)

        # Name override
        name_row = Adw.EntryRow()
        name_row.set_title("Display name (optional)")
        self.name_entry = name_row
        box.append(name_row)

        # App search
        search_entry = Gtk.SearchEntry()
        search_entry.set_placeholder_text("Search installed apps...")
        search_entry.connect("search-changed", self._on_search)
        box.append(search_entry)

        # App list
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(200)
        scroll.set_max_content_height(280)
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.app_list = Gtk.ListBox()
        self.app_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.app_list.connect("row-selected", self._on_app_selected)
        self.app_list.set_filter_func(self._filter_func)
        scroll.set_child(self.app_list)
        box.append(scroll)

        # Custom exe path
        custom_expander = Adw.ExpanderRow()
        custom_expander.set_title("Or enter process name manually")
        exe_row = Adw.EntryRow()
        exe_row.set_title("Process name (e.g. zen-bin, firefox, spotify)")
        self.custom_exe_entry = exe_row
        custom_expander.add_row(exe_row)
        box.append(custom_expander)

        # Block mode
        mode_label = Gtk.Label(label="BLOCK MODE", xalign=0)
        mode_label.add_css_class("subheading")
        box.append(mode_label)

        mode_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        self.network_radio = Gtk.CheckButton(label="Block internet access — cgroup network isolation")
        mode_box.append(self.network_radio)

        self.kill_radio = Gtk.CheckButton(label="Prevent from running — terminate on launch")
        self.kill_radio.set_group(self.network_radio)
        mode_box.append(self.kill_radio)

        self.strict_radio = Gtk.CheckButton(label="Strict — kill entire process tree + block network (strongest)")
        self.strict_radio.set_group(self.network_radio)
        mode_box.append(self.strict_radio)

        self.strict_radio.set_active(True)  # Default to strict
        box.append(mode_box)

        self.set_extra_child(box)

        # Load apps in background
        self._all_profiles: list[AppProfile] = []
        self._search_text = ""
        self._load_apps()

    def _load_apps(self) -> None:
        from blocky.utils.app_discovery import discover_apps
        try:
            self._all_profiles = discover_apps()
        except Exception:
            self._all_profiles = []

        for profile in self._all_profiles:
            row = self._make_app_row(profile)
            self.app_list.append(row)

    def _make_app_row(self, profile: AppProfile) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.profile = profile
        row.set_margin_bottom(2)

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_top(6)
        box.set_margin_bottom(6)
        box.set_margin_start(8)
        box.set_margin_end(8)

        icon = Gtk.Image.new_from_icon_name(profile.icon_name)
        icon.set_pixel_size(24)
        box.append(icon)

        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        name_lbl = Gtk.Label(label=profile.display_name, xalign=0)
        name_lbl.add_css_class("app-name-label")
        info.append(name_lbl)
        exe_lbl = Gtk.Label(label=profile.process_name, xalign=0)
        exe_lbl.add_css_class("muted")
        info.append(exe_lbl)
        box.append(info)

        row.set_child(box)
        return row

    def _filter_func(self, row) -> bool:
        if not self._search_text:
            return True
        profile = getattr(row, "profile", None)
        if not profile:
            return True
        text = self._search_text
        return text in profile.display_name.lower() or text in profile.process_name.lower()

    def _on_search(self, entry) -> None:
        self._search_text = entry.get_text().lower()
        self.app_list.invalidate_filter()

    def _on_app_selected(self, listbox, row) -> None:
        if row:
            self.selected_profile = getattr(row, "profile", None)
