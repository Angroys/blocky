import threading

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from blocky.models.block_rule import BlockRule, BlockStatus, BlockType
from blocky.utils.domain_utils import is_valid_domain, normalize_domain


class WebsitesPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        # Toolbar with search
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.set_margin_top(12)
        toolbar.set_margin_bottom(6)
        toolbar.set_margin_start(16)
        toolbar.set_margin_end(16)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Filter websites...")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._on_search)
        toolbar.append(self.search_entry)

        add_btn = Gtk.Button(label="+ Add Website")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._show_add_dialog)
        toolbar.append(add_btn)

        self.append(toolbar)

        # List
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
        return self._search_text in (rule.domain or "").lower() or \
               self._search_text in rule.name.lower()

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

        rules = [r for r in db.get_all_rules() if r.block_type == BlockType.WEBSITE]
        if not rules:
            placeholder = Gtk.Label(label="No websites blocked yet.\nClick '+ Add Website' to get started.")
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

        # Domain info
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        info.set_hexpand(True)

        name_lbl = Gtk.Label(label=rule.name, xalign=0)
        name_lbl.add_css_class("app-name-label")
        info.append(name_lbl)

        domain_lbl = Gtk.Label(label=rule.domain or "", xalign=0)
        domain_lbl.add_css_class("domain-label")
        info.append(domain_lbl)

        if rule.extra_domains:
            extra = Gtk.Label(
                label="+ " + ", ".join(rule.extra_domains[:3]),
                xalign=0,
            )
            extra.add_css_class("muted")
            info.append(extra)

        card.append(info)

        # Schedule badge + strict lock detection
        bm = self.window.get_block_manager()
        locked = bm.is_rule_locked(rule) if bm else False
        if rule.schedule_id:
            if locked:
                lock_icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
                lock_icon.set_pixel_size(16)
                card.append(lock_icon)
                sched_badge = Gtk.Label(label="LOCKED")
                sched_badge.add_css_class("badge")
                sched_badge.add_css_class("destructive-action")
            else:
                sched_badge = Gtk.Label(label="SCHEDULED")
                sched_badge.add_css_class("badge")
                sched_badge.add_css_class("scheduled")
            card.append(sched_badge)

        # Toggle switch
        toggle = Gtk.Switch()
        toggle.set_active(rule.status == BlockStatus.ACTIVE)
        toggle.set_valign(Gtk.Align.CENTER)
        toggle.set_sensitive(not locked)
        if locked:
            toggle.set_tooltip_text("Locked by strict schedule")
        toggle.connect("state-set", self._on_toggle, rule)
        card.append(toggle)

        # Delete button
        del_btn = Gtk.Button(icon_name="user-trash-symbolic")
        del_btn.add_css_class("destructive-action")
        del_btn.set_valign(Gtk.Align.CENTER)
        del_btn.set_sensitive(not locked)
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
                    GLib.idle_add(self.window.show_toast, f"Blocked: {rule.domain}")
                else:
                    bm.deactivate_rule(rule)
                    GLib.idle_add(self.window.show_toast, f"Paused: {rule.domain}")
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
                GLib.idle_add(self.window.show_toast, f"Removed: {rule.domain}")
                GLib.idle_add(self.refresh)
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Error: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def _show_add_dialog(self, *_) -> None:
        dialog = AddWebsiteDialog(self.window)
        dialog.present()
        dialog.connect("response", self._on_add_dialog_response, dialog)

    def _on_add_dialog_response(self, dialog, response: str, dlg) -> None:
        if response != "block":
            return
        domain = normalize_domain(dlg.domain_entry.get_text().strip())
        if not is_valid_domain(domain):
            self.window.show_toast("Invalid domain name")
            return

        extra_raw = dlg.extra_entry.get_text().strip()
        extra_domains = []
        if extra_raw:
            extra_domains = [
                normalize_domain(d.strip())
                for d in extra_raw.split(",")
                if d.strip() and is_valid_domain(normalize_domain(d.strip()))
            ]

        rule = BlockRule(
            name=dlg.name_entry.get_text().strip() or domain,
            block_type=BlockType.WEBSITE,
            domain=domain,
            extra_domains=extra_domains,
            block_ip_layer=dlg.ip_layer_toggle.get_active(),
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
                GLib.idle_add(self.window.show_toast, f"Blocked: {domain}")
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f"Saved, but blocking failed: {e}")
            GLib.idle_add(self.refresh)

        threading.Thread(target=_work, daemon=True).start()


class AddWebsiteDialog(Adw.MessageDialog):
    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window,
            heading="Block Website",
            body="Enter the domain name to block.",
        )
        self.add_response("cancel", "Cancel")
        self.add_response("block", "Block")
        self.set_response_appearance("block", Adw.ResponseAppearance.SUGGESTED)
        self.set_default_response("block")
        self.set_close_response("cancel")

        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        form.set_margin_top(12)

        # Name
        name_row = Adw.EntryRow()
        name_row.set_title("Label (optional)")
        self.name_entry = name_row
        form.append(name_row)

        # Domain
        domain_row = Adw.EntryRow()
        domain_row.set_title("Domain")
        self.domain_entry = domain_row
        form.append(domain_row)

        # Extra domains
        extra_row = Adw.EntryRow()
        extra_row.set_title("Extra domains (comma-separated)")
        self.extra_entry = extra_row
        form.append(extra_row)

        # IP layer toggle
        ip_row = Adw.ActionRow()
        ip_row.set_title("Deep block (iptables IP blocking)")
        ip_row.set_subtitle("Also blocks direct IP connections")
        self.ip_layer_toggle = Gtk.Switch()
        self.ip_layer_toggle.set_valign(Gtk.Align.CENTER)
        ip_row.add_suffix(self.ip_layer_toggle)
        form.append(ip_row)

        self.set_extra_child(form)
