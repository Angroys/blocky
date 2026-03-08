from datetime import datetime

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from blocky.models.block_rule import BlockType


class DashboardPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(32)
        content.set_margin_end(32)

        # Hero title
        hero = Gtk.Label(label="SYSTEM SHIELD")
        hero.add_css_class("subheading")
        content.append(hero)

        # Stat cards row
        stats_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        stats_row.set_homogeneous(True)

        self.total_card = self._make_stat_card("0", "ACTIVE BLOCKS")
        self.web_card = self._make_stat_card("0", "WEBSITES")
        self.app_card = self._make_stat_card("0", "APPS")
        stats_row.append(self.total_card[0])
        stats_row.append(self.web_card[0])
        stats_row.append(self.app_card[0])
        content.append(stats_row)

        # Quick block entry
        quick_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        quick_label = Gtk.Label(label="QUICK BLOCK", xalign=0)
        quick_label.add_css_class("subheading")
        quick_box.append(quick_label)

        entry_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.quick_entry = Gtk.Entry()
        self.quick_entry.set_placeholder_text("Enter domain (e.g. reddit.com) and press Enter")
        self.quick_entry.set_hexpand(True)
        self.quick_entry.connect("activate", self._on_quick_block)
        entry_row.append(self.quick_entry)

        block_btn = Gtk.Button(label="Block")
        block_btn.add_css_class("suggested-action")
        block_btn.connect("clicked", self._on_quick_block)
        entry_row.append(block_btn)

        quick_box.append(entry_row)
        content.append(quick_box)

        # Activity log
        activity_label = Gtk.Label(label="RECENT ACTIVITY", xalign=0)
        activity_label.add_css_class("subheading")
        content.append(activity_label)

        self.activity_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        content.append(self.activity_list)

        scroll.set_child(content)
        self.append(scroll)

    def _make_stat_card(self, number: str, label: str) -> tuple:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.add_css_class("stat-card")

        num_label = Gtk.Label(label=number)
        num_label.add_css_class("stat-number")
        card.append(num_label)

        lbl = Gtk.Label(label=label)
        lbl.add_css_class("stat-label")
        card.append(lbl)

        return card, num_label

    def refresh(self) -> None:
        db = self.window.get_db()
        if not db:
            return

        active_rules = db.get_active_rules()
        web_count = sum(1 for r in active_rules if r.block_type == BlockType.WEBSITE)
        app_count = sum(1 for r in active_rules if r.block_type == BlockType.APP)
        total = len(active_rules)

        self.total_card[1].set_label(str(total))
        self.web_card[1].set_label(str(web_count))
        self.app_card[1].set_label(str(app_count))

        if total > 0:
            self.total_card[1].add_css_class("danger")
        else:
            self.total_card[1].remove_css_class("danger")

        # Refresh activity
        child = self.activity_list.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.activity_list.remove(child)
            child = next_child

        for entry in db.get_recent_activity(limit=10):
            row = self._make_activity_row(entry)
            self.activity_list.append(row)

    def _make_activity_row(self, entry: dict) -> Gtk.Box:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        row.add_css_class("activity-row")
        row.set_margin_bottom(2)

        action_lbl = Gtk.Label(label=entry["action"].upper())
        action_lbl.add_css_class("activity-action")
        action_lbl.add_css_class(entry["action"])
        action_lbl.set_width_chars(10)
        action_lbl.set_xalign(0)
        row.append(action_lbl)

        name_lbl = Gtk.Label(label=entry["rule_name"])
        name_lbl.set_hexpand(True)
        name_lbl.set_xalign(0)
        row.append(name_lbl)

        try:
            ts = datetime.fromisoformat(entry["timestamp"])
            time_str = ts.strftime("%H:%M")
        except Exception:
            time_str = ""
        time_lbl = Gtk.Label(label=time_str)
        time_lbl.add_css_class("muted")
        row.append(time_lbl)

        return row

    def _on_quick_block(self, *_) -> None:
        from blocky.models.block_rule import BlockRule, BlockStatus, BlockType
        from blocky.utils.domain_utils import is_valid_domain, normalize_domain

        text = self.quick_entry.get_text().strip()
        if not text:
            return

        domain = normalize_domain(text)
        if not is_valid_domain(domain):
            self.window.show_toast(f"Invalid domain: {text}")
            return

        db = self.window.get_db()
        bm = self.window.get_block_manager()
        if not db or not bm:
            return

        rule = BlockRule(
            name=domain,
            block_type=BlockType.WEBSITE,
            domain=domain,
            status=BlockStatus.ACTIVE,
        )
        rule_id = db.add_rule(rule)
        rule.id = rule_id

        try:
            bm.activate_rule(rule)
            self.quick_entry.set_text("")
            self.window.show_toast(f"Blocked: {domain}")
            self.refresh()
        except Exception as e:
            self.window.show_toast(f"Failed: {e}")
