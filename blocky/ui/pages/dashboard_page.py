import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk

from blocky.models.block_rule import BlockType


class DashboardPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_vexpand(True)
        content.set_valign(Gtk.Align.CENTER)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(32)
        content.set_margin_end(32)

        stats_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        stats_row.set_homogeneous(True)

        self.total_card = self._make_stat_card("0", "ACTIVE BLOCKS")
        self.web_card   = self._make_stat_card("0", "WEBSITES")
        self.app_card   = self._make_stat_card("0", "APPS")
        stats_row.append(self.total_card[0])
        stats_row.append(self.web_card[0])
        stats_row.append(self.app_card[0])
        content.append(stats_row)

        self.append(content)

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
