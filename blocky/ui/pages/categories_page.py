import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from blocky.data.categories import CATEGORIES, CATEGORY_COLORS


class CategoriesPage(Gtk.Box):
    """
    One-click category blocking: Adult, Gambling, Social, Gaming, etc.
    Each category also offers an optional 'Smart Detection' mode (experimental)
    that enables DNS-level filtering to catch sites not in the predefined list.
    """

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

        # Header description
        desc = Gtk.Label(
            label="Block entire categories of websites with a single toggle.\n"
                  "Smart Detection (experimental) uses DNS-level filtering to catch unlisted sites.",
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        desc.add_css_class("muted")
        content.append(desc)

        # Category grid (2 columns)
        self.grid = Gtk.FlowBox()
        self.grid.set_selection_mode(Gtk.SelectionMode.NONE)
        self.grid.set_homogeneous(True)
        self.grid.set_min_children_per_line(1)
        self.grid.set_max_children_per_line(2)
        self.grid.set_column_spacing(16)
        self.grid.set_row_spacing(16)
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
            card, refs = self._make_category_card(cat_id, cat, is_active, is_smart)
            self._cards[cat_id] = refs
            self.grid.append(card)

    def _make_category_card(
        self, cat_id: str, cat: dict, is_active: bool, is_smart: bool
    ) -> tuple:
        color = cat.get("color", "cyan")
        accent, bg, border = CATEGORY_COLORS.get(color, CATEGORY_COLORS["cyan"])

        outer = Gtk.Box()  # FlowBox child wrapper
        outer.set_hexpand(True)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("blocky-card")
        if is_active:
            card.add_css_class("active")
        card.set_hexpand(True)
        card.set_margin_top(2)
        card.set_margin_bottom(2)
        card.set_margin_start(2)
        card.set_margin_end(2)

        # ── Top row: icon + name + toggle ──────────────────
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        icon = Gtk.Image.new_from_icon_name(cat.get("icon", "dialog-information-symbolic"))
        icon.set_pixel_size(28)
        top.append(icon)

        name_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        name_box.set_hexpand(True)
        name_lbl = Gtk.Label(label=cat["name"], xalign=0)
        name_lbl.add_css_class("app-name-label")
        name_box.append(name_lbl)
        count_lbl = Gtk.Label(label=f"{len(cat['domains'])} domains", xalign=0)
        count_lbl.add_css_class("muted")
        name_box.append(count_lbl)
        top.append(name_box)

        # Status dot
        dot = Gtk.Box()
        dot.set_size_request(10, 10)
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

        # ── Description ─────────────────────────────────────
        desc_lbl = Gtk.Label(label=cat["description"], xalign=0, wrap=True)
        desc_lbl.add_css_class("muted")
        card.append(desc_lbl)

        # ── Domain list (expandable) ─────────────────────────
        expander = Gtk.Expander()
        expander.set_label(f"View all {len(cat['domains'])} blocked domains")
        expander.add_css_class("muted")

        domain_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        domain_box.set_margin_top(6)
        domain_box.set_margin_start(12)

        for domain in sorted(cat["domains"]):
            dl = Gtk.Label(label=domain, xalign=0)
            dl.add_css_class("domain-label")
            domain_box.append(dl)

        expander.set_child(domain_box)
        card.append(expander)

        # ── Smart Detection (adult only) ─────────────────────
        smart_row = None
        smart_toggle = None
        if cat_id == "adult":
            sep = Gtk.Separator()
            card.append(sep)

            smart_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            smart_icon = Gtk.Image.new_from_icon_name("network-wired-symbolic")
            smart_icon.set_pixel_size(16)
            smart_box.append(smart_icon)

            smart_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            smart_info.set_hexpand(True)
            smart_title = Gtk.Label(label="Smart Detection", xalign=0)
            smart_title.add_css_class("muted")
            smart_info.append(smart_title)
            smart_sub = Gtk.Label(
                label="Experimental — redirects DNS to Cloudflare for Families (1.1.1.3)\n"
                      "Catches unlisted adult sites not in the predefined list",
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

            # Experimental badge
            exp_badge = Gtk.Label(label="EXPERIMENTAL")
            exp_badge.add_css_class("badge")
            exp_badge.add_css_class("scheduled")
            smart_box.append(exp_badge)

            card.append(smart_box)
            smart_row = smart_toggle

        outer.append(card)
        refs = {
            "card": card,
            "dot": dot,
            "toggle": toggle,
            "smart_toggle": smart_row,
        }
        return outer, refs

    def _on_toggle(self, switch, state, cat_id: str, card, dot) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            self.window.show_toast("Helper not installed — run install.sh first")
            switch.set_active(False)
            return True

        try:
            if state:
                smart = False
                refs = self._cards.get(cat_id, {})
                st = refs.get("smart_toggle")
                if st:
                    smart = st.get_active()
                bm.activate_category(cat_id, smart_detect=smart)
                card.add_css_class("active")
                dot.remove_css_class("paused")
                dot.add_css_class("blocked")
                # Enable smart toggle
                if st:
                    st.set_sensitive(True)
                self.window.show_toast(f"Category blocked: {CATEGORIES[cat_id]['name']}")
            else:
                bm.deactivate_category(cat_id)
                card.remove_css_class("active")
                dot.remove_css_class("blocked")
                dot.add_css_class("paused")
                refs = self._cards.get(cat_id, {})
                st = refs.get("smart_toggle")
                if st:
                    st.set_active(False)
                    st.set_sensitive(False)
                self.window.show_toast(f"Category unblocked: {CATEGORIES[cat_id]['name']}")
        except Exception as e:
            self.window.show_toast(f"Error: {e}")

        return False

    def _on_smart_toggle(self, switch, state, cat_id: str) -> bool:
        bm = self.window.get_block_manager()
        if not bm:
            return True
        try:
            # Re-apply category with updated smart_detect setting
            if state:
                bm._apply_category(cat_id, smart_detect=True, save=True)
                self.window.show_toast(
                    "Smart Detection ON — DNS redirected to Cloudflare for Families"
                )
            else:
                from blocky.engine.helper_client import run_helper
                run_helper("dns_redirect_disable")
                from blocky.db.database import Database
                bm.db.set_category_active(cat_id, True, False)
                self.window.show_toast("Smart Detection OFF")
        except Exception as e:
            self.window.show_toast(f"Smart Detection error: {e}")
        return False
