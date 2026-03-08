import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from blocky.engine.helper_client import is_helper_available
from blocky.ui.pages.apps_page import AppsPage
from blocky.ui.pages.categories_page import CategoriesPage
from blocky.ui.pages.dashboard_page import DashboardPage
from blocky.ui.pages.schedules_page import SchedulesPage
from blocky.ui.pages.settings_page import SettingsPage
from blocky.ui.pages.websites_page import WebsitesPage


NAV_ITEMS = [
    ("Dashboard", "view-grid-symbolic", "dashboard"),
    ("Categories", "view-list-symbolic", "categories"),
    ("Websites", "network-wireless-symbolic", "websites"),
    ("Apps", "application-x-executable-symbolic", "apps"),
    ("Schedules", "alarm-symbolic", "schedules"),
    ("Settings", "preferences-system-symbolic", "settings"),
]


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app) -> None:
        super().__init__(application=app, title="BLOCKY")
        self.app = app
        self.set_default_size(1100, 700)
        self.set_size_request(800, 500)

        self._build_ui()
        self._setup_status_callback()

    def _build_ui(self) -> None:
        # Toast overlay wraps everything
        self.toast_overlay = Adw.ToastOverlay()

        # Split view: sidebar + content
        self.split_view = Adw.OverlaySplitView()
        self.split_view.set_sidebar_width_fraction(0.2)
        self.split_view.set_collapsed(False)
        self.split_view.set_min_sidebar_width(180)
        self.split_view.set_max_sidebar_width(240)

        # Sidebar
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar_header = Adw.HeaderBar()
        sidebar_header.set_show_end_title_buttons(False)
        title_label = Gtk.Label(label="BLOCKY")
        title_label.add_css_class("title")
        sidebar_header.set_title_widget(title_label)
        sidebar_box.append(sidebar_header)

        self.nav_list = Gtk.ListBox()
        self.nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.nav_list.add_css_class("nav-sidebar")
        self.nav_list.connect("row-selected", self._on_nav_selected)

        for label, icon_name, page_id in NAV_ITEMS:
            row = self._make_nav_row(label, icon_name, page_id)
            self.nav_list.append(row)

        sidebar_box.append(self.nav_list)

        # Permission warning at bottom of sidebar
        if not is_helper_available():
            warn = Gtk.Label(
                label="Helper not installed\nRun install.sh",
                wrap=True,
                justify=Gtk.Justification.CENTER,
            )
            warn.add_css_class("permission-banner")
            warn.set_margin_start(8)
            warn.set_margin_end(8)
            warn.set_margin_bottom(8)
            sidebar_box.append(warn)

        self.split_view.set_sidebar(sidebar_box)

        # Content area: stack of pages
        self.content_header = Adw.HeaderBar()
        self.content_header.set_show_start_title_buttons(False)
        self.content_title = Gtk.Label(label="Dashboard")
        self.content_title.add_css_class("title")
        self.content_header.set_title_widget(self.content_title)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(150)

        # Create pages
        self.pages = {
            "dashboard": DashboardPage(self),
            "categories": CategoriesPage(self),
            "websites": WebsitesPage(self),
            "apps": AppsPage(self),
            "schedules": SchedulesPage(self),
            "settings": SettingsPage(self),
        }
        for page_id, page in self.pages.items():
            self.stack.add_named(page, page_id)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.append(self.content_header)
        content_box.append(self.stack)

        self.split_view.set_content(content_box)
        self.toast_overlay.set_child(self.split_view)
        self.set_content(self.toast_overlay)

        # Select dashboard by default
        self.nav_list.select_row(self.nav_list.get_row_at_index(0))

    def _make_nav_row(self, label: str, icon_name: str, page_id: str) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.page_id = page_id

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(12)
        box.set_margin_end(12)

        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(18)
        box.append(icon)

        lbl = Gtk.Label(label=label, xalign=0)
        lbl.set_hexpand(True)
        box.append(lbl)

        row.set_child(box)
        return row

    def _on_nav_selected(self, listbox, row) -> None:
        if row is None:
            return
        page_id = row.page_id
        self.stack.set_visible_child_name(page_id)
        labels = {item[2]: item[0] for item in NAV_ITEMS}
        self.content_title.set_label(labels.get(page_id, ""))
        # Refresh the page
        page = self.pages.get(page_id)
        if page and hasattr(page, "refresh"):
            page.refresh()

    def _setup_status_callback(self) -> None:
        if self.app.block_manager:
            self.app.block_manager.set_status_callback(self._on_status_change)

    def _on_status_change(self) -> None:
        from gi.repository import GLib
        GLib.idle_add(self._refresh_current_page)

    def _refresh_current_page(self) -> bool:
        page_id = self.stack.get_visible_child_name()
        page = self.pages.get(page_id)
        if page and hasattr(page, "refresh"):
            page.refresh()
        return False

    def show_toast(self, message: str) -> None:
        toast = Adw.Toast.new(message)
        toast.set_timeout(3)
        self.toast_overlay.add_toast(toast)

    def get_block_manager(self):
        return self.app.block_manager

    def get_db(self):
        return self.app.db

    def get_scheduler(self):
        return self.app.scheduler
