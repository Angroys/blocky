import logging
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from blocky.db.database import Database
from blocky.engine.block_manager import BlockManager
from blocky.engine.helper_client import is_helper_available
from blocky.scheduler.scheduler import BlockScheduler
from blocky.ui.main_window import MainWindow
from blocky.ui.tray import TrayManager

logger = logging.getLogger(__name__)

_STYLE_DIR = Path(__file__).parent / "style"
CSS_PATH = _STYLE_DIR / "main.css"
CSS_LIGHT_PATH = _STYLE_DIR / "glass.css"


class BlockyApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(
            application_id="io.github.blocky",
            flags=Gio.ApplicationFlags.HANDLES_OPEN,
        )
        self.db: Database | None = None
        self.block_manager: BlockManager | None = None
        self.scheduler: BlockScheduler | None = None
        self.window: MainWindow | None = None
        self._css_provider: Gtk.CssProvider | None = None
        self._tray: TrayManager | None = None
        self._window_visible = True

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._init_backend()
        self._load_css()
        self._start_tray()
        # Keep app alive in background (tray keeps it from quitting)
        self.hold()

    def _load_css(self) -> None:
        theme = (self.db.get_setting("ui_theme", "dark") or "dark") if self.db else "dark"
        css_path = CSS_LIGHT_PATH if theme == "light" else CSS_PATH

        # Tell libadwaita to use light mode for neumorphic, dark for neo-tactile
        style_mgr = Adw.StyleManager.get_default()
        if theme == "light":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        else:
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK)

        if self._css_provider:
            Gtk.StyleContext.remove_provider_for_display(
                Gdk.Display.get_default(), self._css_provider
            )
        self._css_provider = Gtk.CssProvider()
        if css_path.exists():
            self._css_provider.load_from_path(str(css_path))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            self._css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    def apply_theme(self, theme: str) -> None:
        """Switch CSS theme at runtime (called from settings page)."""
        if self.db:
            self.db.set_setting("ui_theme", theme)
        self._load_css()

    def _init_backend(self) -> None:
        self.db = Database()
        self.block_manager = BlockManager(self.db)
        self.scheduler = BlockScheduler()
        self.scheduler.set_block_manager(self.block_manager)

        if is_helper_available():
            try:
                self.block_manager.start()
            except Exception as e:
                logger.warning("Block manager start failed: %s", e)

        try:
            self.scheduler.start()
            rules = self.db.get_all_rules()
            schedules = self.db.get_schedules()
            self.scheduler.reload_schedules(rules, schedules)
        except Exception as e:
            logger.warning("Scheduler start failed: %s", e)

    def do_activate(self) -> None:
        if self.window:
            self._show_window()
            return
        self.window = MainWindow(self)
        self.window.connect("close-request", self._on_window_close)
        self.window.present()
        self._window_visible = True

    def do_open(self, files, n_files, hint) -> None:
        self.do_activate()

    # ------------------------------------------------------------------
    # Window / tray helpers
    # ------------------------------------------------------------------
    def _on_window_close(self, window) -> bool:
        """Hide to tray instead of destroying the window."""
        self._hide_window()
        return True  # prevent default destroy

    def _show_window(self) -> None:
        if self.window:
            self.window.set_visible(True)
            self.window.present()
            self._window_visible = True

    def _hide_window(self) -> None:
        if self.window:
            self.window.set_visible(False)
            self._window_visible = False

    def _toggle_window(self) -> None:
        if self._window_visible:
            self._hide_window()
        else:
            self._show_window()

    def quit_app(self) -> None:
        """Full quit — called from tray Quit menu item."""
        if self._tray:
            self._tray.stop()
        self.release()  # undo the hold() from startup
        self.quit()

    def _start_tray(self) -> None:
        self._tray = TrayManager(
            on_toggle=self._toggle_window,
            on_quit=self.quit_app,
        )
        if not self._tray.start():
            logger.warning("System tray not available — app will close normally")
            self._tray = None

    # ------------------------------------------------------------------
    def do_shutdown(self) -> None:
        if self._tray:
            self._tray.stop()
        if self.block_manager:
            try:
                self.block_manager.stop()
            except Exception:
                pass
        if self.scheduler:
            try:
                self.scheduler.stop()
            except Exception:
                pass
        if self.db:
            self.db.close()
        Adw.Application.do_shutdown(self)
