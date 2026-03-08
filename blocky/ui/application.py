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

logger = logging.getLogger(__name__)

CSS_PATH = Path(__file__).parent / "style" / "main.css"


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

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._load_css()
        self._init_backend()

    def _load_css(self) -> None:
        provider = Gtk.CssProvider()
        if CSS_PATH.exists():
            provider.load_from_path(str(CSS_PATH))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

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
            self.window.present()
            self.window.set_visible(True)
            return
        self.window = MainWindow(self)
        self.window.present()

    def do_open(self, files, n_files, hint) -> None:
        # Called when opened via blocky:// URL — just raise the window
        self.do_activate()

    def do_shutdown(self) -> None:
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
