import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from blocky.models.schedule import RecurrenceType, Schedule


DAY_LABELS = ["M", "T", "W", "T", "F", "S", "S"]
DAY_FULL = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


class SchedulesPage(Gtk.Box):
    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.set_margin_top(16)
        toolbar.set_margin_bottom(8)
        toolbar.set_margin_start(24)
        toolbar.set_margin_end(24)

        title = Gtk.Label(label="Manage time-based blocking schedules", xalign=0)
        title.add_css_class("muted")
        title.set_hexpand(True)
        toolbar.append(title)

        add_btn = Gtk.Button(label="+ New Schedule")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._show_add_dialog)
        toolbar.append(add_btn)

        self.append(toolbar)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.set_margin_start(24)
        self.list_box.set_margin_end(24)
        self.list_box.set_margin_bottom(24)

        scroll.set_child(self.list_box)
        self.append(scroll)

    def refresh(self) -> None:
        db = self.window.get_db()
        if not db:
            return

        child = self.list_box.get_first_child()
        while child:
            next_c = child.get_next_sibling()
            self.list_box.remove(child)
            child = next_c

        schedules = db.get_schedules()
        all_rules = db.get_all_rules()

        if not schedules:
            placeholder = Gtk.Label(
                label="No schedules yet.\nCreate one to block websites or apps at specific times."
            )
            placeholder.set_justify(Gtk.Justification.CENTER)
            placeholder.add_css_class("muted")
            placeholder.set_margin_top(64)
            row = Gtk.ListBoxRow()
            row.set_child(placeholder)
            row.set_selectable(False)
            self.list_box.append(row)
            return

        for schedule in schedules:
            rules_using = [r for r in all_rules if r.schedule_id == schedule.id]
            row = self._make_schedule_row(schedule, rules_using)
            self.list_box.append(row)

    def _make_schedule_row(self, schedule: Schedule, rules) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.set_selectable(False)
        row.set_margin_bottom(6)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.add_css_class("blocky-card")
        card.set_margin_top(2)
        card.set_margin_bottom(2)

        # Header row
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        name_lbl = Gtk.Label(label=schedule.name, xalign=0)
        name_lbl.add_css_class("app-name-label")
        name_lbl.set_hexpand(True)
        header.append(name_lbl)

        # Time range
        time_lbl = Gtk.Label(label=f"{schedule.start_time} – {schedule.end_time}")
        time_lbl.add_css_class("domain-label")
        header.append(time_lbl)

        # Active toggle
        toggle = Gtk.Switch()
        toggle.set_active(schedule.active)
        toggle.set_valign(Gtk.Align.CENTER)
        toggle.connect("state-set", self._on_toggle, schedule)
        header.append(toggle)

        # Delete
        del_btn = Gtk.Button(icon_name="user-trash-symbolic")
        del_btn.add_css_class("destructive-action")
        del_btn.set_valign(Gtk.Align.CENTER)
        del_btn.connect("clicked", self._on_delete, schedule)
        header.append(del_btn)

        card.append(header)

        # Day pills
        days_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        mask = schedule.weekday_mask
        if schedule.recurrence == RecurrenceType.WEEKDAYS:
            mask = 0b0011111
        elif schedule.recurrence == RecurrenceType.WEEKENDS:
            mask = 0b1100000
        elif schedule.recurrence == RecurrenceType.DAILY:
            mask = 0b1111111

        for i, label in enumerate(DAY_LABELS):
            pill = Gtk.Label(label=label)
            pill.add_css_class("day-toggle")
            if mask & (1 << i):
                pill.add_css_class("badge")
                pill.add_css_class("website")
            else:
                pill.add_css_class("muted")
            days_box.append(pill)

        days_box.append(Gtk.Label(label=f"  {schedule.recurrence.value}"))
        card.append(days_box)

        # Rules using this schedule
        if rules:
            rules_lbl = Gtk.Label(
                label="Used by: " + ", ".join(r.name for r in rules[:5]),
                xalign=0,
            )
            rules_lbl.add_css_class("muted")
            card.append(rules_lbl)

        row.set_child(card)
        return row

    def _on_toggle(self, switch, state, schedule: Schedule) -> bool:
        db = self.window.get_db()
        if db:
            schedule.active = state
            db.update_schedule(schedule)
            # Reload scheduler
            scheduler = self.window.get_scheduler()
            if scheduler:
                rules = db.get_all_rules()
                schedules = db.get_schedules()
                scheduler.reload_schedules(rules, schedules)
        return False

    def _on_delete(self, _btn, schedule: Schedule) -> None:
        db = self.window.get_db()
        scheduler = self.window.get_scheduler()
        if db:
            db.delete_schedule(schedule.id)
        if scheduler:
            scheduler.remove_schedule(schedule.id)
        self.window.show_toast(f"Deleted schedule: {schedule.name}")
        self.refresh()

    def _show_add_dialog(self, *_) -> None:
        dialog = AddScheduleDialog(self.window)
        dialog.present()
        dialog.connect("response", self._on_add_dialog_response, dialog)

    def _on_add_dialog_response(self, dialog, response: str, dlg) -> None:
        if response != "create":
            return

        name = dlg.name_entry.get_text().strip()
        if not name:
            self.window.show_toast("Please enter a schedule name")
            return

        start_time = f"{dlg.start_hour.get_value():02.0f}:{dlg.start_min.get_value():02.0f}"
        end_time = f"{dlg.end_hour.get_value():02.0f}:{dlg.end_min.get_value():02.0f}"

        # Determine recurrence
        mask = 0
        for i, btn in enumerate(dlg.day_buttons):
            if btn.get_active():
                mask |= (1 << i)

        if mask == 0b0111111:
            recurrence = RecurrenceType.DAILY
        elif mask == 0b0011111:
            recurrence = RecurrenceType.WEEKDAYS
        elif mask == 0b1100000:
            recurrence = RecurrenceType.WEEKENDS
        else:
            recurrence = RecurrenceType.CUSTOM

        schedule = Schedule(
            name=name,
            recurrence=recurrence,
            weekday_mask=mask,
            start_time=start_time,
            end_time=end_time,
        )

        db = self.window.get_db()
        sched_id = db.add_schedule(schedule)
        schedule.id = sched_id

        self.window.show_toast(f"Schedule created: {name}")
        self.refresh()


class AddScheduleDialog(Adw.MessageDialog):
    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window,
            heading="New Schedule",
            body="Define when blocking should be active.",
        )
        self.add_response("cancel", "Cancel")
        self.add_response("create", "Create Schedule")
        self.set_response_appearance("create", Adw.ResponseAppearance.SUGGESTED)
        self.set_default_response("create")
        self.set_close_response("cancel")

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)

        # Name
        name_row = Adw.EntryRow()
        name_row.set_title("Schedule name")
        self.name_entry = name_row
        box.append(name_row)

        # Time pickers
        time_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)

        start_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        start_lbl = Gtk.Label(label="START", xalign=0)
        start_lbl.add_css_class("subheading")
        start_box.append(start_lbl)
        start_time_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.start_hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.start_hour.set_value(9)
        self.start_hour.set_width_chars(3)
        start_time_row.append(self.start_hour)
        start_time_row.append(Gtk.Label(label=":"))
        self.start_min = Gtk.SpinButton.new_with_range(0, 59, 5)
        self.start_min.set_value(0)
        self.start_min.set_width_chars(3)
        start_time_row.append(self.start_min)
        start_box.append(start_time_row)
        time_box.append(start_box)

        end_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        end_lbl = Gtk.Label(label="END", xalign=0)
        end_lbl.add_css_class("subheading")
        end_box.append(end_lbl)
        end_time_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.end_hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.end_hour.set_value(17)
        self.end_hour.set_width_chars(3)
        end_time_row.append(self.end_hour)
        end_time_row.append(Gtk.Label(label=":"))
        self.end_min = Gtk.SpinButton.new_with_range(0, 59, 5)
        self.end_min.set_value(0)
        self.end_min.set_width_chars(3)
        end_time_row.append(self.end_min)
        end_box.append(end_time_row)
        time_box.append(end_box)

        box.append(time_box)

        # Preset buttons
        preset_lbl = Gtk.Label(label="PRESETS", xalign=0)
        preset_lbl.add_css_class("subheading")
        box.append(preset_lbl)

        presets_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for label, mask in [
            ("Weekdays", 0b0011111),
            ("Weekends", 0b1100000),
            ("Every day", 0b1111111),
        ]:
            btn = Gtk.Button(label=label)
            btn.connect("clicked", self._apply_preset, mask)
            presets_box.append(btn)
        box.append(presets_box)

        # Day toggles
        days_lbl = Gtk.Label(label="DAYS", xalign=0)
        days_lbl.add_css_class("subheading")
        box.append(days_lbl)

        days_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.day_buttons = []
        for i, (short, full) in enumerate(zip(DAY_LABELS, DAY_FULL)):
            btn = Gtk.ToggleButton(label=short)
            btn.add_css_class("day-toggle")
            btn.set_tooltip_text(full)
            # Default: weekdays
            if i < 5:
                btn.set_active(True)
            self.day_buttons.append(btn)
            days_box.append(btn)
        box.append(days_box)

        self.set_extra_child(box)

    def _apply_preset(self, _btn, mask: int) -> None:
        for i, btn in enumerate(self.day_buttons):
            btn.set_active(bool(mask & (1 << i)))
