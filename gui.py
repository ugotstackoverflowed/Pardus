import gi
import threading
import time
import os
from scanner.hash_scanner import scan_hash
from scanner.yara_scanner import scan_yara
from scanner.realtime_monitor import monitor_multiple
from scanner.clam_hash_scanner import load_clamav_hashes, scan_file_with_clam_hashes  # [CLAMAV]
from i18n import t, set_language
from themes import get_available_themes, apply_theme
from scanner.clam_hash_scanner import load_clamav_hashes, scan_file_with_clam_hashes

CLAM_HASHES = load_clamav_hashes("/var/lib/clamav/daily.hdb")

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

LOG_FILE = "logs/antivirus.log"

def log_message(gui_ref, message):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S] ")
    full_message = timestamp + message

    GLib.idle_add(gui_ref.append_log, full_message)

    with open(LOG_FILE, "a") as f:
        f.write(full_message + "\n")

class AntivirusWindow(Gtk.Window):
    def __init__(self):
        Gtk.Window.__init__(self, title=t("title"))
        self.set_border_width(20)
        self.set_default_size(650, 450)

        self.threat_count = 0
        self.realtime_active = False

        # [CLAMAV] ClamAV hash veritabanını yükle
        try:
            self.clam_hashes = load_clamav_hashes("/var/lib/clamav/daily.hdb")  # yolu ihtiyaç olursa değiştir
            log_message(self, "[✓] ClamAV hash veritabanı yüklendi.")
        except Exception as e:
            self.clam_hashes = set()
            log_message(self, f"[!] ClamAV veritabanı yüklenemedi: {e}")

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.add(main_box)

        button_box = Gtk.Box(spacing=8)
        main_box.pack_start(button_box, False, False, 0)

        self.build_theme_selector(button_box)
        self.build_language_selector(button_box)

        self.start_button = Gtk.Button(label=t("start_realtime"))
        self.start_button.connect("clicked", self.on_start_clicked)
        button_box.pack_start(self.start_button, True, True, 0)

        self.manual_button = Gtk.Button(label=t("manual_scan"))
        self.manual_button.connect("clicked", self.on_manual_scan)
        button_box.pack_start(self.manual_button, True, True, 0)

        self.quit_button = Gtk.Button(label=t("quit"))
        self.quit_button.connect("clicked", Gtk.main_quit)
        button_box.pack_start(self.quit_button, True, True, 0)

        self.threat_label = Gtk.Label(label=t("threat_count").format(self.threat_count))
        main_box.pack_start(self.threat_label, False, False, 0)

        self.log_buffer = Gtk.TextBuffer()
        self.log_view = Gtk.TextView(buffer=self.log_buffer)
        self.log_view.set_editable(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD)

        scroll = Gtk.ScrolledWindow()
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        scroll.add(self.log_view)
        main_box.pack_start(scroll, True, True, 0)

    def build_theme_selector(self, parent_box):
        theme_box = Gtk.Box(spacing=5)

        theme_label = Gtk.Label(label=t("theme_label"))
        theme_box.pack_start(theme_label, False, False, 0)

        self.theme_combo = Gtk.ComboBoxText()
        for theme in get_available_themes():
            self.theme_combo.append_text(theme)

        current_theme = Gtk.Settings.get_default().get_property("gtk-theme-name")
        themes = get_available_themes()
        if current_theme in themes:
            self.theme_combo.set_active(themes.index(current_theme))
        else:
            self.theme_combo.set_active(0)

        self.theme_combo.connect("changed", self.on_theme_changed)
        theme_box.pack_start(self.theme_combo, False, False, 0)

        parent_box.pack_start(theme_box, False, False, 0)

    def on_theme_changed(self, combo):
        theme = combo.get_active_text()
        apply_theme(theme)
        log_message(self, t("theme_changed").format(theme))

    def build_language_selector(self, parent_box):
        lang_box = Gtk.Box(spacing=5)

        lang_label = Gtk.Label(label=t("language_label"))
        lang_box.pack_start(lang_label, False, False, 0)

        self.lang_combo = Gtk.ComboBoxText()
        self.lang_combo.append_text("Türkçe")
        self.lang_combo.append_text("English")
        self.lang_combo.set_active(0)
        self.lang_combo.connect("changed", self.on_language_changed)
        lang_box.pack_start(self.lang_combo, False, False, 0)

        parent_box.pack_start(lang_box, False, False, 0)

    def on_language_changed(self, combo):
        selected = combo.get_active_text()
        if selected == "Türkçe":
            set_language("tr")
        else:
            set_language("en")

        self.update_labels()
        log_message(self, t("language_changed").format(selected))

    def update_labels(self):
        self.set_title(t("title"))
        self.start_button.set_label(t("start_realtime"))
        self.manual_button.set_label(t("manual_scan"))
        self.quit_button.set_label(t("quit"))
        self.threat_label.set_text(t("threat_count").format(self.threat_count))
        self.theme_combo.get_parent().get_children()[0].set_label(t("theme_label"))
        self.lang_combo.get_parent().get_children()[0].set_label(t("language_label"))

    def append_log(self, text):
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text + "\n")

    def increment_threat(self):
        self.threat_count += 1
        self.threat_label.set_text(t("threat_count").format(self.threat_count))

    def on_start_clicked(self, button):
        if not self.realtime_active:
            paths = ["/home", "/tmp", "/var/tmp"]
            thread = threading.Thread(target=self.start_realtime, args=(paths,), daemon=True)
            thread.start()
            self.realtime_active = True
            button.set_sensitive(False)
            log_message(self, t("realtime_started"))

    def start_realtime(self, paths):
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class RealtimeHandler(FileSystemEventHandler):
            def on_created(s, event):
                if not event.is_directory:
                    log_message(self, t("new_file").format(event.src_path))
                    self.scan_file(event.src_path)

            def on_modified(s, event):
                if not event.is_directory:
                    log_message(self, t("modified_file").format(event.src_path))
                    self.scan_file(event.src_path)

        def monitor(paths):
            event_handler = RealtimeHandler()
            observer = Observer()
            for path in paths:
                try:
                    observer.schedule(event_handler, path=path, recursive=True)
                    log_message(self, t("monitoring").format(path))
                except Exception as e:
                    log_message(self, t("error_monitoring").format(path, e))
            observer.start()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
            observer.join()

        monitor(paths)

    def scan_file(self, path):
        try:
            if scan_hash(path):
                log_message(self, t("threat_found").format(path))
                GLib.idle_add(self.increment_threat)

            # [CLAMAV] ClamAV hash taraması
            if scan_file_with_clam_hashes(path, self.clam_hashes):
                log_message(self, "[!] ClamAV veritabanına göre tehdit bulundu: " + path)
                GLib.idle_add(self.increment_threat)

            if scan_yara(path):
                log_message(self, t("threat_found").format(path))
                GLib.idle_add(self.increment_threat)

        except Exception as e:
            log_message(self, t("error_scanning").format(e))

    def on_manual_scan(self, button):
        dialog = Gtk.FileChooserDialog(
            title=t("select_file"),
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                           Gtk.STOCK_OPEN, Gtk.ResponseType.OK)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            filepath = dialog.get_filename()
            log_message(self, t("scanning").format(filepath))

            if scan_file_with_clam_hashes(filepath, CLAM_HASHES):
                self.append_log(f"[!] ClamAV: Zararlı bulundu: {filepath}")
            else:
                self.append_log(f"[✓] ClamAV: Temiz: {filepath}")

            self.scan_file(filepath)

        dialog.destroy()


if __name__ == "__main__":
    from themes import apply_theme
    current_theme = Gtk.Settings.get_default().get_property("gtk-theme-name")
    apply_theme(current_theme)

    win = AntivirusWindow()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()
