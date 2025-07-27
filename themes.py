import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

def get_available_themes():
    return ["Adwaita", "Adwaita-dark", "HighContrast", "Arc", "Arc-Dark"]

def apply_theme(theme_name):
    settings = Gtk.Settings.get_default()
    try:
        settings.set_property("gtk-theme-name", theme_name)
    except Exception as e:
        # Tema değiştirilemezse sorun çıkarmaz
        print(f"Theme apply error: {e}")
