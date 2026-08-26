"""
CipherPick GTK+ GUI — Application Entry Point
Loads the GTK CSS theme and launches the main window.
"""
import os
import sys

# Add project root to path so backend modules resolve correctly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib

from .app_window import AppWindow

_CSS_PATH = os.path.join(os.path.dirname(__file__), 'style.css')


def _load_css():
    """Load the cyberpunk GTK CSS theme."""
    provider = Gtk.CssProvider()
    try:
        provider.load_from_path(_CSS_PATH)
    except Exception as e:
        print(f"[!] CSS load warning: {e}", file=sys.stderr)
    screen = Gdk.Screen.get_default()
    Gtk.StyleContext.add_provider_for_screen(
        screen,
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )


class CipherPickApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id='io.cipherpick.c2')
        self._window = None

    def do_activate(self):
        _load_css()
        if not self._window:
            self._window = AppWindow(application=self)
        self._window.present()


def main():
    import signal
    app = CipherPickApp()
    # Allow Ctrl+C to terminate cleanly
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sys.exit(app.run(sys.argv))


if __name__ == '__main__':
    main()
