"""Opt-in real Tk widget checks; no connections or account changes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("SSERVCLI_GUI_TESTS") == "1", "Set SSERVCLI_GUI_TESTS=1 with a graphical display")
class DesktopTests(unittest.TestCase):
    def setUp(self):
        import tkinter
        from sservcli.desktop import Desktop
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = tkinter.Tk()
        self.root.withdraw()
        self.app = Desktop(self.root, directory=self.directory, use_tray=False)
        self.addCleanup(self.app.quit)

    def test_catalog_json_setup_and_copy_use_the_same_profile(self):
        profile = json.loads((ROOT / "client/examples/services.json").read_text())
        profile["ssh"]["fallback_hosts"] = ["192.0.2.2", "192.0.2.3"]
        path = self.directory / "services.json"
        path.write_text(json.dumps(profile))
        self.app.load(path)
        self.root.update()
        self.assertEqual(self.app.services.get_children(), ("dashboard", "postgres", "api"))
        self.assertEqual(json.loads(self.app.fields["fallback"].get()), ["192.0.2.2", "192.0.2.3"])
        self.assertEqual(json.loads(self.app.editor.get("1.0", "end")), profile)
        self.app.services.selection_set("dashboard")
        self.app.copy_address()
        self.assertEqual(self.root.clipboard_get(), "http://127.0.0.1:18080/")
        self.assertEqual(json.loads((self.directory / "preferences.json").read_text())["config_path"], str(path))

    def test_launch_is_disabled_until_connected_and_failure_shows_the_window(self):
        self.app.load(ROOT / "client/examples/services.json")
        self.app.services.selection_set("dashboard")
        with patch("sservcli.desktop.launch_service") as launch, patch("sservcli.desktop.messagebox.showerror") as error:
            self.app.open_service()
            launch.assert_not_called()
            error.assert_called_once()
        self.app.tunnel._update("connected", "Connected", host="192.0.2.1")
        self.app.poll()
        self.assertEqual(self.app.services.item("dashboard", "values")[-1], "ready")
        with patch("sservcli.desktop.launch_service") as launch:
            self.app.open_service()
            launch.assert_called_once()
        self.app.tunnel._update("failed", "Host key verification failed")
        self.app.poll()
        self.root.update()
        self.assertEqual(self.root.state(), "normal")

    def test_quick_edit_preserves_custom_services_and_launch_commands(self):
        profile = json.loads((ROOT / "client/examples/services.json").read_text())
        custom = {"id": "metrics", "name": "Custom metrics", "kind": "web", "remote_host": "127.0.0.1", "remote_port": 9090, "local_port": 19090}
        profile["services"].append(custom)
        path = self.directory / "services.json"
        path.write_text(json.dumps(profile))
        self.app.load(path)
        self.app.quick_services[0][1].set("8081")
        self.app.quick_services[0][2].set("18081")
        self.app.quick_services[1][0].set(False)
        with patch.object(self.app, "save_config") as save:
            self.app.save_quick()
            saved = save.call_args.args[0]
        self.assertEqual(saved["services"][0]["remote_port"], 8081)
        self.assertEqual(saved["services"][0]["local_port"], 18081)
        self.assertFalse(saved["services"][1]["enabled"])
        self.assertEqual(saved["services"][1]["launch"], profile["services"][1]["launch"])
        self.assertEqual(saved["services"][3], custom)
        self.assertEqual(self.app.config, profile)

    def test_startup_auto_connects_all_enabled_services_and_tray_close_keeps_tunnel(self):
        from sservcli.desktop import Desktop
        from unittest.mock import Mock
        profile = json.loads((ROOT / "client/examples/services.json").read_text())
        profile["ssh"]["identity_file"] = None
        path = self.directory / "startup.json"
        path.write_text(json.dumps(profile))
        self.app.quit()
        import tkinter
        self.root = tkinter.Tk()
        with patch.object(Desktop, "connect") as connect:
            self.app = Desktop(self.root, path, directory=self.directory, use_tray=False)
            self.root.after(250, self.root.quit)
            self.root.mainloop()
            connect.assert_called_once()
        self.addCleanup(self.app.quit)
        self.app.tray = Mock()
        with patch.object(self.app.tunnel, "disconnect") as disconnect:
            self.app.hide()
            self.root.update()
            self.assertEqual(self.root.state(), "withdrawn")
            disconnect.assert_not_called()
            self.app.actions.put("show")
            self.app.poll()
            self.root.update()
            self.assertEqual(self.root.state(), "normal")


if __name__ == "__main__":
    unittest.main()
