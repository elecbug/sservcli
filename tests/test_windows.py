"""Real Win32 process/listener tests on Windows; table parsing on all platforms."""
import os
import queue
import socket
import struct
import subprocess
import sys
import unittest

from sservcli.windows import table_owns_ports


class TcpTableTests(unittest.TestCase):
    def test_listener_must_belong_to_ssh_pid_on_loopback_for_every_requested_port(self):
        localhost = int.from_bytes(socket.inet_aton("127.0.0.1"), "little")
        def table(*rows):
            return struct.pack("<I", len(rows)) + b"".join(struct.pack("<6I", *row) for row in rows)
        first = (2, localhost, socket.htons(18080), 0, 0, 123)
        second = (2, localhost, socket.htons(15432), 0, 0, 123)
        self.assertTrue(table_owns_ports(table(first, second), 123, [18080, 15432]))
        self.assertFalse(table_owns_ports(table(first), 123, [18080, 15432]))
        self.assertFalse(table_owns_ports(table(first), 124, [18080]))
        self.assertFalse(table_owns_ports(table((2, 0, socket.htons(18080), 0, 0, 123)), 123, [18080]))
        with self.assertRaisesRegex(OSError, "Truncated"):
            table_owns_ports(struct.pack("<I", 100), 123, [18080])


@unittest.skipUnless(os.name == "nt", "Native Windows API tests")
class NativeWindowsTests(unittest.TestCase):
    def test_remembered_token_uses_current_user_data_protection(self):
        from sservcli.windows import protect_secret, unprotect_secret
        protected = protect_secret("aB3dE5gH")
        self.assertNotIn("aB3dE5gH", protected)
        self.assertEqual(unprotect_secret(protected), "aB3dE5gH")

    def test_tcp_listener_ownership_uses_the_real_process_table(self):
        from sservcli.windows import listeners_owned_by
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            self.assertTrue(listeners_owned_by(os.getpid(), [port]))
            self.assertFalse(listeners_owned_by(0, [port]))

    def test_job_close_terminates_the_managed_child(self):
        from sservcli.windows import ChildJob
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], creationflags=subprocess.CREATE_NO_WINDOW)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        job = ChildJob(child)
        self.addCleanup(job.close)
        self.assertIsNone(child.poll())
        job.close()
        child.wait(timeout=5)
        self.assertNotEqual(child.returncode, 0)

    def test_native_tray_starts_and_stops_its_message_thread(self):
        import ctypes
        from sservcli.windows import Tray, api
        find_window = api("user32", "FindWindowW", ctypes.c_void_p, [ctypes.c_wchar_p, ctypes.c_wchar_p])
        if not find_window("Shell_TrayWnd", None):
            self.skipTest("An interactive Windows notification area is required")
        tray = Tray(queue.Queue())
        self.addCleanup(tray.close)
        self.assertIsNotNone(tray.window)
        tray.close()
        self.assertFalse(tray.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
