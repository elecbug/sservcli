"""Minimal Win32 bindings through ctypes; no additional Python packages."""
import ctypes as C
import os
import socket
import struct
import threading

DWORD = C.c_uint32
HANDLE = C.c_void_p
SIZE_T = C.c_size_t


class DataBlob(C.Structure):
    _fields_ = [("size", DWORD), ("data", C.POINTER(C.c_ubyte))]


def _secret_blob(data):
    buffer = (C.c_ubyte * len(data)).from_buffer_copy(data)
    return DataBlob(len(data), buffer), buffer


def protect_secret(text):
    import base64
    source, buffer = _secret_blob(text.encode("utf-8"))
    destination = DataBlob()
    protect = api("crypt32", "CryptProtectData", C.c_int,
                  [C.POINTER(DataBlob), C.c_wchar_p, C.POINTER(DataBlob), HANDLE, HANDLE, DWORD, C.POINTER(DataBlob)])
    if not protect(C.byref(source), "sservcli shared token", None, None, None, 1, C.byref(destination)):
        raise C.WinError(C.get_last_error())
    try:
        return base64.b64encode(C.string_at(destination.data, destination.size)).decode("ascii")
    finally:
        api("kernel32", "LocalFree", HANDLE, [HANDLE])(C.cast(destination.data, HANDLE))


def unprotect_secret(text):
    import base64
    source, buffer = _secret_blob(base64.b64decode(text, validate=True))
    destination = DataBlob()
    unprotect = api("crypt32", "CryptUnprotectData", C.c_int,
                    [C.POINTER(DataBlob), HANDLE, C.POINTER(DataBlob), HANDLE, HANDLE, DWORD, C.POINTER(DataBlob)])
    if not unprotect(C.byref(source), None, None, None, None, 1, C.byref(destination)):
        raise C.WinError(C.get_last_error())
    try:
        return C.string_at(destination.data, destination.size).decode("utf-8")
    finally:
        api("kernel32", "LocalFree", HANDLE, [HANDLE])(C.cast(destination.data, HANDLE))


def api(library, name, result, arguments):
    if os.name != "nt":
        raise OSError("This operation requires Windows")
    function = getattr(C.WinDLL(library, use_last_error=True), name)
    function.restype = result
    function.argtypes = arguments
    return function


def table_owns_ports(data, pid, ports):
    if len(data) < 4:
        raise OSError("Missing Windows TCP table header")
    count, = struct.unpack_from("<I", data)
    if count > (len(data) - 4) // 24:
        raise OSError("Truncated Windows TCP listener table")
    owned = set()
    localhost = int.from_bytes(socket.inet_aton("127.0.0.1"), "little")
    for row in struct.iter_unpack("<6I", data[4:4 + count * 24]):
        if row[0] == 2 and row[1] == localhost and row[5] == pid:
            owned.add(socket.ntohs(row[2] & 0xffff))
    return bool(ports) and set(ports).issubset(owned)


def listeners_owned_by(pid, ports):
    get_table = api("iphlpapi", "GetExtendedTcpTable", DWORD, [HANDLE, C.POINTER(DWORD), C.c_int, DWORD, C.c_int, DWORD])
    size = DWORD()
    result = get_table(None, C.byref(size), False, 2, 3, 0)
    for _ in range(5):
        if result not in (0, 122):
            raise OSError(f"Cannot inspect SSH listeners: Windows error {result}")
        buffer = C.create_string_buffer(max(size.value, 4))
        result = get_table(buffer, C.byref(size), False, 2, 3, 0)
        if result == 122:
            continue
        if result:
            raise OSError(f"Cannot inspect SSH listeners: Windows error {result}")
        return table_owns_ports(buffer.raw[:size.value], pid, ports)
    raise OSError("Windows TCP listener table kept changing; try again")


class BasicLimits(C.Structure):
    _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64), ("flags", DWORD),
                ("minimum_working_set", SIZE_T), ("maximum_working_set", SIZE_T),
                ("active_processes", DWORD), ("affinity", SIZE_T), ("priority", DWORD), ("scheduling", DWORD)]


class ExtendedLimits(C.Structure):
    _fields_ = [("basic", BasicLimits), ("io", C.c_uint64 * 6), ("process_memory", SIZE_T),
                ("job_memory", SIZE_T), ("peak_process_memory", SIZE_T), ("peak_job_memory", SIZE_T)]


class ChildJob:
    """Closing the parent or this job handle terminates the managed SSH process."""
    def __init__(self, child):
        self.handle = None
        self.close_handle = api("kernel32", "CloseHandle", C.c_int, [HANDLE])
        create = api("kernel32", "CreateJobObjectW", HANDLE, [HANDLE, C.c_wchar_p])
        self.handle = create(None, None)
        if not self.handle:
            raise C.WinError(C.get_last_error())
        try:
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            set_info = api("kernel32", "SetInformationJobObject", C.c_int, [HANDLE, C.c_int, HANDLE, DWORD])
            assign = api("kernel32", "AssignProcessToJobObject", C.c_int, [HANDLE, HANDLE])
            if not set_info(self.handle, 9, C.byref(limits), C.sizeof(limits)) or not assign(self.handle, int(child._handle)):
                raise C.WinError(C.get_last_error())
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.close_handle(self.handle)
            self.handle = None


class Tray:
    """Own a hidden native message window on its own thread; queue actions to Tk."""
    def __init__(self, actions):
        self.actions = actions
        self.window = None
        self.error = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready.wait(5):
            raise OSError("Windows tray did not start")
        if self.error:
            raise OSError(str(self.error))

    def close(self):
        if self.window:
            api("user32", "PostMessageW", C.c_int, [HANDLE, DWORD, SIZE_T, C.c_ssize_t])(self.window, 0x10, 0, 0)
        self.thread.join(timeout=3)

    def _run(self):
        try:
            self._message_loop()
        except BaseException as error:
            self.error = error
        finally:
            self.ready.set()

    def _message_loop(self):
        from ctypes import wintypes as W
        callback_type = C.WINFUNCTYPE(C.c_ssize_t, HANDLE, DWORD, SIZE_T, C.c_ssize_t)

        class WindowClass(C.Structure):
            _fields_ = [("style", DWORD), ("procedure", callback_type), ("class_extra", C.c_int), ("window_extra", C.c_int),
                        ("instance", HANDLE), ("icon", HANDLE), ("cursor", HANDLE), ("background", HANDLE),
                        ("menu", C.c_wchar_p), ("name", C.c_wchar_p)]

        class NotifyIcon(C.Structure):
            _fields_ = [("size", DWORD), ("window", HANDLE), ("id", DWORD), ("flags", DWORD), ("message", DWORD),
                        ("icon", HANDLE), ("tip", C.c_wchar * 128), ("state", DWORD), ("state_mask", DWORD),
                        ("info", C.c_wchar * 256), ("timeout", DWORD), ("title", C.c_wchar * 64), ("info_flags", DWORD),
                        ("guid", C.c_byte * 16), ("balloon_icon", HANDLE)]

        module = api("kernel32", "GetModuleHandleW", HANDLE, [C.c_wchar_p])(None)
        notify = api("shell32", "Shell_NotifyIconW", C.c_int, [DWORD, C.POINTER(NotifyIcon)])
        default = api("user32", "DefWindowProcW", C.c_ssize_t, [HANDLE, DWORD, SIZE_T, C.c_ssize_t])
        destroy = api("user32", "DestroyWindow", C.c_int, [HANDLE])
        post_quit = api("user32", "PostQuitMessage", None, [C.c_int])
        taskbar_created = api("user32", "RegisterWindowMessageW", DWORD, [C.c_wchar_p])("TaskbarCreated")
        icon = NotifyIcon()
        icon.size = C.sizeof(icon)
        icon.id, icon.flags, icon.message = 1, 7, 0x8001
        icon.icon = api("user32", "LoadIconW", HANDLE, [HANDLE, HANDLE])(None, 32512)
        icon.tip = "sservcli - double-click to show services"

        @callback_type
        def procedure(window, message, wparam, lparam):
            if message == taskbar_created:
                notify(0, C.byref(icon))
                return 0
            if message == 0x8001:
                if lparam in (0x202, 0x203):  # left click / double click
                    self.actions.put("show")
                elif lparam == 0x205:
                    self._menu(window)
                return 0
            if message == 0x10:
                destroy(window)
                return 0
            if message == 2:
                notify(2, C.byref(icon))
                post_quit(0)
                return 0
            return default(window, message, wparam, lparam)

        name = f"sservcli-tray-{os.getpid()}-{id(self)}"
        wc = WindowClass()
        wc.procedure, wc.instance, wc.name = procedure, module, name
        register = api("user32", "RegisterClassW", C.c_uint16, [C.POINTER(WindowClass)])
        if not register(C.byref(wc)):
            raise C.WinError(C.get_last_error())
        try:
            create = api("user32", "CreateWindowExW", HANDLE, [DWORD, C.c_wchar_p, C.c_wchar_p, DWORD,
                         C.c_int, C.c_int, C.c_int, C.c_int, HANDLE, HANDLE, HANDLE, HANDLE])
            self.window = create(0, name, "sservcli tray", 0, 0, 0, 0, 0, None, None, module, None)
            if not self.window:
                raise C.WinError(C.get_last_error())
            icon.window = self.window
            if not notify(0, C.byref(icon)):
                raise C.WinError(C.get_last_error())
            self.ready.set()
            get_message = api("user32", "GetMessageW", C.c_int, [C.POINTER(W.MSG), HANDLE, DWORD, DWORD])
            translate = api("user32", "TranslateMessage", C.c_int, [C.POINTER(W.MSG)])
            dispatch = api("user32", "DispatchMessageW", C.c_ssize_t, [C.POINTER(W.MSG)])
            message = W.MSG()
            while True:
                result = get_message(C.byref(message), None, 0, 0)
                if result <= 0:
                    break
                translate(C.byref(message))
                dispatch(C.byref(message))
        finally:
            if self.window:
                notify(2, C.byref(icon))
                destroy(self.window)
                self.window = None
            api("user32", "UnregisterClassW", C.c_int, [C.c_wchar_p, HANDLE])(name, module)

    def _menu(self, window):
        from ctypes import wintypes as W
        menu = api("user32", "CreatePopupMenu", HANDLE, [])()
        try:
            append = api("user32", "AppendMenuW", C.c_int, [HANDLE, DWORD, SIZE_T, C.c_wchar_p])
            actions = ("show", "connect", "disconnect", "quit")
            for index, label in enumerate(("Show services", "Connect", "Disconnect", "Quit"), 1):
                append(menu, 0, index, label)
            point = W.POINT()
            api("user32", "GetCursorPos", C.c_int, [C.POINTER(W.POINT)])(C.byref(point))
            api("user32", "SetForegroundWindow", C.c_int, [HANDLE])(window)
            track = api("user32", "TrackPopupMenu", C.c_uint, [HANDLE, C.c_uint, C.c_int, C.c_int, C.c_int, HANDLE, HANDLE])
            selected = track(menu, 0x102, point.x, point.y, 0, window, None)
            if 1 <= selected <= len(actions):
                self.actions.put(actions[selected - 1])
            api("user32", "PostMessageW", C.c_int, [HANDLE, DWORD, SIZE_T, C.c_ssize_t])(window, 0, 0, 0)
        finally:
            api("user32", "DestroyMenu", C.c_int, [HANDLE])(menu)
