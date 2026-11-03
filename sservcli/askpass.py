"""OpenSSH askpass helper. The token is supplied only in the child environment."""
import os
from pathlib import Path
import re
import shlex
import sys

TOKEN_ENV = "SSERVCLI_ASKPASS_TOKEN"


def environment(token, directory):
    if not re.fullmatch(r"[A-Za-z0-9]{8}", token):
        raise ValueError("Expected an 8-character token")
    values = dict(os.environ)
    values.pop("SSERVCLI_TOKEN", None)
    values.pop("SSH_ASKPASS_PROMPT", None)
    script = Path(__file__).resolve()
    executable = Path(sys.executable).resolve()
    if os.name == "nt":
        executable = executable.with_name("pythonw.exe")
        if not executable.is_file():
            raise OSError("pythonw.exe is required for background OpenSSH authentication")
        # Windows OpenSSH's build_commandline_string preserves a quoted
        # executable/argument string. No cmd.exe or shell interprets this value.
        values["SSH_ASKPASS"] = f'"{executable}" "{script}"'
    else:
        wrapper = Path(directory) / "askpass"
        wrapper.write_text(f"#!/bin/sh\nexec {shlex.quote(str(executable))} {shlex.quote(str(script))}\n", encoding="utf-8")
        wrapper.chmod(0o700)
        values["SSH_ASKPASS"] = str(wrapper)
    values.update(SSH_ASKPASS_REQUIRE="force", DISPLAY="sservcli:0")
    values[TOKEN_ENV] = token
    return values


def main():
    token = os.environ.pop(TOKEN_ENV, "")
    if not re.fullmatch(r"[A-Za-z0-9]{8}", token) or os.environ.get("SSH_ASKPASS_PROMPT") in ("confirm", "none"):
        return 1
    data = (token + "\n").encode("ascii")
    if os.name == "nt":
        # pythonw may set sys.stdout=None even though OpenSSH supplied a pipe.
        # Write to that inherited standard handle directly, without a console.
        import ctypes as C
        kernel = C.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.argtypes = [C.c_uint32]
        kernel.GetStdHandle.restype = C.c_void_p
        kernel.WriteFile.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32, C.POINTER(C.c_uint32), C.c_void_p]
        kernel.WriteFile.restype = C.c_int
        handle = kernel.GetStdHandle(0xfffffff5)
        written = C.c_uint32()
        if not kernel.WriteFile(handle, data, len(data), C.byref(written), None) or written.value != len(data):
            return 1
    else:
        os.write(1, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
