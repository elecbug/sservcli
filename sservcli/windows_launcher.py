"""Runtime checks and console-free desktop launch for the Windows ZIP."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def check_runtime():
    if sys.version_info < (3, 11):
        raise RuntimeError("Install Python 3.11 or newer from python.org, including Tcl/Tk and the Python launcher")
    try:
        import tkinter
        import _tkinter
    except ImportError as error:
        raise RuntimeError("Install Python with Tcl/Tk enabled; tkinter is required for the desktop") from error
    from .tunnel import openssh_program, process_options
    for name in ("ssh", "ssh-keygen"):
        program = openssh_program(name)
        if name == "ssh":
            result = subprocess.run([program, "-V"], capture_output=True, timeout=10, **process_options())
            if result.returncode:
                raise RuntimeError("OpenSSH Client could not start")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    try:
        check_runtime()
        if not args.start:
            print("Ready. Python, Tkinter, and OpenSSH are available. Run Start.cmd; compilation is not required.")
            return 0
        from .instance import state_directory
        executable = Path(sys.executable)
        if os.name == "nt":
            executable = executable.with_name("pythonw.exe")
            if not executable.is_file():
                raise RuntimeError("pythonw.exe is missing; repair your Python installation")
        command = [str(executable), "-m", "sservcli", "desktop", "--background"]
        if args.config and args.config.is_file():
            command += ["--config", str(args.config.resolve())]
        with (state_directory() / "desktop.log").open("a", encoding="utf-8") as log:
            subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                             start_new_session=os.name != "nt")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"sservcli: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
