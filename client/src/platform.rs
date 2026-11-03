//! Native process, path, browser, and console integration.
use std::{
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
};

static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static CLEANED_UP: AtomicBool = AtomicBool::new(false);

pub(crate) fn ssh_command() -> Command {
    openssh_command("ssh")
}

pub(crate) fn openssh_command(program: &str) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Prefer native OpenSSH over Git/WSL wrappers that may start another
        // process or expect a different agent and path syntax.
        let native = std::env::var_os("SystemRoot")
            .map(|root| {
                std::path::PathBuf::from(root).join(format!("System32/OpenSSH/{program}.exe"))
            })
            .filter(|path| path.is_file());
        let mut command = Command::new(native.unwrap_or_else(|| format!("{program}.exe").into()));
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        command
    }
    #[cfg(not(windows))]
    Command::new(program)
}

/// OpenSSH accepts Windows drive/UNC paths using forward slashes, without the
/// verbatim prefix produced by Rust's Windows canonicalize().
pub(crate) fn ssh_path(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("SSH paths must be valid Unicode")?;
    #[cfg(windows)]
    {
        let text = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            format!("//{rest}")
        } else {
            text.strip_prefix(r"\\?\").unwrap_or(text).to_owned()
        };
        Ok(text.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    Ok(text.to_owned())
}

pub(crate) fn home_dir() -> Option<std::ffi::OsString> {
    #[cfg(windows)]
    let variables = ["USERPROFILE", "HOME"];
    #[cfg(not(windows))]
    let variables = ["HOME"];
    variables
        .iter()
        .find_map(|key| std::env::var_os(key).filter(|v| !v.is_empty()))
}

pub(crate) fn open_url(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::windows::open_url(url)
    }
    #[cfg(not(windows))]
    {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let mut child = Command::new(opener)
            .arg(url)
            .spawn()
            .map_err(|e| format!("Cannot open browser: {e}"))?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

/// Format the diagnostic command for PowerShell on Windows, POSIX shells on
/// Unix. Runtime process creation always passes arguments directly.
pub fn format_ssh_command(args: &[String]) -> String {
    #[cfg(windows)]
    let quote: fn(&str) -> String = |s| format!("'{}'", s.replace('\'', "''"));
    #[cfg(windows)]
    let program = format!(
        "& {}",
        quote(&ssh_command().get_program().to_string_lossy())
    );
    #[cfg(not(windows))]
    let (program, quote): (&str, fn(&str) -> String) =
        ("ssh", |s| format!("'{}'", s.replace('\'', "'\\''")));
    format!(
        "{program} {}",
        args.iter()
            .map(|arg| quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

#[cfg(windows)]
extern "system" fn console_handler(event: u32) -> i32 {
    match event {
        0 | 1 => {
            // CTRL_C_EVENT / CTRL_BREAK_EVENT
            STOP.store(true, Ordering::SeqCst);
            1
        }
        2 | 5 | 6 => {
            // Console close, logoff, shutdown.
            STOP.store(true, Ordering::SeqCst);
            // Windows terminates the process when this handler returns. Give
            // the main thread a bounded opportunity to disconnect first.
            for _ in 0..80 {
                if CLEANED_UP.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            1
        }
        _ => 0,
    }
}

#[cfg(unix)]
extern "C" fn signal_handler(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn install_shutdown_handler() -> Result<(), String> {
    #[cfg(windows)]
    {
        // SAFETY: console_handler has the required ABI and static lifetime.
        if unsafe { crate::windows::SetConsoleCtrlHandler(Some(console_handler), 1) } == 0 {
            return Err(format!(
                "Cannot install console handler: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    #[cfg(unix)]
    unsafe {
        // SAFETY: the handlers only update a static atomic flag.
        if libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t) == libc::SIG_ERR
            || libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t) == libc::SIG_ERR
        {
            return Err(format!(
                "Cannot install signal handler: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub fn shutdown_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Call after all connection guards have been dropped, including error paths.
pub fn shutdown_complete() {
    #[cfg(windows)]
    CLEANED_UP.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_display_quotes_metacharacters_and_apostrophes() {
        let result = format_ssh_command(&["a'b & $HOME".into()]);
        #[cfg(windows)]
        {
            assert!(result.starts_with("& '"));
            assert!(result.ends_with(" 'a''b & $HOME'"));
        }
        #[cfg(not(windows))]
        assert_eq!(result, "ssh 'a'\\''b & $HOME'");
    }

    #[cfg(windows)]
    #[test]
    fn normalizes_drive_unc_and_unicode_paths_for_openssh() {
        assert_eq!(
            ssh_path(Path::new(r"\\?\C:\Users\한 글\.ssh\known_hosts")).unwrap(),
            "C:/Users/한 글/.ssh/known_hosts"
        );
        assert_eq!(
            ssh_path(Path::new(r"\\?\UNC\server\share\known_hosts")).unwrap(),
            "//server/share/known_hosts"
        );
    }
}
