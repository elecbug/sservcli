//! Small Win32 bindings; no shell commands or localized SSH log parsing.
use std::{ffi::c_void, mem, os::windows::io::AsRawHandle, process::Child, ptr};

type Handle = *mut c_void;

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        af: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    pub(crate) fn SetConsoleCtrlHandler(
        handler: Option<extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: u32, info: *const c_void, size: u32) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteW(
        window: Handle,
        operation: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show: i32,
    ) -> Handle;
}

#[link(name = "ole32")]
extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
    fn CoUninitialize();
}

pub(crate) fn listeners_owned_by(pid: u32, ports: &[u16]) -> Result<bool, String> {
    const INSUFFICIENT_BUFFER: u32 = 122;
    const AF_INET: u32 = 2;
    const OWNER_PID_LISTENER: u32 = 3;
    let mut size = 0;
    // SAFETY: a null output buffer requests its size; all scalar/pointer types
    // match GetExtendedTcpTable's documented IPv4 OWNER_PID_LISTENER API.
    let mut result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            OWNER_PID_LISTENER,
            0,
        )
    };
    for _ in 0..5 {
        if result != 0 && result != INSUFFICIENT_BUFFER {
            return Err(format!(
                "Cannot inspect SSH listeners: Windows error {result}"
            ));
        }
        // DWORD-aligned storage for the count and MIB_TCPROW_OWNER_PID rows.
        let mut table = vec![0_u32; (size as usize + 3) / 4];
        if table.is_empty() {
            return Ok(false);
        }
        let mut available = (table.len() * 4) as u32;
        // SAFETY: table is aligned, writable, and its full byte capacity is
        // supplied. A growing table returns INSUFFICIENT_BUFFER and is retried.
        result = unsafe {
            GetExtendedTcpTable(
                table.as_mut_ptr().cast(),
                &mut available,
                0,
                AF_INET,
                OWNER_PID_LISTENER,
                0,
            )
        };
        size = available;
        if result == INSUFFICIENT_BUFFER {
            continue;
        }
        if result != 0 {
            return Err(format!(
                "Cannot inspect SSH listeners: Windows error {result}"
            ));
        }
        return table_owns_ports(&table, pid, ports);
    }
    Err("Windows TCP listener table kept changing; try connecting again".into())
}

fn table_owns_ports(table: &[u32], pid: u32, ports: &[u16]) -> Result<bool, String> {
    let count = *table.first().ok_or("Missing Windows TCP table header")? as usize;
    if count > (table.len() - 1) / 6 {
        return Err("Truncated Windows TCP listener table".into());
    }
    let localhost = u32::from_ne_bytes([127, 0, 0, 1]);
    Ok(!ports.is_empty()
        && ports.iter().all(|port| {
            table[1..1 + count * 6].chunks_exact(6).any(|row| {
                row[0] == 2
                    && row[1] == localhost
                    && u16::from_be(row[2] as u16) == *port
                    && row[5] == pid
            })
        }))
}

#[repr(C)]
#[derive(Default)]
struct BasicLimits {
    process_time: i64,
    job_time: i64,
    flags: u32,
    minimum_working_set: usize,
    maximum_working_set: usize,
    active_processes: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimits {
    basic: BasicLimits,
    io_counters: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peak_process_memory: usize,
    peak_job_memory: usize,
}

/// An owned, non-inheritable job handle. Windows closes it if the parent exits
/// abruptly, killing the managed SSH process as well as on normal disconnect.
pub(crate) struct ChildJob(Handle);
impl ChildJob {
    pub(crate) fn attach(child: &Child) -> Result<Self, String> {
        // SAFETY: null attributes create a non-inheritable unnamed job object.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(format!(
                "Cannot create SSH job: {}",
                std::io::Error::last_os_error()
            ));
        }
        let job = Self(handle);
        let mut limits = ExtendedLimits::default();
        // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        limits.basic.flags = 0x2000;
        // SAFETY: repr(C) matches JOBOBJECT_EXTENDED_LIMIT_INFORMATION; both
        // handles are live and borrowed only for these synchronous calls.
        if unsafe {
            SetInformationJobObject(
                job.0,
                9,
                (&limits as *const ExtendedLimits).cast(),
                mem::size_of::<ExtendedLimits>() as u32,
            )
        } == 0
            || unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) } == 0
        {
            return Err(format!(
                "Cannot manage SSH process lifetime: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(job)
    }
}
impl Drop for ChildJob {
    fn drop(&mut self) {
        // SAFETY: this unique owned handle is closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(crate) fn open_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://127.0.0.1:") && !url.starts_with("https://127.0.0.1:") {
        return Err("Only a forwarded loopback HTTP(S) URL can be opened".into());
    }
    if url.contains('\0') {
        return Err("URL contains a NUL character".into());
    }
    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let url: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
    // Shell associations may use COM. A fresh STA thread works both in the CLI
    // and inside a desktop runtime that already initialized another apartment.
    std::thread::spawn(move || {
        // SAFETY: the reserved parameter is null and this thread owns its COM
        // apartment. COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE = 6.
        let status = unsafe { CoInitializeEx(ptr::null_mut(), 6) };
        if status < 0 {
            return Err(format!(
                "Cannot initialize browser integration: HRESULT {:#x}",
                status as u32
            ));
        }
        struct Apartment;
        impl Drop for Apartment {
            fn drop(&mut self) {
                // SAFETY: balances this thread's successful CoInitializeEx.
                unsafe {
                    CoUninitialize();
                }
            }
        }
        let _apartment = Apartment;
        // SAFETY: strings are NUL-terminated UTF-16 and remain live for the call.
        // URL is passed as a file association target, never through cmd.exe.
        let result = unsafe {
            ShellExecuteW(
                ptr::null_mut(),
                verb.as_ptr(),
                url.as_ptr(),
                ptr::null(),
                ptr::null(),
                1,
            )
        } as isize;
        if result <= 32 {
            return Err(format!(
                "Cannot open the default browser: Windows shell error {result}"
            ));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "Windows browser launcher failed".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn actual_listener_requires_correct_owner_and_every_port() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let ports = [
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
        ];
        assert!(listeners_owned_by(std::process::id(), &ports).unwrap());
        assert!(!listeners_owned_by(0, &ports).unwrap());
        drop(second);
        assert!(!listeners_owned_by(std::process::id(), &ports).unwrap());
    }

    #[test]
    fn table_parser_rejects_other_interfaces_states_owners_and_truncation() {
        let mut table = vec![
            1,
            2,
            u32::from_ne_bytes([127, 0, 0, 1]),
            18080_u16.to_be() as u32,
            0,
            0,
            123,
        ];
        assert!(table_owns_ports(&table, 123, &[18080]).unwrap());
        for (index, value) in [(1, 5), (2, 0), (6, 124)] {
            let original = table[index];
            table[index] = value;
            assert!(!table_owns_ports(&table, 123, &[18080]).unwrap());
            table[index] = original;
        }
        assert!(!table_owns_ports(&table, 123, &[18080, 19000]).unwrap());
        assert!(table_owns_ports(&table[..3], 123, &[18080]).is_err());
    }

    #[test]
    fn job_struct_layout_matches_64_bit_windows_sdk() {
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(mem::size_of::<BasicLimits>(), 64);
            assert_eq!(mem::size_of::<ExtendedLimits>(), 144);
        }
    }

    #[test]
    fn browser_rejects_nonforwarded_urls_before_invoking_the_shell() {
        assert!(open_url("file:///C:/Windows/notepad.exe").is_err());
        assert!(open_url("https://example.com").is_err());
        assert!(open_url("http://127.0.0.1:18080/\0bad").is_err());
    }

    #[test]
    fn closing_job_terminates_its_child_process() {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let job = match ChildJob::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{error}");
            }
        };
        drop(job);
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Closing the SSH job did not terminate its child");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
