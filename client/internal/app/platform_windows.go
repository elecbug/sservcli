package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
func configureSSH(cmd *exec.Cmd)  { configureCommand(cmd) }
func detachCommand(cmd *exec.Cmd) { configureCommand(cmd) }
func stopProcess(cmd *exec.Cmd)   { _ = cmd.Process.Kill() }
func killProcess(cmd *exec.Cmd)   { _ = cmd.Process.Kill() }
func privateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("private files cannot be links or special files")
	}
	return nil
}
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = privateFile(path); err != nil {
		f.Close()
		return nil, err
	}
	var overlapped syscall.Overlapped
	r, _, callErr := kernel.NewProc("LockFileEx").Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if r == 0 {
		f.Close()
		return nil, fmt.Errorf("another client is running: %w", callErr)
	}
	return f, nil
}

// Native structures use pointer-sized counters, including for Windows ARM64.
type jobBasic struct {
	ProcessTime, JobTime int64
	Flags                uint32
	Min, Max             uintptr
	Active               uint32
	Affinity             uintptr
	Priority, Scheduling uint32
}
type jobInfo struct {
	Basic                                          jobBasic
	IO                                             [6]uint64
	ProcessMemory, JobMemory, PeakProcess, PeakJob uintptr
}

func attachJob(cmd *exec.Cmd) (func(), error) {
	job, _, err := kernel.NewProc("CreateJobObjectW").Call(0, 0)
	if job == 0 {
		return nil, err
	}
	closeJob := func() { _ = syscall.CloseHandle(syscall.Handle(job)) }
	info := jobInfo{}
	info.Basic.Flags = 0x2000
	r, _, err := kernel.NewProc("SetInformationJobObject").Call(job, 9, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		closeJob()
		return nil, err
	}
	handle, err := syscall.OpenProcess(0x0100|0x0001|0x0400, false, uint32(cmd.Process.Pid))
	if err != nil {
		closeJob()
		return nil, err
	}
	defer syscall.CloseHandle(handle)
	r, _, err = kernel.NewProc("AssignProcessToJobObject").Call(job, uintptr(handle))
	if r == 0 {
		closeJob()
		return nil, err
	}
	return closeJob, nil
}
func browserCommand(url string) *exec.Cmd {
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
}
