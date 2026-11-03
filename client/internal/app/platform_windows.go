package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var tcpTable = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

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
func platformReady(cmd *exec.Cmd, control, host string, ports []int) bool {
	var size uint32
	r, _, _ := tcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 3, 0)
	if r != 122 || size < 4 || size > 32*1024*1024 {
		return false
	}
	data := make([]byte, size)
	r, _, _ = tcpTable.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 3, 0)
	if r != 0 {
		return false
	}
	found := map[int]bool{}
	count := int(binary.LittleEndian.Uint32(data[:4]))
	for i := 0; i < count; i++ {
		offset := 4 + i*24
		if offset+24 > len(data) {
			return false
		}
		row := data[offset : offset+24]
		if binary.LittleEndian.Uint32(row[:4]) == 2 && row[4] == 127 && row[5] == 0 && row[6] == 0 && row[7] == 1 && binary.LittleEndian.Uint32(row[20:24]) == uint32(cmd.Process.Pid) {
			found[int(binary.BigEndian.Uint16(row[8:10]))] = true
		}
	}
	for _, port := range ports {
		if !found[port] {
			return false
		}
	}
	return true
}
func browserCommand(url string) *exec.Cmd {
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
}
