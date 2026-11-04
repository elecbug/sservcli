//go:build !windows

package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func configureCommand(cmd *exec.Cmd)          {}
func detachCommand(cmd *exec.Cmd)             { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func attachJob(cmd *exec.Cmd) (func(), error) { return func() {}, nil }
func stopProcess(cmd *exec.Cmd)               { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
func killProcess(cmd *exec.Cmd)               { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
func privateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be a regular private file (chmod 600)", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("private file must belong to the current user")
	}
	return nil
}
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = privateFile(path); err == nil {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("another client is running or lock is unsafe: %w", err)
	}
	return f, nil
}
func browserCommand(url string) *exec.Cmd { return exec.Command("xdg-open", url) }
