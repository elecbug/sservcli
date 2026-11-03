//go:build !windows && !linux

package app

import (
	"os/exec"
	"syscall"
)

func configureSSH(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
