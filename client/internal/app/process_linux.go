package app

import (
	"os/exec"
	"syscall"
)

func configureSSH(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGTERM}
}
