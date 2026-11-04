package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type State struct {
	Status      string   `json:"status"`
	Message     string   `json:"message"`
	Attempt     int      `json:"attempt"`
	Host        string   `json:"active_host,omitempty"`
	Fingerprint string   `json:"host_key_fingerprint,omitempty"`
	Logs        []string `json:"logs"`
}
type Tunnel struct {
	mu     sync.Mutex
	state  State
	output io.Writer
}

func newTunnel(output io.Writer) *Tunnel {
	return &Tunnel{state: State{Status: "disconnected", Message: "SSH is not connected", Logs: []string{}}, output: output}
}
func (t *Tunnel) snapshot() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state
	s.Logs = append([]string{}, s.Logs...)
	return s
}
func (t *Tunnel) log(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.Logs = append(t.state.Logs, line)
	if len(t.state.Logs) > 200 {
		t.state.Logs = t.state.Logs[len(t.state.Logs)-200:]
	}
	if t.output != nil {
		fmt.Fprintln(t.output, line)
	}
}
func (t *Tunnel) update(status, message string, attempt int, host string) {
	t.mu.Lock()
	t.state.Status = status
	t.state.Message = message
	t.state.Attempt = attempt
	t.state.Host = host
	t.mu.Unlock()
	t.log(fmt.Sprintf("[%s] %s", status, message))
}
func openSSH(name string) string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		for _, dir := range []string{"Sysnative", "System32"} {
			path := filepath.Join(root, dir, "OpenSSH", name+".exe")
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return name
}
func childEnvironment(token string) []string {
	values := []string{}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(strings.ToUpper(key), "SSERVCLI_") || strings.HasPrefix(strings.ToUpper(key), "SSH_ASKPASS") || key == "DISPLAY" {
			continue
		}
		values = append(values, value)
	}
	if token != "" {
		exe, _ := os.Executable()
		if runtime.GOOS == "windows" {
			exe = `"` + filepath.Join(filepath.Dir(exe), "sservcli-askpass.exe") + `"`
		}
		values = append(values, "SSERVCLI_ASKPASS_MODE=1", "SSERVCLI_ASKPASS_TOKEN="+token, "SSH_ASKPASS="+exe, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=sservcli:0")
	}
	return values
}
func sshPath(path string) string {
	if runtime.GOOS == "windows" {
		path = strings.ReplaceAll(path, `\`, `/`)
	}
	return path
}
func sshArgs(p Profile, known, host string) []string {
	args := []string{"-F", "none", "-N", "-T", "-n"}
	options := []string{"StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none", "UpdateHostKeys=no", "ExitOnForwardFailure=yes", "ServerAliveInterval=20", "ServerAliveCountMax=3", "ConnectTimeout=10", "ConnectionAttempts=1", "KbdInteractiveAuthentication=no", "ForwardAgent=no", "ForwardX11=no", "GatewayPorts=no", "LogLevel=DEBUG1", `UserKnownHostsFile="` + sshPath(known) + `"`}
	if p.Version == 2 {
		options = append(options, "BatchMode=no", "PreferredAuthentications=password", "PasswordAuthentication=yes", "PubkeyAuthentication=no", "NumberOfPasswordPrompts=1")
	} else {
		options = append(options, "BatchMode=yes", "PreferredAuthentications=publickey", "PasswordAuthentication=no")
	}
	if p.SSH.Identity != "" {
		options = append(options, "IdentitiesOnly=yes")
		args = append(args, "-i", sshPath(p.SSH.Identity))
	}
	for _, option := range options {
		args = append(args, "-o", option)
	}
	args = append(args, "-p", strconv.Itoa(p.SSH.Port), "-l", p.SSH.User)
	for _, s := range p.Services {
		if s.IsEnabled() {
			args = append(args, "-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", s.LocalPort, s.RemotePort))
		}
	}
	return append(args, host)
}
func checkPorts(p Profile) error {
	listeners := []net.Listener{}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, s := range p.Services {
		if s.IsEnabled() {
			listener, err := net.Listen("tcp4", s.Endpoint())
			if err != nil {
				return fmt.Errorf("%s: local port %d is unavailable: %w", s.ID, s.LocalPort, err)
			}
			listeners = append(listeners, listener)
		}
	}
	if len(listeners) == 0 {
		return errors.New("enable at least one service")
	}
	return nil
}
func prepareKey(p Profile, directory string) (string, string, error) {
	if p.SSH.HostKey == "" {
		if p.Version == 2 {
			return "", "", errors.New("import a client bundle with the pinned server public key before connecting")
		}
		if _, err := os.Stat(p.SSH.KnownHosts); err != nil {
			return "", "", err
		}
		return p.SSH.KnownHosts, "", nil
	}
	key := strings.Join(strings.Fields(p.SSH.HostKey)[:2], " ")
	public := filepath.Join(directory, "server.pub")
	if err := os.WriteFile(public, []byte(key+"\n"), 0600); err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, openSSH("ssh-keygen"), "-lf", public)
	configureCommand(cmd)
	cmd.Env = childEnvironment("")
	if err := cmd.Run(); err != nil {
		return "", "", errors.New("invalid server public key or ssh-keygen is unavailable")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.Fields(key)[1])
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	var content strings.Builder
	for _, host := range p.Hosts() {
		if p.SSH.Port != 22 {
			host = fmt.Sprintf("[%s]:%d", host, p.SSH.Port)
		}
		fmt.Fprintf(&content, "%s %s\n", host, key)
	}
	known := filepath.Join(directory, "known_hosts")
	err = os.WriteFile(known, []byte(content.String()), 0600)
	return known, fingerprint, err
}
func (t *Tunnel) run(ctx context.Context, p Profile, token string) (err error) {
	defer func() {
		if ctx.Err() != nil {
			t.update("disconnected", "SSH closed; local listeners released", 0, "")
			err = nil
		} else if err != nil {
			message := err.Error()
			if token != "" {
				message = strings.ReplaceAll(message, token, "[redacted]")
			}
			t.update("failed", message, t.snapshot().Attempt, "")
		}
	}()
	if err = p.Validate(); err != nil {
		return err
	}
	if p.Version == 2 && !tokenPattern.MatchString(token) {
		return errors.New("invalid .token: expected 8 case-sensitive letters/digits")
	}
	if runtime.GOOS == "windows" && p.Version == 2 {
		exe, _ := os.Executable()
		if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "sservcli-askpass.exe")); err != nil {
			return errors.New("sservcli-askpass.exe is missing; extract the entire ZIP or run Build.cmd")
		}
	}
	if err = checkPorts(p); err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", fmt.Sprintf("sservcli-%d-", os.Getpid()))
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	known, fingerprint, err := prepareKey(p, directory)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.state.Fingerprint = fingerprint
	t.mu.Unlock()
	if fingerprint != "" {
		t.log("[pinned host key] " + fingerprint)
	}
	hosts := p.Hosts()
	retries, first := 0, 0
	for ctx.Err() == nil {
		connected := false
		message := "SSH connection failed"
		for offset := 0; offset < len(hosts) && ctx.Err() == nil; offset++ {
			index := (first + offset) % len(hosts)
			host := hosts[index]
			t.update("connecting", fmt.Sprintf("Connecting to %s:%d (address %d/%d)", host, p.SSH.Port, offset+1, len(hosts)), retries, host)
			var fatal bool
			connected, message, fatal = t.connection(ctx, p, token, known, host, retries)
			if ctx.Err() != nil {
				return nil
			}
			if fatal {
				return errors.New(message)
			}
			if connected {
				first = (index + 1) % len(hosts)
				break
			}
			if offset+1 < len(hosts) {
				t.log("[address failed] " + message)
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if !p.Reconnect.Enabled || !connected && retries == 0 || retries >= p.Reconnect.MaxAttempts {
			return errors.New(message)
		}
		retries++
		delay := p.Reconnect.InitialDelay
		for i := 1; i < retries && delay < p.Reconnect.MaxDelay; i++ {
			delay *= 2
		}
		if delay > p.Reconnect.MaxDelay {
			delay = p.Reconnect.MaxDelay
		}
		t.update("reconnecting", fmt.Sprintf("%s; retry %d/%d in %ds", message, retries, p.Reconnect.MaxAttempts, delay), retries, "")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(delay) * time.Second):
		}
	}
	return nil
}

type sshLog struct {
	mu            sync.Mutex
	partial       string
	token         string
	tunnel        *Tunnel
	authenticated bool
	session       bool
	listeners     map[int]bool
	fatal         bool
	rejected      bool
}

func (w *sshLog) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.partial += string(data)
	for {
		line, rest, found := strings.Cut(w.partial, "\n")
		if !found {
			break
		}
		w.partial = rest
		line = strings.Map(func(c rune) rune {
			if unicode.IsPrint(c) {
				return c
			}
			return -1
		}, line)
		progress := strings.TrimPrefix(line, "debug1: ")
		if strings.HasPrefix(progress, "Authenticated to ") || strings.HasPrefix(progress, "Authentication succeeded (") {
			w.authenticated = true
		}
		if line == "debug1: Entering interactive session." {
			w.session = true
		}
		const listening = "debug1: Local forwarding listening on 127.0.0.1 port "
		if strings.HasPrefix(line, listening) && strings.HasSuffix(line, ".") {
			port, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(line, listening), "."))
			if err == nil && port > 0 && port <= 65535 {
				if w.listeners == nil {
					w.listeners = map[int]bool{}
				}
				w.listeners[port] = true
			}
		}
		if strings.Contains(line, "HOST IDENTIFICATION HAS CHANGED") || strings.Contains(line, "Host key verification failed") || strings.Contains(line, "Could not request local forwarding") {
			w.fatal = true
		}
		if !strings.HasPrefix(line, "bind [") && !strings.HasPrefix(line, "listen [") &&
			(strings.Contains(line, ": Permission denied (") || strings.Contains(line, "Permission denied, please try again.")) {
			w.fatal, w.rejected = true, true
		}
		// DEBUG1 supplies lifecycle events without filling the management log
		// with key exchange details. Warnings and authentication results remain.
		if strings.HasPrefix(line, "debug1:") {
			continue
		}
		if w.token != "" {
			line = strings.ReplaceAll(line, w.token, "[redacted]")
		}
		w.tunnel.log(line)
	}
	if len(w.partial) > 8192 {
		w.partial = w.partial[:8192]
	}
	return len(data), nil
}
func (w *sshLog) result() (bool, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fatal, w.rejected
}
func (w *sshLog) forwardingReady(ports []int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	// OpenSSH enters its session loop only after authentication and successful
	// forwarding setup (ExitOnForwardFailure=yes). The earlier listening log
	// alone occurs before bind(), so it must not count as success.
	if !w.authenticated || !w.session || w.fatal || len(ports) == 0 {
		return false
	}
	for _, port := range ports {
		if !w.listeners[port] {
			return false
		}
	}
	return true
}
func (w *sshLog) startupFailure(host string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.authenticated {
		return host + ": SSH token/key authentication succeeded, but local forwarding readiness was not confirmed; see connection log", true
	}
	return host + ": SSH startup timed out before authentication", false
}
func (t *Tunnel) connection(ctx context.Context, p Profile, token, known, host string, attempt int) (connected bool, message string, fatal bool) {
	cmd := exec.Command(openSSH("ssh"), sshArgs(p, known, host)...)
	configureSSH(cmd)
	cmd.Env = childEnvironment(token)
	logs := &sshLog{token: token, tunnel: t}
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		return false, "Cannot start native OpenSSH: " + err.Error(), true
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	closeJob, err := attachJob(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		<-done
		return false, "Cannot manage the SSH child process: " + err.Error(), true
	}
	defer closeJob()
	exited := false
	defer func() {
		if !exited {
			stopProcess(cmd)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				killProcess(cmd)
				<-done
			}
		}
	}()
	ports := []int{}
	for _, s := range p.Services {
		if s.IsEnabled() {
			ports = append(ports, s.LocalPort)
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return connected, "Disconnected", false
		case err := <-done:
			exited = true
			fatal, rejected := logs.result()
			if p.Version == 2 && rejected {
				return connected, "Shared token rejected. Update the case-sensitive 8-character .token file and reconnect.", true
			}
			return connected, fmt.Sprintf("%s: SSH exited (%v); see connection log", host, err), fatal
		case <-deadline.C:
			if !connected {
				message, fatal = logs.startupFailure(host)
				return false, message, fatal
			}
		case <-ticker.C:
			if !connected && logs.forwardingReady(ports) {
				connected = true
				t.update("connected", "Connected to "+host+"; all enabled local listeners are ready (service health is not checked)", attempt, host)
			}
		}
	}
}
func launchService(s Service) error {
	if !s.IsEnabled() {
		return errors.New("service is disabled")
	}
	args := s.Arguments()
	var cmd *exec.Cmd
	if len(args) > 0 {
		cmd = exec.Command(args[0], args[1:]...)
	} else if s.Kind == "web" || s.Kind == "api" {
		cmd = browserCommand(s.URL())
	} else {
		return errors.New("use this service's local endpoint or configure its launch array")
	}
	cmd.Env = childEnvironment("")
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
