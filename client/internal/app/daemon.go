package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type options struct {
	Config, Token, Directory string
	WebPort                  int
}
type runtimeInfo struct {
	PID  int    `json:"pid"`
	Port int    `json:"port"`
	Key  string `json:"key"`
}
type serviceView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Enabled    bool   `json:"enabled"`
	Endpoint   string `json:"endpoint"`
	URL        string `json:"url"`
	RemotePort int    `json:"remote_port"`
}
type statusView struct {
	State
	PID      int           `json:"pid"`
	Name     string        `json:"name"`
	Config   string        `json:"config"`
	Services []serviceView `json:"services"`
}
type manager struct {
	mu      sync.Mutex
	options options
	profile Profile
	tunnel  *Tunnel
	cancel  context.CancelFunc
	done    chan struct{}
	ctx     context.Context
	output  io.Writer
}

func (m *manager) connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	m.tunnel = newTunnel(m.output)
	p, err := loadProfile(m.options.Config)
	if err != nil {
		m.tunnel.update("failed", err.Error(), 0, "")
		return err
	}
	m.profile = p
	token := ""
	if p.Version == 2 {
		token, err = readToken(m.options.Token)
		if err != nil {
			m.tunnel.update("failed", err.Error(), 0, "")
			return err
		}
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel = cancel
	m.done = make(chan struct{})
	done, tunnel := m.done, m.tunnel
	go func() { defer close(done); _ = tunnel.run(ctx, p, token) }()
	return nil
}
func (m *manager) stopLocked() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
		m.done = nil
	}
}
func (m *manager) disconnect() { m.mu.Lock(); defer m.mu.Unlock(); m.stopLocked() }
func (m *manager) snapshot() statusView {
	m.mu.Lock()
	defer m.mu.Unlock()
	view := statusView{State: m.tunnel.snapshot(), PID: os.Getpid(), Name: m.profile.Name, Config: m.options.Config, Services: []serviceView{}}
	for _, s := range m.profile.Services {
		view.Services = append(view.Services, serviceView{s.ID, s.Name, s.Kind, s.IsEnabled(), s.Endpoint(), s.URL(), s.RemotePort})
	}
	return view
}
func (m *manager) open(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel.snapshot().Status != "connected" {
		return errors.New("connect the services first")
	}
	for _, s := range m.profile.Services {
		if s.ID == id {
			return launchService(s)
		}
	}
	return errors.New("unknown service")
}
func (m *manager) save(data []byte) error {
	if _, err := decodeProfile(data); err != nil {
		return err
	}
	if info, err := os.Lstat(m.options.Config); err == nil && !info.Mode().IsRegular() {
		return errors.New("configuration cannot be a link or special file")
	}
	return atomicFile(m.options.Config, data)
}
func atomicFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".sservcli-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory cannot be a link or special file")
	}
	if runtimeIsUnix() && info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must have mode 0700")
	}
	return nil
}
func runtimeIsUnix() bool { return os.PathSeparator == '/' }

func runDaemon(o options) error {
	if err := privateDirectory(o.Directory); err != nil {
		return err
	}
	lock, err := lockFile(filepath.Join(o.Directory, "client.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.WebPort)))
	if err != nil {
		return fmt.Errorf("local management port %d is unavailable: %w", o.WebPort, err)
	}
	defer listener.Close()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	info := runtimeInfo{os.Getpid(), listener.Addr().(*net.TCPAddr).Port, hex.EncodeToString(secret)}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m := &manager{options: o, ctx: ctx, tunnel: newTunnel(os.Stderr), output: os.Stderr}
	defer m.disconnect()
	// A missing/stale token leaves the local management page usable for recovery.
	_ = m.connect()
	handler := managementHandler(m, info, cancel)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	data, _ := json.Marshal(info)
	path := filepath.Join(o.Directory, "run.json")
	if err = atomicFile(path, data); err != nil {
		_ = server.Close()
		return err
	}
	defer os.Remove(path)
	fmt.Fprintf(os.Stderr, "Management: http://127.0.0.1:%d\n", info.Port)
	select {
	case <-ctx.Done():
	case err = <-done:
		cancel()
	}
	m.disconnect()
	_ = server.Close()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
func managementHandler(m *manager, info runtimeInfo, stop context.CancelFunc) http.Handler {
	host := "127.0.0.1:" + strconv.Itoa(info.Port)
	localHost := "localhost:" + strconv.Itoa(info.Port)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host && r.Host != localHost {
			http.Error(w, "invalid local host", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			pageBytes := make([]byte, 24)
			if _, err := rand.Read(pageBytes); err != nil {
				http.Error(w, "cannot initialize page", 500)
				return
			}
			pageNonce := hex.EncodeToString(pageBytes)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+pageNonce+"'; style-src 'nonce-"+pageNonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			_, _ = io.WriteString(w, strings.ReplaceAll(dashboard, "{{NONCE}}", pageNonce))
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "http://"+host && origin != "http://"+localHost {
			http.Error(w, "invalid local origin", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Sservcli-Key")), []byte(info.Key)) != 1 {
			http.Error(w, "local authorization required", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
			jsonResponse(w, m.snapshot())
		case r.URL.Path == "/api/config" && r.Method == http.MethodGet:
			data, err := readLimited(m.options.Config, 1024*1024)
			if err != nil {
				apiError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		case r.URL.Path == "/api/config" && r.Method == http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
			data, err := io.ReadAll(r.Body)
			if err == nil {
				err = m.save(data)
			}
			if err != nil {
				apiError(w, err)
				return
			}
			jsonResponse(w, map[string]string{"message": "Saved. Reconnect to apply changes."})
		case r.URL.Path == "/api/connect" && r.Method == http.MethodPost:
			if err := m.connect(); err != nil {
				apiError(w, err)
				return
			}
			jsonResponse(w, map[string]string{"message": "Connecting using services.json and .token"})
		case r.URL.Path == "/api/disconnect" && r.Method == http.MethodPost:
			m.disconnect()
			jsonResponse(w, map[string]string{"message": "Disconnected"})
		case r.URL.Path == "/api/stop" && r.Method == http.MethodPost:
			jsonResponse(w, map[string]string{"message": "Stopping"})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			stop()
		case r.URL.Path == "/api/open" && r.Method == http.MethodPost:
			if err := m.open(r.URL.Query().Get("id")); err != nil {
				apiError(w, err)
				return
			}
			jsonResponse(w, map[string]string{"message": "Opened on this computer"})
		default:
			http.NotFound(w, r)
		}
	})
}
func jsonResponse(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
func readRuntime(o options) (runtimeInfo, error) {
	path := filepath.Join(o.Directory, "run.json")
	if err := privateFile(path); err != nil {
		return runtimeInfo{}, err
	}
	data, err := readLimited(path, 4096)
	if err != nil {
		return runtimeInfo{}, err
	}
	var info runtimeInfo
	if err = json.Unmarshal(data, &info); err != nil {
		return info, err
	}
	if info.Port < 1 || info.Port > 65535 || len(info.Key) != 64 || info.PID < 1 {
		return info, errors.New("invalid client runtime metadata")
	}
	return info, nil
}
func controlRequest(o options, path, method string) ([]byte, error) {
	info, err := readRuntime(o)
	if err != nil {
		return nil, errors.New("client is not running (use start)")
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d/api/%s", info.Port, path), nil)
	req.Header.Set("X-Sservcli-Key", info.Key)
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("client is not reachable (use start to recover stale state)")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("management request failed: %s", strings.TrimSpace(string(data)))
	}
	return data, nil
}
func startDaemon(o options) error {
	if data, err := controlRequest(o, "status", http.MethodGet); err == nil {
		fmt.Println("Client is already running.")
		fmt.Println(string(bytes.TrimSpace(data)))
		return nil
	}
	if err := privateDirectory(o.Directory); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(o.Directory, "client.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	if err = privateFile(log.Name()); err != nil {
		return err
	}
	cmd := exec.Command(exe, "run", "--config", o.Config, "--token-file", o.Token, "--state-dir", o.Directory, "--web-port", strconv.Itoa(o.WebPort))
	detachCommand(cmd)
	cmd.Env = childEnvironment("")
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for i := 0; i < 100; i++ {
		if data, err := controlRequest(o, "status", http.MethodGet); err == nil {
			fmt.Printf("Client started. Management: http://127.0.0.1:%d\n%s\n", o.WebPort, bytes.TrimSpace(data))
			return nil
		}
		select {
		case err := <-done:
			return fmt.Errorf("background client stopped (%v); see %s", err, log.Name())
		case <-time.After(50 * time.Millisecond):
		}
	}
	// The child may still be creating its control endpoint. Do not kill by PID.
	return fmt.Errorf("client startup is taking longer than expected; check status and %s", log.Name())
}

func openUI(o options) error {
	info, err := readRuntime(o)
	if err != nil {
		return errors.New("start the client first")
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/#%s", info.Port, info.Key)
	cmd := browserCommand(url)
	cmd.Env = childEnvironment("")
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
