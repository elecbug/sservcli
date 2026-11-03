package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) Profile {
	t.Helper()
	data, err := os.ReadFile("../../../examples/services.token.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func encode(t *testing.T, p Profile) []byte {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestProfilesAndStrictValidation(t *testing.T) {
	for _, name := range []string{"services.token.json", "services.token.windows.json"} {
		data, err := os.ReadFile("../../../examples/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = decodeProfile(append([]byte{0xef, 0xbb, 0xbf}, data...)); err != nil {
			t.Fatal(err)
		}
	}
	p := fixture(t)
	data := string(encode(t, p))
	for _, changed := range []string{
		strings.Replace(data, `"version":2`, `"version":true`, 1),
		strings.Replace(data, `"port":22`, `"port":null`, 1),
		strings.Replace(data, `"port":22`, `"port":true`, 1),
		strings.Replace(data, `"ssh":{`, `"ssh":{"token":"secret",`, 1),
		strings.Replace(data, `"ssh":{`, `"ssh":{"identity_file":null,`, 1),
		strings.Replace(data, `"reconnect":{`, `"reconnect":{"enabled":null,`, 1),
		data + ` {}`, `null`,
	} {
		if _, err := decodeProfile([]byte(changed)); err == nil {
			t.Errorf("accepted invalid input: %s", changed)
		}
	}
	mutations := []func(*Profile){
		func(p *Profile) { p.SSH.Host = "-oProxyCommand=bad" },
		func(p *Profile) { p.SSH.Fallback = []string{p.SSH.Host} },
		func(p *Profile) { p.Services[1].LocalPort = p.Services[0].LocalPort },
		func(p *Profile) { p.Services[0].RemoteHost = "0.0.0.0" },
		func(p *Profile) { p.Services[0].Path = "//evil.example" },
		func(p *Profile) { p.Services[0].Launch = []string{"tool", "{unknown}"} },
		func(p *Profile) { p.SSH.HostKey = "ssh-ed25519 AAAA\nssh-ed25519 BBBB" },
		func(p *Profile) { p.Reconnect.MaxDelay = 0 },
	}
	for _, mutate := range mutations {
		q := fixture(t)
		mutate(&q)
		if err := q.Validate(); err == nil {
			t.Error("unsafe configuration was accepted")
		}
	}
}
func TestTokenFilesAreExactCaseSensitiveAndNotEnvironmentDriven(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".token")
	t.Setenv("SSERVCLI_TOKEN", "OTHER123")
	for _, value := range []string{"Ab1Cd2E3", "Ab1Cd2E3\r\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		token, err := readToken(path)
		if err != nil || token != "Ab1Cd2E3" {
			t.Fatalf("token=%q err=%v", token, err)
		}
	}
	for _, value := range []string{"short", "Ab1Cd2E3 ", " Ab1Cd2E3", "Ab1Cd2E3\nextra", "éB1Cd2E3"} {
		_ = os.WriteFile(path, []byte(value), 0600)
		if _, err := readToken(path); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
func TestSSHUsesOneTransportAllEnabledServicesAndStrictAuth(t *testing.T) {
	p := fixture(t)
	no := false
	p.Services[2].Enabled = &no
	args := sshArgs(p, "known_hosts", "control", "127.0.0.1")
	count := 0
	for _, arg := range args {
		if arg == "-L" {
			count++
		}
	}
	if count != 2 {
		t.Fatal(args)
	}
	joined := strings.Join(args, "\n")
	for _, value := range []string{"StrictHostKeyChecking=yes", "ExitOnForwardFailure=yes", "PreferredAuthentications=password", "PubkeyAuthentication=no", "NumberOfPasswordPrompts=1", "127.0.0.1:18080:127.0.0.1:8080"} {
		if !strings.Contains(joined, value) {
			t.Errorf("missing %s", value)
		}
	}
	if strings.Contains(joined, "SSERVCLI_ASKPASS_TOKEN") {
		t.Fatal("token in arguments")
	}
	p.Version = 1
	p.SSH.Identity = "client_key"
	args = sshArgs(p, "known_hosts", "control", p.SSH.Host)
	if !strings.Contains(strings.Join(args, " "), "BatchMode=yes") {
		t.Fatal(args)
	}
}
func TestTokenRedactionAndScopedAskpass(t *testing.T) {
	t.Setenv("SSERVCLI_TOKEN", "do-not-inherit")
	t.Setenv("SSERVCLI_ASKPASS_MODE", "bad")
	env := strings.Join(childEnvironment("Ab1Cd2E3"), "\n")
	if strings.Contains(env, "do-not-inherit") || strings.Contains(env, "MODE=bad") {
		t.Fatal("ambient secret inherited")
	}
	if !strings.Contains(env, "SSH_ASKPASS_REQUIRE=force") || !strings.Contains(env, "SSERVCLI_ASKPASS_TOKEN=Ab1Cd2E3") {
		t.Fatal("askpass not configured")
	}
	tunnel := newTunnel(io.Discard)
	log := &sshLog{tunnel: tunnel, token: "Ab1Cd2E3"}
	_, _ = log.Write([]byte("debug Ab1C"))
	_, _ = log.Write([]byte("d2E3 value\nPermission denied\n"))
	if strings.Contains(strings.Join(tunnel.snapshot().Logs, ""), "Ab1Cd2E3") {
		t.Fatal("secret leaked to log")
	}
	fatal, rejected := log.result()
	if !fatal || !rejected {
		t.Fatal("auth failure should stop retrying")
	}
}
func TestOccupiedPortsAndDisabledServices(t *testing.T) {
	p := fixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	p.Services[0].LocalPort = listener.Addr().(*net.TCPAddr).Port
	if err = checkPorts(p); err == nil {
		t.Fatal("occupied port accepted")
	}
	no := false
	for i := range p.Services {
		p.Services[i].Enabled = &no
	}
	if err = checkPorts(p); err == nil {
		t.Fatal("empty forwarding set accepted")
	}
}
func TestLaunchArgumentsAreSeparateAndExpandOnlyKnownPlaceholders(t *testing.T) {
	s := fixture(t).Services[0]
	s.Launch = []string{"browser", "{url}", "literal; argument with spaces"}
	args := s.Arguments()
	if args[1] != "http://127.0.0.1:18080/" || args[2] != "literal; argument with spaces" {
		t.Fatal(args)
	}
}
func TestLocalManagementRejectsCrossOriginRequestsAndNeverReturnsToken(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "services.json")
	profile := fixture(t)
	original := encode(t, profile)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	m := &manager{options: options{Config: path}, profile: profile, tunnel: newTunnel(io.Discard), ctx: context.Background(), output: io.Discard}
	key := strings.Repeat("a", 64)
	handler := managementHandler(m, runtimeInfo{PID: 123, Port: 8000, Key: key}, func() {})
	request := func(method, path, host, origin, auth, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Sservcli-Key", auth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, r := range []*httptest.ResponseRecorder{request("GET", "/api/status", "127.0.0.1:8000", "", "", ""), request("GET", "/api/status", "evil.example:8000", "", key, ""), request("POST", "/api/disconnect", "127.0.0.1:8000", "http://evil.example", key, "")} {
		if r.Code != http.StatusForbidden {
			t.Fatal(r.Code, r.Body.String())
		}
	}
	r := request("GET", "/api/status", "127.0.0.1:8000", "", key, "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "18080") || strings.Contains(r.Body.String(), key) {
		t.Fatal(r.Code, r.Body.String())
	}
	r = request("GET", "/", "127.0.0.1:8000", "", "", "")
	if r.Code != 200 || strings.Contains(r.Body.String(), key) || !strings.Contains(r.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("dashboard is not protected")
	}
	r = request("POST", "/api/config", "127.0.0.1:8000", "", key, `{"token":"bad"}`)
	if r.Code == 200 {
		t.Fatal("invalid config saved")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(original) {
		t.Fatal("invalid edit changed configuration")
	}
	profile.Name = "Updated profile"
	r = request("POST", "/api/config", "localhost:8000", "http://localhost:8000", key, string(encode(t, profile)))
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	loaded, err := loadProfile(path)
	if err != nil || loaded.Name != "Updated profile" {
		t.Fatal(loaded.Name, err)
	}
}

func TestPinnedKeyCoversAllAddressesWithOpenSSHHostSyntax(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("OpenSSH Client required")
	}
	directory := t.TempDir()
	key := filepath.Join(directory, "host")
	if output, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	public, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	p := fixture(t)
	p.SSH.Host = "192.0.2.1"
	p.SSH.Fallback = []string{"server.example.net", "2001:db8::1"}
	p.SSH.Port = 2222
	p.SSH.HostKey = strings.TrimSpace(string(public))
	known, fingerprint, err := prepareKey(p, directory)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(known)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range p.Hosts() {
		if !strings.Contains(string(data), "["+host+"]:2222 ssh-ed25519 ") {
			t.Fatal(string(data))
		}
	}
	actual, err := exec.Command("ssh-keygen", "-lf", key+".pub").Output()
	if err != nil || !strings.Contains(string(actual), fingerprint) {
		t.Fatal(fingerprint, string(actual), err)
	}
}
