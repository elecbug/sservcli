package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type SSH struct {
	Host       string   `json:"host"`
	Fallback   []string `json:"fallback_hosts,omitempty"`
	Port       int      `json:"port"`
	User       string   `json:"user"`
	HostKey    string   `json:"host_public_key,omitempty"`
	Identity   string   `json:"identity_file,omitempty"`
	KnownHosts string   `json:"known_hosts_file,omitempty"`
}
type Reconnect struct {
	Enabled      bool `json:"enabled"`
	MaxAttempts  int  `json:"max_attempts"`
	InitialDelay int  `json:"initial_delay_secs"`
	MaxDelay     int  `json:"max_delay_secs"`
}
type Service struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	RemoteHost string   `json:"remote_host"`
	RemotePort int      `json:"remote_port"`
	LocalPort  int      `json:"local_port"`
	Enabled    *bool    `json:"enabled,omitempty"`
	Path       string   `json:"path,omitempty"`
	Scheme     string   `json:"scheme,omitempty"`
	Launch     []string `json:"launch,omitempty"`
}
type Profile struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	SSH       SSH       `json:"ssh"`
	Reconnect Reconnect `json:"reconnect"`
	Services  []Service `json:"services"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var hostname = regexp.MustCompile(`^[A-Za-z0-9.:-]+$`)
var hostkey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]{16,}( [^\r\n]*)?$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9]{8}$`)

func decodeProfile(data []byte) (Profile, error) {
	p := Profile{SSH: SSH{Port: 22, User: "svc_tunnel"}, Reconnect: Reconnect{true, 5, 2, 30}}
	if len(data) > 1024*1024 {
		return p, errors.New("profile must be smaller than 1 MiB")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return p, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, fmt.Errorf("invalid profile: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return p, errors.New("profile must contain one JSON object")
	}
	// Reject explicit nulls and missing required members instead of treating them
	// as Go zero values or silently keeping a security-sensitive default.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return p, errors.New("profile must be an object")
	}
	if err := exactFields(raw, "version", "name", "ssh", "reconnect", "services"); err != nil {
		return p, err
	}
	for _, field := range []string{"version", "name", "ssh", "services"} {
		if !present(raw, field) {
			return p, fmt.Errorf("missing or null %s", field)
		}
	}
	for _, value := range raw {
		if string(bytes.TrimSpace(value)) == "null" {
			return p, errors.New("profile fields cannot be null")
		}
	}
	var ssh map[string]json.RawMessage
	_ = json.Unmarshal(raw["ssh"], &ssh)
	if err := exactFields(ssh, "host", "fallback_hosts", "port", "user", "host_public_key", "identity_file", "known_hosts_file"); err != nil {
		return p, err
	}
	if !present(ssh, "host") || (p.Version == 1 && !present(ssh, "user")) {
		return p, errors.New("SSH host/user is required")
	}
	for _, field := range []string{"port", "user", "fallback_hosts", "host_public_key"} {
		if v, ok := ssh[field]; ok && string(bytes.TrimSpace(v)) == "null" {
			return p, fmt.Errorf("ssh.%s cannot be null", field)
		}
	}
	if p.Version == 2 {
		for _, field := range []string{"identity_file", "known_hosts_file"} {
			if _, ok := ssh[field]; ok {
				return p, errors.New("token profiles cannot contain login key fields")
			}
		}
	}
	var services []map[string]json.RawMessage
	_ = json.Unmarshal(raw["services"], &services)
	for _, s := range services {
		if err := exactFields(s, "id", "name", "kind", "remote_host", "remote_port", "local_port", "enabled", "path", "scheme", "launch"); err != nil {
			return p, err
		}
		for _, field := range []string{"id", "name", "kind", "remote_host", "remote_port", "local_port"} {
			if !present(s, field) {
				return p, fmt.Errorf("service needs %s", field)
			}
		}
		for _, value := range s {
			if string(bytes.TrimSpace(value)) == "null" {
				return p, errors.New("service fields cannot be null")
			}
		}
	}
	if r, ok := raw["reconnect"]; ok {
		var fields map[string]json.RawMessage
		if json.Unmarshal(r, &fields) != nil || fields == nil {
			return p, errors.New("reconnect must be an object")
		}
		if err := exactFields(fields, "enabled", "max_attempts", "initial_delay_secs", "max_delay_secs"); err != nil {
			return p, err
		}
		for _, value := range fields {
			if string(bytes.TrimSpace(value)) == "null" {
				return p, errors.New("reconnect fields cannot be null")
			}
		}
	}
	return p, p.Validate()
}
func present(values map[string]json.RawMessage, key string) bool {
	v, ok := values[key]
	return ok && string(bytes.TrimSpace(v)) != "null"
}
func (p Profile) Validate() error {
	if p.Version != 1 && p.Version != 2 {
		return errors.New("profile version must be 1 (key/Agent) or 2 (token)")
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 128 || !utf8.ValidString(p.Name) {
		return errors.New("profile name must contain 1-128 UTF-8 bytes")
	}
	hosts := p.Hosts()
	seen := map[string]bool{}
	if len(hosts) > 16 {
		return errors.New("at most 16 SSH addresses are allowed")
	}
	for _, host := range hosts {
		key := strings.ToLower(host)
		if len(host) > 253 || !hostname.MatchString(host) || strings.HasPrefix(host, "-") || seen[key] {
			return errors.New("SSH addresses must be valid and unique")
		}
		seen[key] = true
	}
	if !identifier.MatchString(p.SSH.User) || strings.HasPrefix(p.SSH.User, "-") {
		return errors.New("invalid SSH user")
	}
	if p.SSH.Port < 1 || p.SSH.Port > 65535 {
		return errors.New("invalid SSH port")
	}
	if p.Version == 1 && (p.SSH.HostKey == "") == (p.SSH.KnownHosts == "") {
		return errors.New("set exactly one host-key verification source")
	}
	if p.SSH.HostKey != "" && (len(p.SSH.HostKey) > 16384 || !hostkey.MatchString(strings.TrimSpace(p.SSH.HostKey))) {
		return errors.New("expected one plain SSH host public key")
	}
	for _, path := range []string{p.SSH.Identity, p.SSH.KnownHosts} {
		if strings.ContainsAny(path, "\"%") || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return errors.New("SSH paths cannot contain controls, quotes or %")
		}
	}
	r := p.Reconnect
	if r.MaxAttempts < 0 || r.MaxAttempts > 100 || r.InitialDelay < 1 || r.InitialDelay > 300 || r.MaxDelay < r.InitialDelay || r.MaxDelay > 300 {
		return errors.New("invalid reconnect limits")
	}
	if len(p.Services) < 1 || len(p.Services) > 64 {
		return errors.New("configure 1-64 services")
	}
	ids := map[string]bool{}
	ports := map[int]bool{}
	for _, s := range p.Services {
		if !identifier.MatchString(s.ID) || ids[s.ID] || strings.TrimSpace(s.Name) == "" {
			return errors.New("services need unique IDs and names")
		}
		ids[s.ID] = true
		if s.Kind != "web" && s.Kind != "api" && s.Kind != "database" && s.Kind != "tcp" {
			return fmt.Errorf("%s: invalid service kind", s.ID)
		}
		if s.RemoteHost != "127.0.0.1" || s.RemotePort < 1 || s.RemotePort > 65535 || s.LocalPort < 1024 || s.LocalPort > 65535 || ports[s.LocalPort] {
			return fmt.Errorf("%s: invalid or duplicate ports/destination", s.ID)
		}
		ports[s.LocalPort] = true
		path := s.Path
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") || strings.IndexFunc(path, func(c rune) bool { return unicode.IsControl(c) || unicode.IsSpace(c) }) >= 0 || s.Scheme != "" && s.Scheme != "http" && s.Scheme != "https" {
			return fmt.Errorf("%s: invalid URL path or scheme", s.ID)
		}
		if s.Launch != nil {
			if len(s.Launch) == 0 || s.Launch[0] == "" || strings.HasPrefix(s.Launch[0], "-") || strings.ContainsAny(s.Launch[0], "{}\x00") {
				return errors.New("invalid launch executable")
			}
			for _, arg := range s.Launch {
				if strings.ContainsRune(arg, 0) {
					return errors.New("launch arguments cannot contain NUL")
				}
			}
			for _, arg := range s.Launch[1:] {
				rest := strings.NewReplacer("{host}", "", "{port}", "", "{url}", "").Replace(arg)
				if strings.ContainsAny(rest, "{}") {
					return errors.New("unknown launch placeholder")
				}
			}
		}
	}
	return nil
}
func (p Profile) Hosts() []string  { return append([]string{p.SSH.Host}, p.SSH.Fallback...) }
func (s Service) IsEnabled() bool  { return s.Enabled == nil || *s.Enabled }
func (s Service) Endpoint() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.LocalPort)) }
func (s Service) URL() string {
	scheme := s.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := s.Path
	if path == "" {
		path = "/"
	}
	return scheme + "://" + s.Endpoint() + path
}
func (s Service) Arguments() []string {
	args := append([]string(nil), s.Launch...)
	replace := strings.NewReplacer("{host}", "127.0.0.1", "{port}", strconv.Itoa(s.LocalPort), "{url}", s.URL())
	for i := 1; i < len(args); i++ {
		args[i] = replace.Replace(args[i])
	}
	return args
}
func loadProfile(path string) (Profile, error) {
	data, err := readLimited(path, 1024*1024)
	if err != nil {
		return Profile{}, err
	}
	p, err := decodeProfile(data)
	if err != nil {
		return p, err
	}
	for _, target := range []*string{&p.SSH.Identity, &p.SSH.KnownHosts} {
		if *target != "" {
			*target = resolvePath(*target, filepath.Dir(path))
		}
	}
	return p, nil
}
func resolvePath(path, base string) string {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimLeft(path[1:], `/\`))
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return filepath.Clean(path)
}
func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid or oversized file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("file is too large")
	}
	return data, err
}
func readToken(path string) (string, error) {
	if err := privateFile(path); err != nil {
		return "", err
	}
	data, err := readLimited(path, 64)
	if err != nil {
		return "", err
	}
	token := strings.TrimRight(string(data), "\r\n")
	if !tokenPattern.MatchString(token) {
		return "", errors.New(".token must contain exactly 8 case-sensitive characters (A-Z, a-z, 0-9), optionally followed by a newline")
	}
	return token, nil
}

// encoding/json otherwise accepts duplicate and case-insensitive object names.
func exactFields(values map[string]json.RawMessage, names ...string) error {
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for key := range values {
		if !allowed[key] {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}
func uniqueJSON(decoder *json.Decoder) error {
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON object key")
			}
			seen[key] = true
			if err := uniqueJSON(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSON(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
