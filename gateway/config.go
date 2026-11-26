package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultListenAddress    = "127.0.0.1:8443"
	defaultHandshakeTimeout = 10 * time.Second
)

// Runtime is the parsed process configuration plus the immutable routing
// snapshot built from it.
type Runtime struct {
	ConfigPath       string
	ConfigSHA256     [sha256.Size]byte
	ListenAddress    string
	LogLevel         slog.Level
	HandshakeTimeout time.Duration
	Snapshot         *Snapshot
}

type fileConfig struct {
	ListenAddress      string      `json:"listen_address"`
	LogLevel           string      `json:"log_level"`
	UnknownSNI         string      `json:"unknown_sni"`
	HandshakeTimeout   string      `json:"handshake_timeout"`
	Certificates       []certFile  `json:"certificates"`
	Routes             []routeFile `json:"routes"`
	DefaultCertificate string      `json:"default_certificate"`
}

type certFile struct {
	Name     string `json:"name"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type routeFile struct {
	Host        string `json:"host"`
	Certificate string `json:"certificate"`
}

// LoadConfig reads and builds a complete routing snapshot from path.
// Certificate paths are resolved relative to the configuration file.
func LoadConfig(path string) (*Runtime, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path %q: %w", path, err)
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", absPath, err)
	}
	runtime, err := ParseConfig(data, filepath.Dir(absPath))
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", absPath, err)
	}
	runtime.ConfigPath = absPath
	runtime.ConfigSHA256 = sha256.Sum256(data)
	return runtime, nil
}

// ParseConfig builds a runtime from JSON. Relative certificate paths are
// resolved against baseDir.
func ParseConfig(data []byte, baseDir string) (*Runtime, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var raw fileConfig
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}

	runtime := &Runtime{
		ListenAddress:    strings.TrimSpace(raw.ListenAddress),
		LogLevel:         slog.LevelInfo,
		HandshakeTimeout: defaultHandshakeTimeout,
	}
	if runtime.ListenAddress == "" {
		runtime.ListenAddress = defaultListenAddress
	}
	if _, _, err := net.SplitHostPort(runtime.ListenAddress); err != nil {
		return nil, fmt.Errorf("listen_address %q: %w", runtime.ListenAddress, err)
	}
	if strings.TrimSpace(raw.LogLevel) != "" {
		if err := runtime.LogLevel.UnmarshalText([]byte(strings.TrimSpace(raw.LogLevel))); err != nil {
			return nil, fmt.Errorf("log_level %q: %w", raw.LogLevel, err)
		}
	}
	if strings.TrimSpace(raw.HandshakeTimeout) != "" {
		timeout, err := time.ParseDuration(strings.TrimSpace(raw.HandshakeTimeout))
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("handshake_timeout %q must be a positive duration", raw.HandshakeTimeout)
		}
		runtime.HandshakeTimeout = timeout
	}

	policy, err := parseUnknownPolicy(raw.UnknownSNI)
	if err != nil {
		return nil, err
	}

	certificates := make(map[string]*Certificate, len(raw.Certificates))
	for index, item := range raw.Certificates {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, fmt.Errorf("certificates[%d].name must not be empty", index)
		}
		if _, exists := certificates[name]; exists {
			return nil, fmt.Errorf("certificate name %q is duplicated", name)
		}
		certPath, err := resolvePath(baseDir, item.CertFile)
		if err != nil {
			return nil, fmt.Errorf("certificate %q: %w", name, err)
		}
		keyPath, err := resolvePath(baseDir, item.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("certificate %q: %w", name, err)
		}
		certificate, err := loadCertificate(name, certPath, keyPath)
		if err != nil {
			return nil, err
		}
		certificates[name] = certificate
	}

	snapshot := &Snapshot{
		loadedAt:      time.Now().UTC(),
		unknownPolicy: policy,
		exact:         make(map[string]*route),
	}
	seenWildcards := make(map[string]struct{})
	for index, item := range raw.Routes {
		host, wildcard, suffix, err := normalizePattern(item.Host)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", index, err)
		}
		certName := strings.TrimSpace(item.Certificate)
		certificate := certificates[certName]
		if certificate == nil {
			return nil, fmt.Errorf("routes[%d] (%q) references unknown certificate %q", index, host, certName)
		}
		if wildcard {
			if _, exists := seenWildcards[host]; exists {
				return nil, fmt.Errorf("wildcard route %q is duplicated", host)
			}
			seenWildcards[host] = struct{}{}
			snapshot.wildcards = append(snapshot.wildcards, &route{
				host: host, wildcard: true, suffix: suffix, certificate: certificate,
			})
			continue
		}
		if _, exists := snapshot.exact[host]; exists {
			return nil, fmt.Errorf("exact route %q is duplicated", host)
		}
		snapshot.exact[host] = &route{host: host, certificate: certificate}
	}
	sortWildcards(snapshot.wildcards)

	if name := strings.TrimSpace(raw.DefaultCertificate); name != "" {
		certificate := certificates[name]
		if certificate == nil {
			return nil, fmt.Errorf("default_certificate references unknown certificate %q", name)
		}
		snapshot.defaultCertificate = certificate
	}
	if snapshot.unknownPolicy == UnknownPolicyDefault && snapshot.defaultCertificate == nil {
		return nil, fmt.Errorf("unknown_sni=%q requires default_certificate", UnknownPolicyDefault)
	}

	runtime.Snapshot = snapshot
	return runtime, nil
}

func parseUnknownPolicy(value string) (UnknownPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "reject", "reject_handshake", "disabled", "disable", "drop":
		return UnknownPolicyReject, nil
	case "default", "default_certificate", "default_cert":
		return UnknownPolicyDefault, nil
	default:
		return "", fmt.Errorf("unknown_sni %q must be %q or %q", value, UnknownPolicyReject, UnknownPolicyDefault)
	}
}

func resolvePath(baseDir, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	if filepath.IsAbs(value) {
		return value, nil
	}
	return filepath.Join(baseDir, value), nil
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode JSON: unexpected trailing data")
		}
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}
