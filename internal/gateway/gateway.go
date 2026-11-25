package gateway

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const stateVersion = 1

type LoadedCertificate struct {
	ID           string    `json:"id"`
	CertPath     string    `json:"cert_path"`
	KeyPath      string    `json:"key_path"`
	Fingerprint  string    `json:"fingerprint"`
	BundleSHA256 string    `json:"bundle_sha256"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	DNSNames     []string  `json:"dns_names"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	ChainLength  int       `json:"chain_length"`
	LoadedAt     time.Time `json:"loaded_at"`
}

type Snapshot struct {
	Version      int                          `json:"version"`
	Gateway      string                       `json:"gateway"`
	ReloadedAt   time.Time                    `json:"reloaded_at"`
	Certificates map[string]LoadedCertificate `json:"certificates"`
	Errors       map[string]string            `json:"errors,omitempty"`
}

type Gateway struct {
	mu         sync.RWMutex
	configPath string
	statePath  string
	baseDir    string
	config     Config
	snapshot   Snapshot
}

func New(configPath, statePath, baseDir string) (*Gateway, error) {
	config, err := LoadConfig(configPath, baseDir)
	if err != nil {
		return nil, err
	}

	gateway := &Gateway{
		configPath: configPath,
		statePath:  statePath,
		baseDir:    baseDir,
		config:     config,
	}
	if err := gateway.restoreState(); err != nil {
		if reloadErr := gateway.Reload(); reloadErr != nil {
			return nil, fmt.Errorf("restore gateway state: %v; initial reload: %w", err, reloadErr)
		}
	}
	return gateway, nil
}

func (g *Gateway) Config() Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

func (g *Gateway) Snapshot() Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return cloneSnapshot(g.snapshot)
}

func (g *Gateway) Reload() error {
	config, err := LoadConfig(g.configPath, g.baseDir)
	if err != nil {
		return err
	}

	reloadedAt := time.Now().UTC()
	snapshot := Snapshot{
		Version:      stateVersion,
		Gateway:      config.Name,
		ReloadedAt:   reloadedAt,
		Certificates: make(map[string]LoadedCertificate),
		Errors:       make(map[string]string),
	}

	for _, configured := range config.Certificates {
		if !configured.Enabled {
			continue
		}
		loaded, loadErr := loadCertificate(configured, g.baseDir, reloadedAt)
		if loadErr != nil {
			snapshot.Errors[configured.ID] = loadErr.Error()
			continue
		}
		snapshot.Certificates[configured.ID] = loaded
	}

	g.mu.Lock()
	g.config = config
	g.snapshot = snapshot
	g.mu.Unlock()

	if err := g.persistState(snapshot); err != nil {
		return fmt.Errorf("gateway reloaded but state could not be saved: %w", err)
	}
	return nil
}

func (g *Gateway) restoreState() error {
	data, err := os.ReadFile(g.statePath)
	if err != nil {
		return err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	if snapshot.Version != stateVersion || snapshot.Gateway != g.config.Name {
		return errors.New("gateway state does not match the current configuration")
	}
	if snapshot.Certificates == nil {
		snapshot.Certificates = make(map[string]LoadedCertificate)
	}
	if snapshot.Errors == nil {
		snapshot.Errors = make(map[string]string)
	}

	g.mu.Lock()
	g.snapshot = snapshot
	g.mu.Unlock()
	return nil
}

func (g *Gateway) persistState(snapshot Snapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(g.statePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gateway-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, g.statePath)
}

func loadCertificate(configured CertificateConfig, baseDir string, loadedAt time.Time) (LoadedCertificate, error) {
	pair, err := tls.LoadX509KeyPair(configured.CertPath, configured.KeyPath)
	if err != nil {
		return LoadedCertificate{}, fmt.Errorf("load certificate and key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return LoadedCertificate{}, errors.New("certificate file contains no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return LoadedCertificate{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	bundle, err := os.ReadFile(configured.CertPath)
	if err != nil {
		return LoadedCertificate{}, fmt.Errorf("read certificate bundle: %w", err)
	}
	if _, ok := pair.PrivateKey.(crypto.Signer); !ok {
		return LoadedCertificate{}, errors.New("certificate private key is unavailable")
	}

	return LoadedCertificate{
		ID:           configured.ID,
		CertPath:     RelativePath(baseDir, configured.CertPath),
		KeyPath:      RelativePath(baseDir, configured.KeyPath),
		Fingerprint:  fingerprint(leaf.Raw),
		BundleSHA256: fingerprint(bundle),
		Subject:      leaf.Subject.String(),
		Issuer:       leaf.Issuer.String(),
		DNSNames:     append([]string(nil), leaf.DNSNames...),
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		ChainLength:  len(pair.Certificate),
		LoadedAt:     loadedAt,
	}, nil
}

func fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	cloned := snapshot
	cloned.Certificates = make(map[string]LoadedCertificate, len(snapshot.Certificates))
	for key, value := range snapshot.Certificates {
		value.DNSNames = append([]string(nil), value.DNSNames...)
		cloned.Certificates[key] = value
	}
	cloned.Errors = make(map[string]string, len(snapshot.Errors))
	for key, value := range snapshot.Errors {
		cloned.Errors[key] = value
	}
	return cloned
}
