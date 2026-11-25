package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CertificateConfig struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	Enabled  bool   `json:"enabled"`
}

type Config struct {
	Name         string              `json:"name"`
	RootCAPath   string              `json:"root_ca_path"`
	Certificates []CertificateConfig `json:"certificates"`
	ConfigPath   string              `json:"-"`
	BaseDir      string              `json:"-"`
}

func LoadConfig(path, baseDir string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read gateway config: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode gateway config: %w", err)
	}
	if strings.TrimSpace(config.Name) == "" {
		config.Name = "local-tls-gateway"
	}
	config.ConfigPath = path
	config.BaseDir = baseDir

	for index := range config.Certificates {
		cert := &config.Certificates[index]
		cert.CertPath = resolvePath(baseDir, cert.CertPath)
		cert.KeyPath = resolvePath(baseDir, cert.KeyPath)
	}
	config.RootCAPath = resolvePath(baseDir, config.RootCAPath)
	return config, nil
}

func RelativePath(baseDir, path string) string {
	if !filepath.IsAbs(path) {
		return filepath.ToSlash(filepath.Clean(path))
	}
	relative, err := filepath.Rel(baseDir, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

func resolvePath(baseDir, path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}
