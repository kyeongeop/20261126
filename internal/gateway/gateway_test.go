package gateway

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureReload(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(filepath.Join(root, "fixtures/gateway/gateway.json"), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range config.Certificates {
		if !cert.Enabled {
			continue
		}
		if _, err := loadCertificate(cert, root, time.Now()); err != nil {
			t.Errorf("%s: %v", cert.ID, err)
		}
	}
}
