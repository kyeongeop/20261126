package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"certgateway/internal/gateway"
)

type authority struct {
	name string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type leafSpec struct {
	id        string
	domain    string
	dir       string
	notBefore time.Time
	notAfter  time.Time
	includeCA bool
}

func main() {
	root := mustAbs(".")
	certRoot := filepath.Join(root, "fixtures", "certificates")
	configRoot := filepath.Join(root, "fixtures", "gateway")

	must(os.MkdirAll(filepath.Join(certRoot, "ca"), 0o755))
	must(os.MkdirAll(configRoot, 0o755))

	rootCA := newAuthority("Local Gateway Root CA", nil, time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	writeAuthority(filepath.Join(certRoot, "ca"), rootCA)

	intermediate := newAuthority("Local Gateway Intermediate CA", rootCA, time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC))
	writeAuthority(filepath.Join(certRoot, "ca"), intermediate)

	leaves := []leafSpec{
		{id: "shop", domain: "shop.example.test", dir: "edge/shop.example.test", notBefore: date(2026, 8, 1), notAfter: date(2027, 1, 18), includeCA: true},
		{id: "api", domain: "api.example.test", dir: "public/api.example.test", notBefore: date(2026, 9, 1), notAfter: date(2027, 9, 1), includeCA: true},
		{id: "admin", domain: "admin.example.test", dir: "internal/admin.example.test", notBefore: date(2026, 6, 1), notAfter: date(2026, 12, 12), includeCA: false},
		{id: "legacy", domain: "legacy.example.test", dir: "legacy/legacy.example.test", notBefore: date(2025, 9, 1), notAfter: date(2026, 9, 15), includeCA: true},
		{id: "orders", domain: "orders.example.test", dir: "payments/orders.example.test", notBefore: date(2026, 10, 1), notAfter: date(2027, 10, 1), includeCA: true},
	}

	for _, spec := range leaves {
		dir := filepath.Join(certRoot, spec.dir)
		must(os.MkdirAll(dir, 0o755))
		leaf, key := issueLeaf(intermediate, spec)
		writePEM(filepath.Join(dir, "cert.pem"), "CERTIFICATE", leaf)
		writeKey(filepath.Join(dir, "key.pem"), key)
		if spec.includeCA {
			writePEM(filepath.Join(dir, "chain.pem"), "CERTIFICATE", intermediate.cert.Raw)
			writeChain(filepath.Join(dir, "fullchain.pem"), leaf, intermediate.cert.Raw)
		}
	}

	oldOrders, _ := issueLeaf(intermediate, leafSpec{
		id: "orders", domain: "orders.example.test",
		notBefore: date(2025, 10, 1), notAfter: date(2026, 12, 5), includeCA: true,
	})
	writePEM(filepath.Join(configRoot, "orders-previous.pem"), "CERTIFICATE", oldOrders)
	must(writeConfig(configRoot, leaves))
	must(writeGatewayState(configRoot, root, oldOrders, intermediate.cert.Raw))
	fmt.Println("fixtures written to", root)
}

func writeGatewayState(configRoot, root string, oldOrders, intermediateRaw []byte) error {
	configPath := filepath.Join(configRoot, "gateway.json")
	bootstrapPath := filepath.Join(configRoot, ".bootstrap-state.json")
	_ = os.Remove(bootstrapPath)
	defer os.Remove(bootstrapPath)

	runtime, err := gateway.New(configPath, bootstrapPath, root)
	if err != nil {
		return err
	}
	snapshot := runtime.Snapshot()
	reloadedAt := time.Date(2026, 11, 24, 9, 30, 0, 0, time.UTC)
	snapshot.ReloadedAt = reloadedAt
	for id, loaded := range snapshot.Certificates {
		loaded.LoadedAt = reloadedAt
		snapshot.Certificates[id] = loaded
	}

	oldCert, err := x509.ParseCertificate(oldOrders)
	if err != nil {
		return err
	}
	current := snapshot.Certificates["orders"]
	current.Fingerprint = hashBytes(oldCert.Raw)
	current.BundleSHA256 = hashBytes(append(append([]byte{}, oldOrders...), intermediateRaw...))
	current.Subject = oldCert.Subject.String()
	current.Issuer = oldCert.Issuer.String()
	current.DNSNames = append([]string(nil), oldCert.DNSNames...)
	current.NotBefore = oldCert.NotBefore.UTC()
	current.NotAfter = oldCert.NotAfter.UTC()
	current.ChainLength = 2
	current.LoadedAt = reloadedAt
	snapshot.Certificates["orders"] = current

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configRoot, "state.json"), append(data, '\n'), 0o644)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func newAuthority(name string, parent *authority, notBefore, notAfter time.Time) *authority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	serial := mustSerial()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Local TLS Gateway"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		template.SubjectKeyId = []byte{1, 2, 3, 4}
		template.MaxPathLen = 1
	} else {
		template.SubjectKeyId = []byte{5, 6, 7, 8}
		template.AuthorityKeyId = parent.cert.SubjectKeyId
	}
	parentCert := template
	signer := key
	if parent != nil {
		parentCert = parent.cert
		signer = parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, signer)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)
	return &authority{name: name, cert: cert, key: key}
}

func issueLeaf(ca *authority, spec leafSpec) ([]byte, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{
		SerialNumber:   mustSerial(),
		Subject:        pkix.Name{CommonName: spec.domain, Organization: []string{"Local TLS Gateway"}},
		DNSNames:       []string{spec.domain},
		NotBefore:      spec.notBefore,
		NotAfter:       spec.notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	must(err)
	return der, key
}

func writeAuthority(dir string, ca *authority) {
	must(os.MkdirAll(dir, 0o755))
	base := "root"
	if ca.name == "Local Gateway Intermediate CA" {
		base = "intermediate"
	}
	writePEM(filepath.Join(dir, base+".pem"), "CERTIFICATE", ca.cert.Raw)
	writeKey(filepath.Join(dir, base+"-key.pem"), ca.key)
}

func writeConfig(dir string, leaves []leafSpec) error {
	type certConfig struct {
		ID       string `json:"id"`
		Domain   string `json:"domain"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
		Enabled  bool   `json:"enabled"`
	}
	cfg := struct {
		Name         string       `json:"name"`
		RootCAPath   string       `json:"root_ca_path"`
		Certificates []certConfig `json:"certificates"`
	}{
		Name:       "local-tls-gateway",
		RootCAPath: "fixtures/certificates/ca/root.pem",
	}
	for _, leaf := range leaves {
		dir := filepath.ToSlash(filepath.Join("fixtures/certificates", leaf.dir))
		certName := "fullchain.pem"
		if !leaf.includeCA {
			certName = "cert.pem"
		}
		cfg.Certificates = append(cfg.Certificates, certConfig{
			ID: leaf.id, Domain: leaf.domain,
			CertPath: filepath.ToSlash(filepath.Join(dir, certName)),
			KeyPath:  filepath.ToSlash(filepath.Join(dir, "key.pem")),
			Enabled:  leaf.id != "legacy",
		})
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "gateway.json"), append(data, '\n'), 0o644)
}

func writePEM(path, blockType string, der []byte) {
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	must(os.WriteFile(path, data, 0o644))
}

func writeChain(path string, ders ...[]byte) {
	var data []byte
	for _, der := range ders {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	must(os.WriteFile(path, data, 0o644))
}

func writeKey(path string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	writePEM(path, "PRIVATE KEY", der)
}

func mustSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	must(err)
	return serial
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	must(err)
	return abs
}

func date(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}
