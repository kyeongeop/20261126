package inventory

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"certgateway/internal/gateway"
)

const (
	ChainComplete            = "complete"
	ChainMissingIntermediate = "missing_intermediate"
	ChainUntrusted           = "untrusted"
	ChainInvalid             = "invalid"

	UsageActive   = "active"
	UsageStandby  = "standby"
	UsageStale    = "stale"
	UsagePending  = "pending"
	UsageUnloaded = "unloaded"
)

type ChainInfo struct {
	Status   string `json:"status"`
	Label    string `json:"label"`
	Detail   string `json:"detail"`
	Provided int    `json:"provided"`
}

type UsageInfo struct {
	State             string `json:"state"`
	Label             string `json:"label"`
	Detail            string `json:"detail"`
	Sync              string `json:"sync"`
	LoadedAt          string `json:"loaded_at,omitempty"`
	LoadedExpiresAt   string `json:"loaded_expires_at,omitempty"`
	LoadedFingerprint string `json:"loaded_fingerprint,omitempty"`
}

type Certificate struct {
	ID             string     `json:"id"`
	Domain         string     `json:"domain"`
	DNSNames       []string   `json:"dns_names"`
	Issuer         string     `json:"issuer"`
	Subject        string     `json:"subject"`
	NotBefore      time.Time  `json:"not_before"`
	ExpiresAt      time.Time  `json:"expires_at"`
	DaysRemaining  int        `json:"days_remaining"`
	Expired        bool       `json:"expired"`
	ExpiringSoon   bool       `json:"expiring_soon"`
	Fingerprint    string     `json:"fingerprint"`
	SerialNumber   string     `json:"serial_number"`
	CertPath       string     `json:"cert_path"`
	KeyPath        string     `json:"key_path"`
	FileModifiedAt *time.Time `json:"file_modified_at,omitempty"`
	Chain          ChainInfo  `json:"chain"`
	Usage          UsageInfo  `json:"usage"`
	Error          string     `json:"error,omitempty"`
}

type Summary struct {
	Total        int `json:"total"`
	Active       int `json:"active"`
	Expiring7    int `json:"expiring_7"`
	Expiring30   int `json:"expiring_30"`
	Expiring90   int `json:"expiring_90"`
	Expired      int `json:"expired"`
	Inconsistent int `json:"inconsistent"`
	Incomplete   int `json:"incomplete"`
}

type Filter struct {
	Preset        string `json:"preset,omitempty"`
	ExpiresBefore string `json:"expires_before,omitempty"`
	ExpiresAfter  string `json:"expires_after,omitempty"`
	Usage         string `json:"usage,omitempty"`
	Query         string `json:"query,omitempty"`
}

type Response struct {
	GeneratedAt  time.Time     `json:"generated_at"`
	Gateway      GatewayInfo   `json:"gateway"`
	Summary      Summary       `json:"summary"`
	Visible      int           `json:"visible"`
	Filter       Filter        `json:"filter"`
	Certificates []Certificate `json:"certificates"`
}

type GatewayInfo struct {
	Name       string    `json:"name"`
	ConfigPath string    `json:"config_path"`
	RootCAPath string    `json:"root_ca_path"`
	ReloadedAt time.Time `json:"reloaded_at"`
}

type Service struct {
	gateway *gateway.Gateway
	now     func() time.Time
}

func NewService(gatewayState *gateway.Gateway) *Service {
	return &Service{gateway: gatewayState, now: time.Now}
}

func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

func (s *Service) List(filter Filter) Response {
	now := s.now().UTC()
	config := s.gateway.Config()
	snapshot := s.gateway.Snapshot()
	roots, rootErr := loadRootPool(config.RootCAPath)

	certificates := make([]Certificate, 0, len(config.Certificates))
	for _, configured := range config.Certificates {
		certificates = append(certificates, inspectCertificate(configured, snapshot.Certificates[configured.ID], snapshot, config.BaseDir, roots, rootErr, now))
	}

	summary := summarize(certificates, now)
	sort.SliceStable(certificates, func(i, j int) bool {
		if certificates[i].ExpiresAt.Equal(certificates[j].ExpiresAt) {
			return certificates[i].Domain < certificates[j].Domain
		}
		return certificates[i].ExpiresAt.Before(certificates[j].ExpiresAt)
	})

	filtered := make([]Certificate, 0, len(certificates))
	for _, cert := range certificates {
		if matchesFilter(cert, filter, now) {
			filtered = append(filtered, cert)
		}
	}

	return Response{
		GeneratedAt: now,
		Gateway: GatewayInfo{
			Name:       config.Name,
			ConfigPath: config.ConfigPath,
			RootCAPath: config.RootCAPath,
			ReloadedAt: snapshot.ReloadedAt,
		},
		Summary:      summary,
		Visible:      len(filtered),
		Filter:       filter,
		Certificates: filtered,
	}
}

func inspectCertificate(configured gateway.CertificateConfig, loaded gateway.LoadedCertificate, snapshot gateway.Snapshot, baseDir string, roots *x509.CertPool, rootErr error, now time.Time) Certificate {
	certificate := Certificate{
		ID:       configured.ID,
		Domain:   configured.Domain,
		CertPath: configured.CertPath,
		KeyPath:  configured.KeyPath,
		DNSNames: []string{configured.Domain},
		Chain: ChainInfo{
			Status: ChainInvalid,
			Label:  "无法读取",
			Detail: "证书文件不可用",
		},
	}

	certData, readErr := os.ReadFile(configured.CertPath)
	if readErr != nil {
		certificate.Error = fmt.Sprintf("读取证书失败：%v", readErr)
		certificate.ExpiresAt = time.Time{}
		certificate.Usage = usageFor(configured, loaded, snapshot, baseDir, certificate.Error)
		return certificate
	}

	if info, statErr := os.Stat(configured.CertPath); statErr == nil {
		modified := info.ModTime().UTC()
		certificate.FileModifiedAt = &modified
	}

	certs := parseCertificates(certData)
	if len(certs) == 0 {
		certificate.Error = "证书文件中没有有效的 CERTIFICATE 块"
		certificate.Usage = usageFor(configured, loaded, snapshot, baseDir, certificate.Error)
		return certificate
	}

	leaf := certs[0]
	certificate.Subject = leaf.Subject.String()
	certificate.Issuer = leaf.Issuer.CommonName
	if certificate.Issuer == "" {
		certificate.Issuer = leaf.Issuer.String()
	}
	certificate.NotBefore = leaf.NotBefore.UTC()
	certificate.ExpiresAt = leaf.NotAfter.UTC()
	certificate.DaysRemaining = daysRemaining(now, certificate.ExpiresAt)
	certificate.Expired = !certificate.ExpiresAt.After(now)
	certificate.ExpiringSoon = !certificate.Expired && certificate.DaysRemaining <= 30
	certificate.SerialNumber = leaf.SerialNumber.Text(16)
	certificate.Fingerprint = fingerprint(leaf.Raw)
	if len(leaf.DNSNames) > 0 {
		certificate.DNSNames = append([]string(nil), leaf.DNSNames...)
	}

	certificate.Chain = inspectChain(certs, roots, rootErr, leaf)
	if _, keyErr := tls.LoadX509KeyPair(configured.CertPath, configured.KeyPath); keyErr != nil {
		certificate.Error = fmt.Sprintf("私钥或证书对不可用：%v", keyErr)
	}
	certificate.Usage = usageFor(configured, loaded, snapshot, baseDir, certificate.Error)
	return certificate
}

func usageFor(configured gateway.CertificateConfig, loaded gateway.LoadedCertificate, snapshot gateway.Snapshot, baseDir, parseError string) UsageInfo {
	if !configured.Enabled {
		return UsageInfo{State: UsageStandby, Label: "未启用", Detail: "未纳入网关监听配置", Sync: "disabled"}
	}

	if loadError := snapshot.Errors[configured.ID]; loadError != "" {
		return UsageInfo{
			State:  UsageUnloaded,
			Label:  "未加载",
			Detail: "网关重载时无法读取此证书",
			Sync:   "unloaded",
		}
	}

	if loaded.ID == "" {
		return UsageInfo{
			State:  UsagePending,
			Label:  "待重载",
			Detail: "配置中存在，但网关内存快照尚无此证书",
			Sync:   "pending",
		}
	}

	if !samePath(baseDir, loaded.CertPath, configured.CertPath) || !samePath(baseDir, loaded.KeyPath, configured.KeyPath) {
		return UsageInfo{
			State:             UsageStale,
			Label:             "配置已变更",
			Detail:            "证书路径已变更，网关仍在加载旧配置",
			Sync:              "stale",
			LoadedAt:          loaded.LoadedAt.Format(time.RFC3339),
			LoadedExpiresAt:   loaded.NotAfter.Format(time.RFC3339),
			LoadedFingerprint: loaded.Fingerprint,
		}
	}

	if parseError != "" {
		return UsageInfo{
			State:             UsageStale,
			Label:             "文件不可用",
			Detail:            "磁盘证书与网关已加载版本不一致",
			Sync:              "stale",
			LoadedAt:          loaded.LoadedAt.Format(time.RFC3339),
			LoadedExpiresAt:   loaded.NotAfter.Format(time.RFC3339),
			LoadedFingerprint: loaded.Fingerprint,
		}
	}

	currentFingerprint := ""
	if data, err := os.ReadFile(configured.CertPath); err == nil {
		if certs := parseCertificates(data); len(certs) > 0 {
			currentFingerprint = fingerprint(certs[0].Raw)
		}
		currentBundle := fingerprint(data)
		if currentFingerprint != loaded.Fingerprint || currentBundle != loaded.BundleSHA256 {
			return UsageInfo{
				State:             UsageStale,
				Label:             "文件不一致",
				Detail:            "证书文件已更新，但网关配置尚未重载，当前使用状态不一致",
				Sync:              "stale",
				LoadedAt:          loaded.LoadedAt.Format(time.RFC3339),
				LoadedExpiresAt:   loaded.NotAfter.Format(time.RFC3339),
				LoadedFingerprint: loaded.Fingerprint,
			}
		}
	}

	if currentFingerprint == "" {
		return UsageInfo{
			State:             UsageStale,
			Label:             "文件不可用",
			Detail:            "网关卡仍使用内存中的旧证书",
			Sync:              "stale",
			LoadedAt:          loaded.LoadedAt.Format(time.RFC3339),
			LoadedExpiresAt:   loaded.NotAfter.Format(time.RFC3339),
			LoadedFingerprint: loaded.Fingerprint,
		}
	}

	return UsageInfo{
		State:             UsageActive,
		Label:             "使用中",
		Detail:            "网关当前加载的证书与磁盘一致",
		Sync:              "synced",
		LoadedAt:          loaded.LoadedAt.Format(time.RFC3339),
		LoadedExpiresAt:   loaded.NotAfter.Format(time.RFC3339),
		LoadedFingerprint: loaded.Fingerprint,
	}
}

func samePath(baseDir, loadedPath, configuredPath string) bool {
	resolved := loadedPath
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}
	return filepath.Clean(resolved) == filepath.Clean(configuredPath)
}

func inspectChain(certs []*x509.Certificate, roots *x509.CertPool, rootErr error, leaf *x509.Certificate) ChainInfo {
	info := ChainInfo{
		Status:   ChainInvalid,
		Label:    "链不完整",
		Detail:   "无法建立到本地根 CA 的信任链",
		Provided: len(certs),
	}
	if rootErr != nil {
		info.Detail = fmt.Sprintf("本地根 CA 不可用：%v", rootErr)
		return info
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	verifyTime := leaf.NotBefore.Add(time.Minute)
	if verifyTime.After(leaf.NotAfter) {
		verifyTime = leaf.NotAfter.Add(-time.Minute)
	}
	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   verifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(leaf.DNSNames) > 0 {
		options.DNSName = leaf.DNSNames[0]
	}
	if _, err := leaf.Verify(options); err == nil {
		info.Status = ChainComplete
		info.Label = "完整"
		info.Detail = fmt.Sprintf("叶子证书 + %d 张中间证书，已验证至本地根 CA", len(certs)-1)
		return info
	}

	if len(certs) == 1 {
		info.Status = ChainMissingIntermediate
		info.Label = "缺少中间证书"
		info.Detail = "文件中只有叶子证书，浏览器可能无法完成链验证"
		return info
	}
	info.Status = ChainUntrusted
	info.Label = "链不受信任"
	info.Detail = "提供的证书链无法验证至本地根 CA"
	return info
}

func parseCertificates(data []byte) []*x509.Certificate {
	var certificates []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certificates = append(certificates, cert)
		}
	}
	return certificates
}

func loadRootPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("root CA file contains no valid certificate")
	}
	return pool, nil
}

func summarize(certificates []Certificate, now time.Time) Summary {
	summary := Summary{Total: len(certificates)}
	for _, cert := range certificates {
		if cert.Usage.State == UsageActive {
			summary.Active++
		}
		if cert.Usage.State == UsageStale {
			summary.Inconsistent++
		}
		if cert.ExpiresAt.IsZero() {
			continue
		}
		days := daysRemaining(now, cert.ExpiresAt)
		if cert.Chain.Status != ChainComplete {
			summary.Incomplete++
		}
		if cert.Expired {
			summary.Expired++
			continue
		}
		if days <= 7 {
			summary.Expiring7++
		}
		if days <= 30 {
			summary.Expiring30++
		}
		if days <= 90 {
			summary.Expiring90++
		}
	}
	return summary
}

func matchesFilter(cert Certificate, filter Filter, now time.Time) bool {
	if filter.Usage != "" && filter.Usage != "all" && cert.Usage.State != filter.Usage {
		return false
	}
	if filter.Query != "" {
		query := strings.ToLower(strings.TrimSpace(filter.Query))
		haystack := strings.ToLower(strings.Join([]string{
			cert.Domain, cert.Issuer, cert.Subject, cert.CertPath, strings.Join(cert.DNSNames, " "),
		}, " "))
		if !strings.Contains(haystack, query) {
			return false
		}
	}
	if cert.ExpiresAt.IsZero() {
		return filter.Preset == "" && filter.ExpiresBefore == "" && filter.ExpiresAfter == ""
	}

	switch filter.Preset {
	case "", "all":
	case "custom":
	case "expired":
		if !cert.Expired {
			return false
		}
	case "7d", "30d", "90d":
		days := map[string]int{"7d": 7, "30d": 30, "90d": 90}[filter.Preset]
		if cert.Expired || cert.ExpiresAt.After(now.AddDate(0, 0, days)) {
			return false
		}
	default:
		return false
	}

	if filter.ExpiresAfter != "" {
		value, err := parseDate(filter.ExpiresAfter, false)
		if err != nil || cert.ExpiresAt.Before(value) {
			return false
		}
	}
	if filter.ExpiresBefore != "" {
		value, err := parseDate(filter.ExpiresBefore, true)
		if err != nil || cert.ExpiresAt.After(value) {
			return false
		}
	}
	return true
}

func parseDate(value string, endOfDay bool) (time.Time, error) {
	parsed, err := time.ParseInLocation("2006-01-02", value, time.UTC)
	if err != nil {
		return time.Time{}, err
	}
	if endOfDay {
		parsed = parsed.Add(24*time.Hour - time.Nanosecond)
	}
	return parsed, nil
}

func daysRemaining(now, expiresAt time.Time) int {
	return int(math.Floor(expiresAt.Sub(now).Hours() / 24))
}

func fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
