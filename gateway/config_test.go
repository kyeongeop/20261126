package gateway

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
)

func TestLoadExampleConfigs(t *testing.T) {
	runtime, err := LoadConfig(repoFile(t, "config", "gateway.json"))
	if err != nil {
		t.Fatalf("load default example: %v", err)
	}
	if runtime.ListenAddress != "127.0.0.1:8443" {
		t.Fatalf("listen address = %q", runtime.ListenAddress)
	}
	if runtime.LogLevel != slog.LevelDebug {
		t.Fatalf("log level = %v, want debug", runtime.LogLevel)
	}
	if runtime.Snapshot.UnknownPolicy() != UnknownPolicyDefault {
		t.Fatalf("unknown policy = %q, want default", runtime.Snapshot.UnknownPolicy())
	}
	if selection := runtime.Snapshot.Resolve("shop.example.com"); selection.Kind != MatchExact {
		t.Fatalf("shop.example.com kind = %q, want exact", selection.Kind)
	}
	if selection := runtime.Snapshot.Resolve("api.example.com"); selection.Kind != MatchWildcard {
		t.Fatalf("api.example.com kind = %q, want wildcard", selection.Kind)
	}

	runtime, err = LoadConfig(repoFile(t, "config", "gateway-reject.json"))
	if err != nil {
		t.Fatalf("load reject example: %v", err)
	}
	if selection := runtime.Snapshot.Resolve("unknown.example.org"); selection.Kind != MatchRejected {
		t.Fatalf("unknown host kind = %q, want rejected", selection.Kind)
	}
}

func TestParseConfigValidation(t *testing.T) {
	exactCert := strconv.Quote(repoFile(t, "certs", "exact-shop.pem"))
	exactKey := strconv.Quote(repoFile(t, "certs", "exact-shop-key.pem"))
	certificate := fmt.Sprintf(
		`{"name":"exact","cert_file":%s,"key_file":%s}`, exactCert, exactKey)

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "default policy requires default certificate",
			body:    fmt.Sprintf(`{"unknown_sni":"default","certificates":[%s]}`, certificate),
			wantErr: "requires default_certificate",
		},
		{
			name: "duplicate exact route",
			body: fmt.Sprintf(
				`{"certificates":[%s],"routes":[{"host":"shop.example.com","certificate":"exact"},{"host":"SHOP.EXAMPLE.COM.","certificate":"exact"}]}`,
				certificate),
			wantErr: "exact route",
		},
		{
			name: "invalid wildcard",
			body: fmt.Sprintf(
				`{"certificates":[%s],"routes":[{"host":"shop.*.com","certificate":"exact"}]}`,
				certificate),
			wantErr: "wildcard host pattern",
		},
		{
			name: "duplicate wildcard route",
			body: fmt.Sprintf(
				`{"certificates":[%s],"routes":[{"host":"*.example.com","certificate":"exact"},{"host":"*.EXAMPLE.COM.","certificate":"exact"}]}`,
				certificate),
			wantErr: "wildcard route",
		},
		{
			name: "unknown certificate reference",
			body: fmt.Sprintf(
				`{"certificates":[%s],"routes":[{"host":"shop.example.com","certificate":"missing"}]}`,
				certificate),
			wantErr: "unknown certificate",
		},
		{
			name:    "unknown JSON field",
			body:    fmt.Sprintf(`{"certificates":[%s],"unknown_field":true}`, certificate),
			wantErr: "unknown field",
		},
		{
			name:    "invalid unknown policy",
			body:    fmt.Sprintf(`{"unknown_sni":"sometimes","certificates":[%s]}`, certificate),
			wantErr: "unknown_sni",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.body), repoRoot(t))
			if err == nil {
				t.Fatal("ParseConfig succeeded, want error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error %q does not contain %q", err, test.wantErr)
			}
		})
	}
}
