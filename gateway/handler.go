package gateway

import (
	"encoding/json"
	"net/http"

	"certgateway/identity"
)

// IdentityInfo is returned by /whoami and used by tests/demos.
type IdentityInfo struct {
	CommonName   string `json:"common_name"`
	Service      string `json:"service"`
	Purpose      string `json:"purpose"`
	InvitationID string `json:"invitation_id"`
	Serial       string `json:"serial"`
}

// NewMux builds routes with purpose-based authorization. The TLS layer has
// already verified the chain and the service binding.
//
//	/whoami   any valid client certificate
//	/api/     purpose api or admin
//	/metrics  purpose metrics or admin
//	/admin/   purpose admin only
func NewMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /whoami", handleWhoAmI)
	mux.Handle("GET /api/", requirePurpose(identity.PurposeAPI, identity.PurposeAdmin)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"route": "api", "message": "api access granted"})
		})))
	mux.Handle("GET /metrics", requirePurpose(identity.PurposeMetrics, identity.PurposeAdmin)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"route": "metrics", "load": "0.42"})
		})))
	mux.Handle("GET /admin/", requirePurpose(identity.PurposeAdmin)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"route": "admin"})
		})))
	return mux
}

func handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	state := r.TLS
	if state == nil || len(state.PeerCertificates) == 0 {
		writeError(w, http.StatusUnauthorized, "no client certificate")
		return
	}
	cert := state.PeerCertificates[0]
	b, err := identity.FromCertificate(cert)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, IdentityInfo{
		CommonName:   cert.Subject.CommonName,
		Service:      b.Service,
		Purpose:      b.Purpose,
		InvitationID: b.InvitationID,
		Serial:       cert.SerialNumber.String(),
	})
}

// requirePurpose authorizes only certificates bound to one of allowed purposes.
func requirePurpose(allowed ...string) func(http.Handler) http.Handler {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, p := range allowed {
		allowedSet[p] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				writeError(w, http.StatusUnauthorized, "client certificate required")
				return
			}
			binding, err := identity.FromCertificate(r.TLS.PeerCertificates[0])
			if err != nil {
				writeError(w, http.StatusForbidden, "invalid certificate binding")
				return
			}
			if _, ok := allowedSet[binding.Purpose]; !ok {
				writeError(w, http.StatusForbidden,
					"purpose "+binding.Purpose+" is not allowed on this route")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
