// Package certgateway is the root of the one-time-invitation client
// certificate self-registration system.
//
// The implementation is standard-library only and organized around:
//
//   - invitation: one-time, service/purpose/validity-bound invitations with
//     an in-memory, mutex-guarded store (no external database);
//   - identity:   the signed service/purpose binding embedded in certificates;
//   - pki:        the local CA and crypto/x509 issuance;
//   - enroll:     the challenge/proof-of-possession registration service,
//     HTTP API and Go client;
//   - gateway:    the net.Listener + crypto/tls mTLS gateway that enforces
//     the service binding.
//
// The root test file runs the full end-to-end flow over real localhost
// listeners. Use "go test ./..." for every package.
package certgateway
