// Package enroll implements the challenge-based client certificate
// self-service registration flow on top of a one-time invitation store and
// the local CA.
//
// Flow:
//
//  1. An operator creates an invitation bound to service, validity and purpose.
//  2. The client calls Begin with the invitation token and a PEM CSR.
//  3. The service validates the invitation and returns a random nonce bound to
//     the CSR.
//  4. The client signs the challenge transcript with the CSR's private key and
//     calls Complete.
//  5. The service verifies the signature, atomically consumes the invitation
//     and returns the service-bound certificate.
package enroll

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"certgateway/identity"
	"certgateway/invitation"
	"certgateway/pki"
)

// TranscriptLabel domain-separates challenge signatures from other protocols.
const TranscriptLabel = "certgateway-enroll-challenge-v1"

// DefaultChallengeTTL is how long a solved/unsolved challenge stays valid.
const DefaultChallengeTTL = 5 * time.Minute

// Flow errors.
var (
	ErrInvalidCSR        = errors.New("enroll: invalid certificate request")
	ErrChallengeNotFound = errors.New("enroll: challenge not found or expired")
	ErrChallengeUsed     = errors.New("enroll: challenge already completed")
	ErrSignature         = errors.New("enroll: challenge signature verification failed")
)

// Service orchestrates invitations, challenges and certificate issuance.
type Service struct {
	Invites      *invitation.Store
	CA           *pki.CA
	ChallengeTTL time.Duration

	mu         sync.Mutex
	challenges map[string]*challenge
}

type challenge struct {
	id           string
	invitationID string
	nonce        []byte
	csrRaw       []byte
	publicKey    crypto.PublicKey
	expiresAt    time.Time
	used         bool
}

// NewService wires a Service.
func NewService(invites *invitation.Store, ca *pki.CA) *Service {
	return &Service{
		Invites:      invites,
		CA:           ca,
		ChallengeTTL: DefaultChallengeTTL,
		challenges:   make(map[string]*challenge),
	}
}

func (s *Service) now() time.Time { return s.Invites.Now() }

// BeginResult is returned by Begin.
type BeginResult struct {
	ChallengeID string
	Nonce       []byte
	ExpiresAt   time.Time
}

// Begin validates the one-time token and CSR and creates a proof-of-possession
// challenge bound to the CSR.
func (s *Service) Begin(token string, csrPEM []byte) (*BeginResult, error) {
	inv, err := s.Invites.AuthenticateToken(token)
	if err != nil {
		return nil, err
	}

	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("enroll: generate nonce: %w", err)
	}
	id, err := randomHexID("ch_")
	if err != nil {
		return nil, err
	}

	ttl := s.ChallengeTTL
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	ch := &challenge{
		id:           id,
		invitationID: inv.ID,
		nonce:        nonce,
		csrRaw:       csr.Raw,
		publicKey:    csr.PublicKey,
		expiresAt:    s.now().Add(ttl),
	}

	s.mu.Lock()
	s.challenges[id] = ch
	s.mu.Unlock()

	return &BeginResult{ChallengeID: id, Nonce: nonce, ExpiresAt: ch.expiresAt}, nil
}

// Credential is the result of a successful enrollment.
type Credential struct {
	CertificatePEM []byte
	ChainPEM       []byte
	Serial         string
	Binding        identity.Binding
	NotAfter       time.Time
}

// Complete verifies the challenge signature and, exactly once per invitation,
// issues the client certificate.
func (s *Service) Complete(challengeID string, signature []byte) (*Credential, error) {
	ch, err := s.takeChallenge(challengeID)
	if err != nil {
		return nil, err
	}

	transcript := ChallengeTranscript(ch.nonce, ch.csrRaw)
	if err := VerifySignature(ch.publicKey, transcript, signature); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}

	inv, err := s.Invites.Get(ch.invitationID)
	if err != nil {
		return nil, err
	}
	binding := identity.Binding{
		Service:      inv.Service,
		Purpose:      inv.Purpose,
		InvitationID: inv.ID,
	}

	serial, err := pki.RandomSerial()
	if err != nil {
		return nil, err
	}

	// Atomic one-time gate: only the caller that transitions pending ->
	// consumed may ask the CA to sign. A failed or losing call never issues.
	consumed, err := s.Invites.Consume(inv.ID, serial.String())
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(ch.csrRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	certPEM, cert, err := s.CA.SignClientCSR(csr, binding, serial, inv.CertValidity, s.now())
	if err != nil {
		return nil, err
	}

	chain := append(append([]byte{}, certPEM...), s.CA.CertPEM...)
	return &Credential{
		CertificatePEM: certPEM,
		ChainPEM:       chain,
		Serial:         consumed.CertSerial,
		Binding:        binding,
		NotAfter:       cert.NotAfter,
	}, nil
}

// takeChallenge validates liveness and marks the challenge used atomically, so
// a challenge can only be completed once.
func (s *Service) takeChallenge(id string) (*challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.challenges[id]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	if s.now().After(ch.expiresAt) {
		delete(s.challenges, id)
		return nil, ErrChallengeNotFound
	}
	if ch.used {
		return nil, ErrChallengeUsed
	}
	ch.used = true
	return ch, nil
}

// ChallengeTranscript builds the exact message the client signs. It binds the
// domain separator and server nonce to the CSR bytes, preventing substitution
// of the public key. SignChallenge/VerifySignature apply the algorithm's
// required hashing.
func ChallengeTranscript(nonce, csrRaw []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(TranscriptLabel)
	buf.Write(nonce)
	buf.Write(csrRaw)
	return buf.Bytes()
}

// SignChallenge signs a transcript digest with a supported client key.
func SignChallenge(key crypto.Signer, transcript []byte) ([]byte, error) {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(transcript)
		return ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), sum[:])
	case ed25519.PublicKey:
		return key.Sign(rand.Reader, transcript, crypto.Hash(0))
	case *rsa.PublicKey:
		sum := sha256.Sum256(transcript)
		return rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, sum[:])
	default:
		return nil, fmt.Errorf("unsupported key type %T", key.Public())
	}
}

// VerifySignature verifies a ChallengeTranscript signature produced by the
// client key matching the CSR.
func VerifySignature(publicKey crypto.PublicKey, transcript, signature []byte) error {
	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(transcript)
		if !ecdsa.VerifyASN1(pub, sum[:], signature) {
			return errors.New("ecdsa verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, transcript, signature) {
			return errors.New("ed25519 verification failed")
		}
		return nil
	case *rsa.PublicKey:
		sum := sha256.Sum256(transcript)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature)
	default:
		return fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

// ParseCSRPEM decodes and validates a PEM-encoded PKCS#10 CSR.
func ParseCSRPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: expected PEM CERTIFICATE REQUEST", ErrInvalidCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	return csr, nil
}

func randomHexID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
