// Package testutil builds an in-memory PKI for tests: a CA, server and
// client certificates, CRLs and signed OCSP responses.
package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed CA valid for the given duration.
func NewCA(t *testing.T, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, Key: key}
}

// Issue creates a certificate signed by the CA. server=true makes a server
// cert valid for 127.0.0.1; otherwise a client certificate.
func (ca *CA) Issue(t *testing.T, cn string, serial int64, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Cert.Raw},
		PrivateKey:  key,
	}
}

// Leaf parses the leaf certificate of a tls.Certificate chain.
func Leaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// CreateCRL signs a CRL revoking the given serials, with explicit
// thisUpdate/nextUpdate so tests can control staleness.
func (ca *CA) CreateCRL(t *testing.T, serials []int64, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: thisUpdate,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// OCSPStatus selects the certStatus in a generated OCSP response.
type OCSPStatus int

const (
	OCSPGood OCSPStatus = iota
	OCSPRevoked
	OCSPUnknown
)

// CreateOCSPResponse builds a signed basic OCSP response for one serial.
func (ca *CA) CreateOCSPResponse(t *testing.T, serial int64, status OCSPStatus, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	nameHash, keyHash := ocspIssuerHashes(t, ca.Cert)
	var certStatus asn1.RawValue
	switch status {
	case OCSPGood:
		certStatus = asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte{5, 0}}
	case OCSPRevoked:
		info, err := asn1.Marshal(revokedInfo{RevocationTime: thisUpdate})
		if err != nil {
			t.Fatal(err)
		}
		certStatus = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: info}
	default:
		certStatus = asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte{5, 0}}
	}
	single := ocspSingleResponse{
		CertID: ocspCertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
			NameHash:      nameHash,
			IssuerKeyHash: keyHash,
			SerialNumber:  big.NewInt(serial),
		},
		CertStatus: certStatus,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	tbs := ocspTBSResponseData{
		ResponderID: asn1.RawValue{Class: 2, Tag: 2, Bytes: ca.Cert.RawSubject},
		ProducedAt:  thisUpdate,
		Responses:   []ocspSingleResponse{single},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signTBS(ca, tbsDER)
	if err != nil {
		t.Fatal(err)
	}
	basic := ocspBasicResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		t.Fatal(err)
	}
	resp := ocspResponse{
		Status: 0,
		ResponseBytes: ocspResponseBytes{
			ResponseType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1},
			Response:     basicDER,
		},
	}
	der, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// --- OCSP wire types (mirror of the minimal parser in internal/revoke) ---

type ocspResponse struct {
	Status        asn1.Enumerated
	ResponseBytes ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspBasicResponse struct {
	TBSResponseData    ocspTBSResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type ocspTBSResponseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingleResponse
}

type ocspSingleResponse struct {
	CertID     ocspCertID
	CertStatus asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"explicit,tag:0,optional,generalized"`
}

type ocspCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type revokedInfo struct {
	RevocationTime time.Time `asn1:"generalized"`
}

func ocspIssuerHashes(t *testing.T, issuer *x509.Certificate) (nameHash, keyHash []byte) {
	t.Helper()
	h := sha1.New()
	h.Write(issuer.RawSubject)
	nameHash = h.Sum(nil)
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	h.Reset()
	h.Write(spki.SubjectPublicKey.RightAlign())
	keyHash = h.Sum(nil)
	return nameHash, keyHash
}

func signTBS(ca *CA, tbsDER []byte) ([]byte, error) {
	digest := sha256.Sum256(tbsDER)
	return ca.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
}
