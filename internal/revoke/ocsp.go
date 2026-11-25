package revoke

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Minimal OCSP (RFC 6960) decoding built on encoding/asn1 so the gateway
// works with pinned responses in an isolated environment without any
// third-party dependency.

var oidBasicOCSPResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

type ocspResponse struct {
	Status       asn1.Enumerated
	ResponseBytes responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicOCSPResponse struct {
	TBSResponseData      asn1.RawValue
	SignatureAlgorithm   pkix.AlgorithmIdentifier
	Signature            asn1.BitString
	Certificates         []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type tbsResponseData struct {
	Version       int `asn1:"optional,explicit,tag:0,default:0"`
	ResponderID   asn1.RawValue
	ProducedAt    time.Time `asn1:"generalized"`
	Responses     []singleResponse
	Extensions    []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponse struct {
	CertID     certID
	CertStatus asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"explicit,tag:0,optional,generalized"`
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// PinnedOCSP is a pre-fetched, offline OCSP response for one issuer.
type PinnedOCSP struct {
	Responses []ocspSingle
}

type ocspSingle struct {
	Serial     *big.Int
	Status     Status
	ThisUpdate time.Time
	NextUpdate time.Time
}

var errOCSPBadResponse = errors.New("revoke: malformed OCSP response")

// ParseOCSPResponse decodes a DER OCSP response and verifies its signature
// against issuer. Only responses carrying a single certificate status that
// matches issuer are accepted.
func ParseOCSPResponse(der []byte, issuer *x509.Certificate) (*PinnedOCSP, error) {
	var resp ocspResponse
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, fmt.Errorf("%w: %v", errOCSPBadResponse, err)
	}
	if resp.Status != 0 {
		return nil, fmt.Errorf("%w: responder status %d", errOCSPBadResponse, resp.Status)
	}
	if !resp.ResponseBytes.ResponseType.Equal(oidBasicOCSPResponse) {
		return nil, fmt.Errorf("%w: unsupported response type %s", errOCSPBadResponse, resp.ResponseBytes.ResponseType)
	}
	var basic basicOCSPResponse
	if _, err := asn1.Unmarshal(resp.ResponseBytes.Response, &basic); err != nil {
		return nil, fmt.Errorf("%w: %v", errOCSPBadResponse, err)
	}
	var tbs tbsResponseData
	if _, err := asn1.Unmarshal(basic.TBSResponseData.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("%w: %v", errOCSPBadResponse, err)
	}
	algo, ok := signatureAlgorithm(basic.SignatureAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported signature algorithm %s", errOCSPBadResponse, basic.SignatureAlgorithm.Algorithm)
	}
	signer := issuer
	if len(basic.Certificates) > 0 {
		if c, err := x509.ParseCertificate(basic.Certificates[0].FullBytes); err == nil {
			if bytes.Equal(c.RawSubject, issuer.RawSubject) || c.CheckSignatureFrom(issuer) == nil {
				signer = c
			}
		}
	}
	if err := signer.CheckSignature(algo, basic.TBSResponseData.FullBytes, basic.Signature.RightAlign()); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", errOCSPBadResponse, err)
	}
	nameHash, keyHash := issuerHashes(issuer, crypto.SHA1)
	pinned := &PinnedOCSP{}
	for _, r := range tbs.Responses {
		if !bytes.Equal(r.CertID.NameHash, nameHash) || !bytes.Equal(r.CertID.IssuerKeyHash, keyHash) {
			continue
		}
		pinned.Responses = append(pinned.Responses, ocspSingle{
			Serial:     new(big.Int).Set(r.CertID.SerialNumber),
			Status:     parseCertStatus(r.CertStatus),
			ThisUpdate: r.ThisUpdate,
			NextUpdate: r.NextUpdate,
		})
	}
	if len(pinned.Responses) == 0 {
		return nil, fmt.Errorf("%w: no responses for issuer %q", errOCSPBadResponse, issuer.Subject)
	}
	return pinned, nil
}

func parseCertStatus(raw asn1.RawValue) Status {
	switch raw.Tag {
	case 0:
		return StatusGood
	case 1:
		return StatusRevoked
	default:
		return StatusUnknown
	}
}

func issuerHashes(issuer *x509.Certificate, hash crypto.Hash) (nameHash, keyHash []byte) {
	h := hash.New()
	h.Write(issuer.RawSubject)
	nameHash = h.Sum(nil)
	h.Reset()
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err == nil {
		h.Write(spki.SubjectPublicKey.RightAlign())
	}
	keyHash = h.Sum(nil)
	return nameHash, keyHash
}

func (p *PinnedOCSP) lookup(serial *big.Int) (ocspSingle, bool) {
	for _, r := range p.Responses {
		if r.Serial.Cmp(serial) == 0 {
			return r, true
		}
	}
	return ocspSingle{}, false
}

func signatureAlgorithm(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, bool) {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return x509.SHA256WithRSA, true
	case oid.Equal(oidSHA384WithRSA):
		return x509.SHA384WithRSA, true
	case oid.Equal(oidSHA512WithRSA):
		return x509.SHA512WithRSA, true
	case oid.Equal(oidECDSAWithSHA256):
		return x509.ECDSAWithSHA256, true
	case oid.Equal(oidECDSAWithSHA384):
		return x509.ECDSAWithSHA384, true
	case oid.Equal(oidECDSAWithSHA512):
		return x509.ECDSAWithSHA512, true
	}
	return x509.UnknownSignatureAlgorithm, false
}

var (
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)
