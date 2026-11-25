package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the enrollment HTTP API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Enroll runs the full self-registration flow with a fresh P-256 key and
// returns the key plus issued certificate chain.
func (c *Client) Enroll(ctx context.Context, token string) (*EnrolledKey, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	csrDER, csrPEM, err := CreateCSRPEM(key, "")
	if err != nil {
		return nil, err
	}

	var begin beginResponse
	if err := c.postJSON(ctx, PathEnrollBegin, beginRequest{
		Token: token, CSRPEM: string(csrPEM),
	}, &begin); err != nil {
		return nil, fmt.Errorf("enroll begin: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(begin.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	transcript := ChallengeTranscript(nonce, csrDER)
	sig, err := SignChallenge(key, transcript)
	if err != nil {
		return nil, err
	}

	var cred credentialResponse
	if err := c.postJSON(ctx, PathEnrollComplete, completeRequest{
		ChallengeID:  begin.ChallengeID,
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}, &cred); err != nil {
		return nil, fmt.Errorf("enroll complete: %w", err)
	}

	keyPEM, err := EncodeECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &EnrolledKey{
		PrivateKey:     key,
		KeyPEM:         keyPEM,
		CertificatePEM: []byte(cred.CertificatePEM),
		ChainPEM:       []byte(cred.ChainPEM),
	}, nil
}

// CreateInvitation calls the admin API. It is used by operator tooling.
func (c *Client) CreateInvitation(ctx context.Context, adminToken string, in CreateInvitationInput) (*CreatedInvitation, error) {
	var out invitationResponse
	err := c.doJSON(ctx, http.MethodPost, PathAdminInvites, createInvitationRequest{
		Service:          in.Service,
		Purpose:          in.Purpose,
		InviteTTLSeconds: int64(in.InviteTTL / time.Second),
		CertTTLSeconds:   int64(in.CertTTL / time.Second),
	}, &out, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+adminToken)
	})
	if err != nil {
		return nil, err
	}
	return &CreatedInvitation{
		ID: out.ID, Token: out.Token, Service: out.Service, Purpose: out.Purpose, ExpiresAt: out.ExpiresAt,
	}, nil
}

// CreateInvitationInput is the operator invitation request.
type CreateInvitationInput struct {
	Service   string
	Purpose   string
	InviteTTL time.Duration
	CertTTL   time.Duration
}

// CreatedInvitation contains the one-time plaintext token.
type CreatedInvitation struct {
	ID        string
	Token     string
	Service   string
	Purpose   string
	ExpiresAt time.Time
}

func (c *Client) postJSON(ctx context.Context, path string, body, out any) error {
	return c.doJSON(ctx, http.MethodPost, path, body, out, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, out any, decorate func(*http.Request)) error {
	base := c.BaseURL
	if base == "" {
		base = "http://127.0.0.1:0"
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if decorate != nil {
		decorate(req)
	}

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("HTTP %d: %s", res.StatusCode, apiErr.Error)
		}
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
