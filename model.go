package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	rolePublisher = "publisher"
	roleAdmin     = "admin"
)

var (
	packageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

var (
	errVersionExists  = errors.New("published version already exists")
	errInvalidName    = errors.New("invalid package name")
	errInvalidVersion = errors.New("invalid package version")
)

type Publisher struct {
	User        string    `json:"user"`
	Role        string    `json:"role"`
	PublishedAt time.Time `json:"published_at"`
	RemoteAddr  string    `json:"remote_addr,omitempty"`
}

type Signature struct {
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Value     string    `json:"value"`
	SignedAt  time.Time `json:"signed_at"`
}

type signedSignature struct {
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	SignedAt  time.Time `json:"signed_at"`
}

type RepairInfo struct {
	OfVersion string `json:"of_version"`
	Reason    string `json:"reason"`
}

type ArchiveInfo struct {
	Format  string `json:"format"`
	Size    int64  `json:"size"`
	Entries int    `json:"entries"`
}

type Release struct {
	SchemaVersion int         `json:"schema_version"`
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	ContentDigest string      `json:"content_digest"`
	Publisher     Publisher   `json:"publisher"`
	Archive       ArchiveInfo `json:"archive"`
	Repair        *RepairInfo `json:"repair,omitempty"`
	Signature     Signature   `json:"signature"`
	PublishedAt   time.Time   `json:"published_at"`
}

func (r Release) signedPayload() ([]byte, error) {
	payload := struct {
		SchemaVersion int             `json:"schema_version"`
		Name          string          `json:"name"`
		Version       string          `json:"version"`
		ContentDigest string          `json:"content_digest"`
		Publisher     Publisher       `json:"publisher"`
		Archive       ArchiveInfo     `json:"archive"`
		Repair        *RepairInfo     `json:"repair,omitempty"`
		Signature     signedSignature `json:"signature"`
		PublishedAt   time.Time       `json:"published_at"`
	}{
		SchemaVersion: r.SchemaVersion,
		Name:          r.Name,
		Version:       r.Version,
		ContentDigest: r.ContentDigest,
		Publisher:     r.Publisher,
		Archive:       r.Archive,
		Repair:        r.Repair,
		Signature: signedSignature{
			Algorithm: r.Signature.Algorithm,
			KeyID:     r.Signature.KeyID,
			SignedAt:  r.Signature.SignedAt,
		},
		PublishedAt: r.PublishedAt,
	}
	return json.Marshal(payload)
}

func validateIdentity(name, version string) error {
	if !packageNamePattern.MatchString(name) {
		return errInvalidName
	}
	if !versionPattern.MatchString(version) || strings.Contains(version, "..") {
		return errInvalidVersion
	}
	return nil
}
