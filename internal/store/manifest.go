package store

import "time"

// Version describes one immutable historical version of a shared file.
//
// Each version owns its own data encryption key (DEK). The DEK is never
// stored in plaintext: WrappedDEK is the DEK sealed under the KEK version
// named by KeyVersion. Old versions are never re-wrapped or rewritten, even
// after key rotation.
type Version struct {
	Number       int       `json:"number"`
	BlobPath     string    `json:"blob_path"`
	KeyVersion   int       `json:"key_version"`
	WrappedDEK   []byte    `json:"wrapped_dek"`
	PlainSHA256  string    `json:"plain_sha256"`
	CipherSHA256 string    `json:"cipher_sha256"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	Note         string    `json:"note,omitempty"`
}

// Manifest is the version ledger of one logical file, stored as
// <data>/files/<id>/manifest.json. Entries are append-only.
type Manifest struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Latest      int       `json:"latest"`
	Versions    []Version `json:"versions"`
	LastUpdated time.Time `json:"last_updated"`
}

// PublicVersion is the safe view of a version returned over HTTP. It exposes
// metadata and checksums but never the wrapped DEK or blob storage path.
type PublicVersion struct {
	Number       int       `json:"number"`
	KeyVersion   int       `json:"key_version"`
	PlainSHA256  string    `json:"plain_sha256"`
	CipherSHA256 string    `json:"cipher_sha256"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	Note         string    `json:"note,omitempty"`
}

// PublicManifest is the safe view of a file ledger.
type PublicManifest struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Latest      int             `json:"latest"`
	LastUpdated time.Time       `json:"last_updated"`
	Versions    []PublicVersion `json:"versions"`
}

func toPublic(m *Manifest) PublicManifest {
	out := PublicManifest{
		ID:          m.ID,
		Name:        m.Name,
		Latest:      m.Latest,
		LastUpdated: m.LastUpdated,
		Versions:    make([]PublicVersion, 0, len(m.Versions)),
	}
	for _, v := range m.Versions {
		out.Versions = append(out.Versions, PublicVersion{
			Number:       v.Number,
			KeyVersion:   v.KeyVersion,
			PlainSHA256:  v.PlainSHA256,
			CipherSHA256: v.CipherSHA256,
			Size:         v.Size,
			CreatedAt:    v.CreatedAt,
			CreatedBy:    v.CreatedBy,
			Note:         v.Note,
		})
	}
	return out
}
