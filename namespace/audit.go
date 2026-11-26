package namespace

import (
	"archive/tar"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const zeroAuditHash = "0000000000000000000000000000000000000000000000000000000000000000"

type auditHashMaterial struct {
	SchemaVersion int       `json:"schema_version"`
	Sequence      int64     `json:"sequence"`
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Namespace     string    `json:"namespace,omitempty"`
	ActorID       string    `json:"actor_id"`
	ActorName     string    `json:"actor_name"`
	ActorRole     string    `json:"actor_role"`
	RequestID     string    `json:"request_id,omitempty"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	ClaimID       string    `json:"claim_id,omitempty"`
	FromOwnerID   string    `json:"from_owner_id,omitempty"`
	FromOwnerName string    `json:"from_owner_name,omitempty"`
	ToOwnerID     string    `json:"to_owner_id,omitempty"`
	ToOwnerName   string    `json:"to_owner_name,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Details       string    `json:"details,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	PreviousHash  string    `json:"previous_hash"`
}

func hashAuditEvent(event AuditEvent) (string, error) {
	material := auditHashMaterial{
		SchemaVersion: SchemaVersion,
		Sequence:      event.Sequence,
		ID:            event.ID,
		Type:          event.Type,
		Namespace:     event.Namespace,
		ActorID:       event.ActorID,
		ActorName:     event.ActorName,
		ActorRole:     event.ActorRole,
		RequestID:     event.RequestID,
		RemoteAddr:    event.RemoteAddr,
		ClaimID:       event.ClaimID,
		FromOwnerID:   event.FromOwnerID,
		FromOwnerName: event.FromOwnerName,
		ToOwnerID:     event.ToOwnerID,
		ToOwnerName:   event.ToOwnerName,
		Reason:        event.Reason,
		Details:       event.Details,
		CreatedAt:     event.CreatedAt.UTC(),
		PreviousHash:  event.PreviousHash,
	}
	payload, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func appendAudit(state *State, event AuditEvent) (AuditEvent, error) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = nowUTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC().Truncate(time.Microsecond)
	}
	event.Sequence = int64(len(state.Audit) + 1)
	event.ID = newID("aud")
	if len(state.Audit) == 0 {
		event.PreviousHash = zeroAuditHash
	} else {
		event.PreviousHash = state.Audit[len(state.Audit)-1].Hash
	}
	hash, err := hashAuditEvent(event)
	if err != nil {
		return AuditEvent{}, err
	}
	event.Hash = hash
	state.Audit = append(state.Audit, event)
	return event, nil
}

func verifyAuditChain(events []AuditEvent) error {
	previous := zeroAuditHash
	for i, event := range events {
		if event.Sequence != int64(i+1) {
			return fmt.Errorf("event %d has sequence %d", i, event.Sequence)
		}
		if event.PreviousHash != previous {
			return fmt.Errorf("event %d previous hash does not match predecessor", event.Sequence)
		}
		want, err := hashAuditEvent(event)
		if err != nil {
			return err
		}
		if event.Hash != want {
			return fmt.Errorf("event %d hash mismatch", event.Sequence)
		}
		previous = event.Hash
	}
	return nil
}

type AuditVerification struct {
	Valid      bool      `json:"valid"`
	EventCount int       `json:"event_count"`
	ChainHead  string    `json:"chain_head"`
	VerifiedAt time.Time `json:"verified_at"`
	Error      string    `json:"error,omitempty"`
}

func VerifyAudit(events []AuditEvent, at time.Time) AuditVerification {
	result := AuditVerification{Valid: true, EventCount: len(events), VerifiedAt: at.UTC()}
	if len(events) == 0 {
		result.ChainHead = zeroAuditHash
	} else {
		result.ChainHead = events[len(events)-1].Hash
	}
	if err := verifyAuditChain(events); err != nil {
		result.Valid = false
		result.Error = err.Error()
	}
	return result
}

type auditManifest struct {
	SchemaVersion int       `json:"schema_version"`
	Format        string    `json:"format"`
	GeneratedAt   time.Time `json:"generated_at"`
	EventCount    int       `json:"event_count"`
	ChainHead     string    `json:"chain_head"`
	ChainValid    bool      `json:"chain_valid"`
	HashAlgorithm string    `json:"hash_algorithm"`
}

func WriteAuditTar(w io.Writer, events []AuditEvent, generatedAt time.Time) (err error) {
	generatedAt = generatedAt.UTC().Truncate(time.Second)
	verification := VerifyAudit(events, generatedAt)
	manifest := auditManifest{
		SchemaVersion: SchemaVersion,
		Format:        "namespaceguard-audit-tar-v1",
		GeneratedAt:   generatedAt,
		EventCount:    len(events),
		ChainHead:     verification.ChainHead,
		ChainValid:    verification.Valid,
		HashAlgorithm: "sha256",
	}
	manifestPayload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestPayload = append(manifestPayload, '\n')

	tw := tar.NewWriter(w)
	defer func() {
		if closeErr := tw.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	readme := "Namespace ownership audit export\n\n" +
		"manifest.json describes the export. Each file under events/ contains one\n" +
		"hash-chained JSON record. index.jsonl lists the same records in order.\n" +
		"Verify every record's sha256 hash and its previous_hash link before import.\n"
	if err := writeTarBytes(tw, "audit/README.txt", []byte(readme), generatedAt); err != nil {
		return err
	}
	if err := writeTarBytes(tw, "audit/manifest.json", manifestPayload, generatedAt); err != nil {
		return err
	}

	var index strings.Builder
	for _, event := range events {
		payload, err := json.MarshalIndent(event, "", "  ")
		if err != nil {
			return err
		}
		payload = append(payload, '\n')
		name := fmt.Sprintf("audit/events/%012d.json", event.Sequence)
		if err := writeTarBytes(tw, name, payload, generatedAt); err != nil {
			return err
		}
		line, err := json.Marshal(event)
		if err != nil {
			return err
		}
		index.Write(line)
		index.WriteByte('\n')
	}
	if err := writeTarBytes(tw, "audit/index.jsonl", []byte(index.String()), generatedAt); err != nil {
		return err
	}
	return nil
}

func writeTarBytes(tw *tar.Writer, name string, payload []byte, modTime time.Time) error {
	header := &tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(payload)),
		ModTime:  modTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(payload)
	return err
}

func newID(prefix string) string {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(random)
}
