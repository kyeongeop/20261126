// Package audit provides an append-only, hash-chained audit log.
// Every authorization decision (allow or deny) is recorded; the
// sha256 chain makes retroactive tampering detectable.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Decision outcomes recorded in the log.
const (
	Allow = "allow"
	Deny  = "deny"
)

// Event is one audit record.
type Event struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor"` // token ID, "admin" or "anonymous"
	Action    string    `json:"action"`
	Namespace string    `json:"namespace,omitempty"`
	Package   string    `json:"package,omitempty"`
	Version   string    `json:"version,omitempty"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

func (e Event) digest() string {
	body, _ := json.Marshal(struct {
		Seq       uint64    `json:"seq"`
		Time      time.Time `json:"time"`
		Actor     string    `json:"actor"`
		Action    string    `json:"action"`
		Namespace string    `json:"namespace,omitempty"`
		Package   string    `json:"package,omitempty"`
		Version   string    `json:"version,omitempty"`
		Decision  string    `json:"decision"`
		Reason    string    `json:"reason"`
		PrevHash  string    `json:"prev_hash"`
	}{e.Seq, e.Time, e.Actor, e.Action, e.Namespace, e.Package, e.Version, e.Decision, e.Reason, e.PrevHash})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Logger appends events to a JSONL file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	seq  uint64
	prev string
}

// Open opens (or creates) the audit log, continuing the hash chain.
func Open(path string) (*Logger, error) {
	l := &Logger{prev: "genesis"}
	if _, err := os.Stat(path); err == nil {
		last, err := lastEvent(path)
		if err != nil {
			return nil, fmt.Errorf("audit log corrupt: %w", err)
		}
		if last != nil {
			l.seq = last.Seq
			l.prev = last.Hash
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.file = f
	return l, nil
}

// Log records one event. It is safe for concurrent use.
func (l *Logger) Log(actor, action, namespace, pkg, version, decision, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := Event{
		Seq:       l.seq,
		Time:      time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Namespace: namespace,
		Package:   pkg,
		Version:   version,
		Decision:  decision,
		Reason:    reason,
		PrevHash:  l.prev,
	}
	e.Hash = e.digest()
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, err := l.file.Write(append(line, '\n')); err == nil {
		l.prev = e.Hash
	} else {
		l.seq--
	}
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func lastEvent(path string) (*Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var last *Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, err
		}
		last = &e
	}
	return last, sc.Err()
}

// Verify checks the integrity of the whole hash chain.
func Verify(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	prev := "genesis"
	var seq uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("line %d: %w", seq+1, err)
		}
		seq++
		if e.Seq != seq {
			return fmt.Errorf("line %d: sequence gap (got %d)", seq, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("line %d: prev_hash mismatch", seq)
		}
		if e.Hash != e.digest() {
			return fmt.Errorf("line %d: hash mismatch", seq)
		}
		prev = e.Hash
	}
	return sc.Err()
}
