package store

import (
	"errors"
	"path/filepath"
	"testing"
)

type doc struct {
	Counter int               `json:"counter"`
	Items   map[string]string `json:"items"`
}

func TestUpdateCreatesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	file, err := Open[doc](path)
	if err != nil {
		t.Fatal(err)
	}

	err = file.Update(doc{Items: map[string]string{}}, func(d *doc) error {
		d.Counter = 1
		d.Items["a"] = "one"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open[doc](path)
	if err != nil {
		t.Fatal(err)
	}
	err = reopened.View(func(d *doc) error {
		if d.Counter != 1 || d.Items["a"] != "one" {
			t.Fatalf("unexpected persisted state: %+v", d)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFailedUpdateDoesNotPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	file, err := Open[doc](path)
	if err != nil {
		t.Fatal(err)
	}

	boom := errors.New("boom")
	err = file.Update(doc{}, func(d *doc) error {
		d.Counter = 99
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}

	err = file.View(func(d *doc) error {
		if d.Counter != 0 {
			t.Fatalf("mutation leaked despite failed update: %+v", d)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestViewMissingFileReturnsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	file, err := Open[doc](path)
	if err != nil {
		t.Fatal(err)
	}
	err = file.View(func(d *doc) error {
		if d.Counter != 0 || d.Items != nil {
			t.Fatalf("expected zero value, got %+v", d)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
