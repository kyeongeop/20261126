package gateway_test

import (
	"io"
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Expected handshake rejections make net/http log TLS errors through the
	// standard logger; silence them so "go test" output stays actionable.
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}
