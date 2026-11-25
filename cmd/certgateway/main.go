// Command certgateway runs the local client-certificate self-registration
// service and mTLS gateway, creates invitations, or executes an in-process
// end-to-end demo.
//
//	go run ./cmd/certgateway serve
//	go run ./cmd/certgateway invite -service billing.internal -purpose api
//	go run ./cmd/certgateway demo
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "invite":
		err = runInvite(os.Args[2:])
	case "demo":
		err = runDemo()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `certgateway — one-time invitation client-certificate registration

Usage:
  certgateway <command> [flags]

Commands:
  serve   Start the enrollment HTTP API and the mTLS TLS gateway
  invite  Create a one-time invitation through the admin API
  demo    Run an in-process end-to-end demonstration
`)
}
