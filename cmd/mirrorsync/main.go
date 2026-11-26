// Command mirrorsync verifies and synchronizes offline software-package
// mirror images. It replaces filename-only checks with manifest parsing,
// per-package SHA-256 verification, Ed25519 signature-chain validation,
// resumable transfers and cross-machine review summaries.
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprint(os.Stderr, `mirrorsync - offline mirror image synchronization and verification

Usage:
  mirrorsync keygen       --subject <name> --key <key.json>
  mirrorsync root-cert    --key <root-key.json> --cert <root-cert.json>
  mirrorsync issue-cert   --ca-key <key.json> --ca-cert <cert.json> --subject <name>
                           --key <key.json> --cert <cert.json> [--ca]
  mirrorsync build        --image <dir> --image-id <id> --manifest <manifest.json>
  mirrorsync sign         --key <leaf-key.json> --cert <leaf-cert.json>
                           --chain <ca-cert.json>[,<root-cert.json>]
                           --manifest <manifest.json> --signature <signature.json>
  mirrorsync verify       --image <dir> --manifest <manifest.json>
                           [--signature <signature.json> --root-cert <root-cert.json>]
  mirrorsync sync         --source <url|dir|tar> --dest <dir> --manifest <manifest.json>
                           [--signature <signature.json> --root-cert <root-cert.json>]
                           [--max-retries <n>]
  mirrorsync review       --image <dir> --summary <sync-summary.json>
                           [--checksums <SHA256SUMS.txt>] [--root-cert <root-cert.json>
                           --manifest <manifest.json> --signature <signature.json>]
  mirrorsync serve        --addr <host:port> --image <dir>
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(args)
	case "root-cert":
		err = cmdRootCert(args)
	case "issue-cert":
		err = cmdIssueCert(args)
	case "build":
		err = cmdBuild(args)
	case "sign":
		err = cmdSign(args)
	case "verify":
		err = cmdVerify(args)
	case "sync":
		err = cmdSync(args)
	case "review":
		err = cmdReview(args)
	case "serve":
		err = cmdServe(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
