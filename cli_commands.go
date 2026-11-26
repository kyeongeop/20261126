package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		// Bare invocation boots the protected registry with defaults,
		// matching the internal-repository service convention.
		fmt.Fprintln(stderr, "no command given; starting `serve` with defaults (see `depguard help` for check/fix/pack).")
		return runServe(nil, stdout, stderr)
	}
	switch args[0] {
	case "check", "preinstall", "scan":
		return runCheck(args[1:], stdout, stderr)
	case "fix":
		return runFix(args[1:], stdout, stderr)
	case "seed":
		return runSeed(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "pack":
		return runPack(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `depguard — dependency-confusion configuration guard

Usage:
  depguard            (no command) start the registry via the serve defaults
  depguard check  -config depguard.json [-json] [--strict]   (alias: preinstall, scan)
  depguard fix    -config depguard.json [-out fixed-lock.json]
  depguard seed   -config depguard.json -data ./data   # publish fixture tarballs
  depguard serve  [-addr 127.0.0.1:8080] [-data ./data] [-config depguard.json]
                  [-prefix @acme/]... [-exact legacy-name]...
                  [-public-catalog catalog.json] [-publish-token t]
                  [-upstream http://127.0.0.1:9000] [-allow-public-fallback]
  depguard pack   -src ./pkg-dir -name @acme/core -version 1.0.0 [-out p.tar]

Rules:
  DG101 undeclared-mirror          未声明镜像
  DG102 same-name-public-package   同名公共包
  DG103 internal-prefix-fallback   内部前缀回退
  DG104 lockfile-source-override   锁文件覆盖

Exit codes (check): 0 = pass, 1 = blocking findings, 2 = usage/runtime error.
`)
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "path to depguard.json")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	strict := fs.Bool("strict", false, "treat warnings as blocking")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *config == "" {
		fmt.Fprintln(stderr, "check: -config is required")
		return 2
	}

	report, err := CheckConfigFile(context.Background(), *config)
	if err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return 2
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "encode report: %v\n", err)
			return 2
		}
	} else {
		_ = WriteTextReport(stdout, report)
	}

	if report.Summary.Errors > 0 || (*strict && report.Summary.Warnings > 0) {
		return 1
	}
	return 0
}

func runFix(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "path to depguard.json")
	out := fs.String("out", "", "output lockfile path (default: stdout)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *config == "" {
		fmt.Fprintln(stderr, "fix: -config is required")
		return 2
	}

	cfg, err := LoadConfig(*config)
	if err != nil {
		fmt.Fprintf(stderr, "fix: %v\n", err)
		return 2
	}
	report, err := CheckConfigFile(context.Background(), *config)
	if err != nil {
		fmt.Fprintf(stderr, "fix: %v\n", err)
		return 2
	}
	lockPath := cfg.ResolvePath(cfg.Lockfile)
	data, err := os.ReadFile(lockPath)
	if err != nil {
		fmt.Fprintf(stderr, "fix: read lockfile: %v\n", err)
		return 2
	}
	fixed, changed, err := RewriteLockfile(data, report)
	if err != nil {
		fmt.Fprintf(stderr, "fix: %v\n", err)
		return 2
	}
	if *out == "" {
		_, _ = stdout.Write(fixed)
	} else {
		if err := os.WriteFile(*out, fixed, 0o644); err != nil {
			fmt.Fprintf(stderr, "fix: write: %v\n", err)
			return 2
		}
	}
	fmt.Fprintf(stderr, "fix: rewrote %d lockfile entr(ies) using %d replacement candidate(s)\n", changed, len(report.Replacements))
	return 0
}
