package main

import (
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
)

func runPack(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	src := fs.String("src", "", "source directory to archive")
	name := fs.String("name", "", "package name")
	version := fs.String("version", "", "package version")
	out := fs.String("out", "", "output tar path (default: stdout)")
	prefix := fs.String("prefix", "package", "archive entry prefix ('' to disable)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *src == "" || *name == "" || *version == "" {
		fmt.Fprintln(stderr, "pack: -src, -name and -version are required")
		return 2
	}

	files := map[string]string{}
	err := filepath.WalkDir(*src, func(p string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(*src, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if *prefix != "" {
			rel = strings.TrimSuffix(*prefix, "/") + "/" + rel
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[rel] = string(b)
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "pack: walk source: %v\n", err)
		return 2
	}

	tarBytes, err := BuildTar(files)
	if err != nil {
		fmt.Fprintf(stderr, "pack: %v\n", err)
		return 2
	}
	digest := DigestBytes(tarBytes)

	if *out == "" {
		if _, err := stdout.Write(tarBytes); err != nil {
			fmt.Fprintf(stderr, "pack: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "%s  %s@%s  (%d bytes)\n", digest, *name, *version, len(tarBytes))
		return 0
	}
	if err := os.WriteFile(*out, tarBytes, 0o644); err != nil {
		fmt.Fprintf(stderr, "pack: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "%s  %s@%s  %s  (%d bytes)\n", digest, *name, *version, *out, len(tarBytes))
	return 0
}
