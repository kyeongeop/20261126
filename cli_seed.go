package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func runSeed(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "path to depguard.json (uses its internal_index)")
	data := fs.String("data", "./data", "store directory to populate")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *config == "" {
		fmt.Fprintln(stderr, "seed: -config is required")
		return 2
	}

	cfg, err := LoadConfig(*config)
	if err != nil {
		fmt.Fprintf(stderr, "seed: %v\n", err)
		return 2
	}
	indexPath := cfg.ResolvePath(cfg.InternalIndex)
	idx, err := LoadInternalIndex(indexPath)
	if err != nil {
		fmt.Fprintf(stderr, "seed: %v\n", err)
		return 2
	}
	store, err := NewStore(*data)
	if err != nil {
		fmt.Fprintf(stderr, "seed: open store: %v\n", err)
		return 2
	}

	names := make([]string, 0, len(idx.Packages))
	for name := range idx.Packages {
		names = append(names, name)
	}
	sort.Strings(names)

	indexDir := filepath.Dir(indexPath)
	published, existing := 0, 0
	for _, name := range names {
		pkg := idx.Packages[name]
		versions := make([]string, 0, len(pkg.Versions))
		for v := range pkg.Versions {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		for _, v := range versions {
			rel := pkg.Versions[v]
			if rel.Archive == "" {
				fmt.Fprintf(stderr, "seed: skip %s@%s: no local archive field\n", name, v)
				continue
			}
			archivePath := rel.Archive
			if !filepath.IsAbs(archivePath) {
				archivePath = filepath.Join(indexDir, archivePath)
			}
			blob, err := os.ReadFile(archivePath)
			if err != nil {
				fmt.Fprintf(stderr, "seed: read archive for %s@%s: %v\n", name, v, err)
				return 2
			}
			stored, err := store.Publish(name, v, blob)
			if errors.Is(err, ErrVersionExists) {
				existing++
				fmt.Fprintf(stdout, "existing %s@%s %s\n", name, v, rel.SHA256)
				continue
			}
			if err != nil {
				fmt.Fprintf(stderr, "seed: publish %s@%s: %v\n", name, v, err)
				return 2
			}
			published++
			fmt.Fprintf(stdout, "seeded %s@%s %s\n", stored.Name, stored.Version, stored.SHA256)
		}
	}
	fmt.Fprintf(stderr, "seed: %d published, %d already present in %s\n", published, existing, *data)
	return 0
}
