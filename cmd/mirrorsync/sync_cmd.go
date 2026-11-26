package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"mirrorsync/internal/source"
	"mirrorsync/internal/sync"
)

func cmdSync(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "source", "dest", "manifest")
	if err != nil {
		return err
	}
	m, manifestBytes, err := loadManifest(flags["manifest"])
	if err != nil {
		return err
	}
	if err := verifySignature(manifestBytes, flags); err != nil {
		return err
	}
	src, inspect, err := buildSource(flags["source"])
	if err != nil {
		return err
	}
	maxRetries, err := optionalInt(flags, "max-retries", sync.DefaultMaxRetries)
	if err != nil {
		return err
	}
	engine := &sync.Engine{
		Src:               src,
		DestDir:           flags["dest"],
		MaxRetries:        maxRetries,
		InspectDuplicates: inspect,
		OnProgress: func(path string, done, total int64) {
			fmt.Fprintf(os.Stderr, "\r  %s: %d/%d bytes", path, done, total)
		},
	}
	result, err := engine.Run(context.Background(), m)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)
	printReport(result.Report)
	if _, err := sync.WriteSummary(flags["dest"], m, result.Report); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s into %s\n",
		sync.SummaryFile, sync.ChecksumsFile, flags["dest"])
	if result.Report.Problems() {
		os.Exit(3)
	}
	return nil
}

// buildSource recognizes http(s) URLs, .tar archive paths and plain
// directories, returning the matching backend plus an optional duplicate
// inspection hook.
func buildSource(ref string) (source.Source, func() ([]source.DuplicateEntry, error), error) {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		src, err := source.NewHTTPSource(ref)
		return src, nil, err
	}
	if strings.HasSuffix(ref, ".tar") {
		src, err := source.NewTarSource(ref)
		if err != nil {
			return nil, nil, err
		}
		return src, func() ([]source.DuplicateEntry, error) {
			return source.TarDuplicates(ref)
		}, nil
	}
	src, err := source.NewDirSource(ref)
	if err != nil {
		return nil, nil, err
	}
	return src, func() ([]source.DuplicateEntry, error) {
		return source.DirDuplicates(ref)
	}, nil
}

func cmdServe(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "addr", "image")
	if err != nil {
		return err
	}
	return source.ListenAndServe(flags["addr"], flags["image"])
}
