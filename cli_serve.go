package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", envOr("DEPGUARD_ADDR", "127.0.0.1:8080"), "listen address")
	data := fs.String("data", envOr("DEPGUARD_DATA_DIR", "./data"), "store directory")
	configPath := fs.String("config", "", "optional depguard.json for namespace policy")
	catalogPath := fs.String("public-catalog", "", "public catalog fixture for collision evidence")
	token := fs.String("publish-token", os.Getenv("DEPGUARD_PUBLISH_TOKEN"), "optional publish token")
	upstream := fs.String("upstream", "", "public upstream base for unreserved fallback only")
	allowPublic := fs.Bool("allow-public-fallback", false, "allow unreserved names to use upstream")
	var prefixes, exact stringList
	fs.Var(&prefixes, "prefix", "internal prefix/scope (repeatable)")
	fs.Var(&exact, "exact", "exact reserved internal name (repeatable)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	policy := NamespacePolicy{Fallback: "deny"}
	var catalog *PublicCatalog

	if *configPath != "" {
		cfg, err := LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "serve: %v\n", err)
			return 2
		}
		policy = cfg.Namespace
		if p := cfg.ResolvePath(cfg.PublicCatalog); p != "" {
			catalog, err = LoadPublicCatalog(p)
			if err != nil {
				fmt.Fprintf(stderr, "serve: %v\n", err)
				return 2
			}
		}
	}
	if len(prefixes) > 0 {
		policy.Prefixes = append(policy.Prefixes, []string(prefixes)...)
	}
	if len(exact) > 0 {
		policy.Exact = append(policy.Exact, []string(exact)...)
	}
	if *catalogPath != "" {
		cat, err := LoadPublicCatalog(*catalogPath)
		if err != nil {
			fmt.Fprintf(stderr, "serve: %v\n", err)
			return 2
		}
		catalog = cat
	}

	store, err := NewStore(*data)
	if err != nil {
		fmt.Fprintf(stderr, "serve: open store: %v\n", err)
		return 2
	}
	guard := &Guard{
		Classifier:          NewClassifier(policy),
		Public:              catalog,
		AllowPublicFallback: *allowPublic || *upstream != "",
	}
	srv := NewServer(store, guard)
	srv.PublishToken = *token
	srv.UpstreamBase = *upstream

	fmt.Fprintf(stdout, "depguard registry listening on http://%s (data=%s, prefixes=%v, exact=%v)\n",
		*addr, *data, policy.Prefixes, policy.Exact)
	fmt.Fprintln(stdout, "dependency-confusion protection: reserved internal names are never sent to a public upstream")
	if err := srv.ListenAndServe(*addr); err != nil {
		fmt.Fprintf(stderr, "serve: %v\n", err)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
