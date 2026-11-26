// Command depguard runs pre-install dependency-confusion checks and the
// protected internal package registry.
package main

import (
	"os"
)

func main() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}
