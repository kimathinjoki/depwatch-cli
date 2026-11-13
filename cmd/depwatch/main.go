// Command depwatch takes the inventory of a project and checks it for known vulnerabilities and
// compromised releases.
package main

import (
	"os"

	"github.com/kimathinjoki/depwatch-cli/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
