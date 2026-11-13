// Package version holds the build's version, commit and date, stamped at build time with
// -ldflags "-X github.com/kimathinjoki/depwatch-cli/internal/version.Version=...".
package version

// Stamped at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// UserAgent names the CLI to the sources it calls. It carries no personal detail.
func UserAgent() string {
	return "depwatch-cli/" + Version + " (+https://github.com/kimathinjoki/depwatch-cli)"
}
