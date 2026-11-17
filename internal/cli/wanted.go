package cli

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/watchdep-cli/internal/config"
	"github.com/kimathinjoki/watchdep-cli/internal/discover"
	"github.com/kimathinjoki/watchdep-cli/internal/extract"
	"github.com/kimathinjoki/watchdep-cli/internal/image"
)

func newWanted(env *Env) *cobra.Command {
	var configPath string
	c := &cobra.Command{
		Use:   "wanted [--config watchdep.yml] < listing",
		Short: "Say which files of a repository listing watchdep would read",
		Long: `Read a repository's file listing on standard input, one file per line as "<path> <size>" (size
optional), and answer which of those files watchdep inventory would read: dependency files, the
manifests beside lockfiles, version files, Dockerfiles, watchdep.yml and the files of unsupported
ecosystems. Never a source file.

The watchdep server uses it to fetch exactly the files the CLI reads, so the GitHub route and the CLI
route give the same inventory. With --config, folders the given watchdep.yml ignores are left out.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			var ignore []string
			if configPath != "" {
				f, err := os.Open(configPath)
				if err != nil {
					return &usageError{msg: err.Error()}
				}
				cfg, err := config.Parse(f, config.FileName)
				f.Close()
				if err != nil {
					return err
				}
				ignore = cfg.IgnoredDirs()
			}
			var out []string
			sc := bufio.NewScanner(c.InOrStdin())
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				p, size := line, int64(0)
				if i := strings.LastIndex(line, " "); i > 0 {
					if n, err := strconv.ParseInt(line[i+1:], 10, 64); err == nil {
						p, size = line[:i], n
					}
				}
				p = strings.TrimPrefix(path.Clean("/"+p), "/")
				if discover.Skipped(p, ignore) {
					continue
				}
				base := path.Base(p)
				if base == config.FileName || config.IsRuntimeFile(p) || image.IsDockerfile(p) || extract.Wants(p, size) {
					out = append(out, p)
				}
			}
			if err := sc.Err(); err != nil {
				return err
			}
			sort.Strings(out)
			if out == nil {
				out = []string{}
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, map[string]any{"paths": out})
			}
			for _, p := range out {
				fmt.Fprintln(env.Stdout, p)
			}
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "a watchdep.yml whose ignore list applies")
	return c
}
