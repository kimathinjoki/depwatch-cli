// Package config reads watchdep.yml: what no lockfile states about a part.
//
// The shape is schema/watchdep.schema.json. Unknown keys and wrong types stop the run with an error
// that names the line, because a misspelt key silently ignored would hide a runtime from the check.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the name of the file at the root of a part.
const FileName = "watchdep.yml"

// Version is a version written as a string or a number; the literal text is kept ("3.10" stays "3.10").
type Version string

// UnmarshalYAML keeps the literal scalar text.
func (v *Version) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!bool" || n.Tag == "!!null" {
		return fmt.Errorf("line %d: a version must be a string or a number", n.Line)
	}
	if strings.TrimSpace(n.Value) == "" {
		return fmt.Errorf("line %d: a version must not be empty", n.Line)
	}
	*v = Version(n.Value)
	return nil
}

// Database is a database engine and version.
type Database struct {
	Engine  string  `yaml:"engine"`
	Version Version `yaml:"version"`
}

// Hosting is a runtime the hosting platform provides.
type Hosting struct {
	Name    string  `yaml:"name"`
	Version Version `yaml:"version"`
}

// Config is the content of watchdep.yml.
type Config struct {
	Version          int                `yaml:"version"`
	ProductionBranch string             `yaml:"production_branch"`
	Runtimes         map[string]Version `yaml:"runtimes"`
	Databases        []Database         `yaml:"databases"`
	Hosting          []Hosting          `yaml:"hosting"`
	Images           []string           `yaml:"images"`
	Ignore           []string           `yaml:"ignore"`

	// Path is where the file was read from, relative to the part's root; empty when there is none.
	Path string `yaml:"-"`
}

// Error is a problem with watchdep.yml. The CLI exits with the usage code on it.
type Error struct {
	Path string
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Path, e.Msg) }

// Load reads watchdep.yml from the root folder. A missing file is an empty config, not an error.
func Load(root string) (*Config, error) {
	p := filepath.Join(root, FileName)
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, &Error{Path: FileName, Msg: err.Error()}
	}
	defer f.Close()
	c, err := Parse(f, FileName)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Parse reads watchdep.yml content. name is used in error messages.
func Parse(r io.Reader, name string) (*Config, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, &Error{Path: name, Msg: err.Error()}
	}
	c := &Config{Path: name}
	if len(bytes.TrimSpace(raw)) == 0 {
		return c, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, &Error{Path: name, Msg: cleanYAMLError(err)}
	}
	if err := c.check(); err != nil {
		return nil, &Error{Path: name, Msg: err.Error()}
	}
	return c, nil
}

func (c *Config) check() error {
	if c.Version != 0 && c.Version != 1 {
		return fmt.Errorf("version %d is not supported; this CLI reads version 1", c.Version)
	}
	for i, d := range c.Databases {
		if strings.TrimSpace(d.Engine) == "" || d.Version == "" {
			return fmt.Errorf("databases[%d] needs both engine and version", i)
		}
	}
	for i, h := range c.Hosting {
		if strings.TrimSpace(h.Name) == "" || h.Version == "" {
			return fmt.Errorf("hosting[%d] needs both name and version", i)
		}
	}
	for i, img := range c.Images {
		if strings.TrimSpace(img) == "" {
			return fmt.Errorf("images[%d] is empty", i)
		}
	}
	for i, ig := range c.Ignore {
		if strings.TrimSpace(ig) == "" {
			return fmt.Errorf("ignore[%d] is empty", i)
		}
		if filepath.IsAbs(ig) || strings.HasPrefix(filepath.Clean(ig), "..") {
			return fmt.Errorf("ignore[%d] %q must be a folder inside the part", i, ig)
		}
	}
	return nil
}

// IgnoredDirs returns the ignore list as clean slash paths relative to the part's root.
func (c *Config) IgnoredDirs() []string {
	out := make([]string, 0, len(c.Ignore))
	for _, ig := range c.Ignore {
		out = append(out, strings.TrimSuffix(filepath.ToSlash(filepath.Clean(ig)), "/"))
	}
	return out
}

func cleanYAMLError(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "yaml: ")
	msg = strings.ReplaceAll(msg, "unmarshal errors:\n  ", "")
	msg = strings.ReplaceAll(msg, "\n  ", "; ")
	msg = strings.ReplaceAll(msg, " in type config.Config", "")
	msg = strings.ReplaceAll(msg, " in type config.Database", "")
	msg = strings.ReplaceAll(msg, " in type config.Hosting", "")
	msg = strings.ReplaceAll(msg, "field ", "unknown key ")
	msg = strings.ReplaceAll(msg, " not found", "")
	return msg
}
