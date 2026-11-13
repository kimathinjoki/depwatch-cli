// Package extract hands every dependency file to the matching OSV-SCALIBR extractor and records
// every attempt, so what was read, what could not be read and why is never a guess.
package extract

import (
	"fmt"
	"sort"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/plugin/config"
)

// sourceExtractors are the language extractors depwatch uses on a project folder.
// Secrets, editor and CI metadata, Bazel and binary artifacts are left out on purpose.
func sourceExtractors() ([]filesystem.Extractor, error) {
	maps := []list.InitMap{
		list.CppSource, list.JavaSource, list.JavascriptSource, list.PythonSource, list.GoSource,
		list.DartSource, list.ErlangSource, list.ElixirSource, list.GleamSource, list.HaskellSource,
		list.PHPSource, list.RSource, list.RubySource, list.RustSource, list.JuliaSource,
		list.DotnetSource, list.SwiftSource, list.NimSource, list.OcamlSource, list.LuaSource,
		list.CPANSource,
	}
	return build(maps, nil)
}

// osExtractors read operating system package databases in a filesystem or an image.
func osExtractors() ([]filesystem.Extractor, error) {
	return build([]list.InitMap{list.OS}, nil)
}

// imageExtractors read everything an image can hold: its OS packages and installed language packages.
func imageExtractors() ([]filesystem.Extractor, error) {
	return build([]list.InitMap{list.OS, list.JavascriptArtifact, list.PythonArtifact, list.RubyArtifact,
		list.GoArtifact, list.JavaArtifact, list.RustArtifact, list.DotnetArtifact}, nil)
}

func build(maps []list.InitMap, skip map[string]bool) ([]filesystem.Extractor, error) {
	seen := map[string]bool{}
	var names []string
	byName := map[string][]list.InitFn{}
	for _, m := range maps {
		for name, fns := range m {
			if skip[name] || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
			byName[name] = fns
		}
	}
	sort.Strings(names)
	var out []filesystem.Extractor
	for _, name := range names {
		for _, fn := range byName[name] {
			e, err := fn(&config.PluginConfig{})
			if err != nil {
				return nil, fmt.Errorf("starting extractor %s: %w", name, err)
			}
			out = append(out, e)
		}
	}
	return out, nil
}
