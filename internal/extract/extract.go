package extract

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"

	"github.com/kimathinjoki/depwatch-cli/internal/discover"
	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
)

// Found is one package an extractor read, with the file it came from.
type Found struct {
	Pkg    *extractor.Package
	File   string
	Reader string
}

// Result is everything one extraction pass saw.
type Result struct {
	Found        []Found
	FilesRead    []inventory.FileRead
	FilesNotRead []inventory.FileNotRead
	Unsupported  []inventory.Unsupported
	Unpinned     []inventory.Unpinned
	// Ranged are packages declared in unpinned manifests, with their ranges and no version.
	Ranged []inventory.Package
}

// dropped extractors read the project's own description, build outputs or source code, not its
// dependencies, or duplicate another extractor.
var dropped = map[string]bool{
	"javascript/packagejson":   true, // the package itself; unpinned manifests are read by readRanges
	"ruby/gemspec":             true, // the gem itself
	"dart/packageconfig":       true, // installed state under .dart_tool
	"javascript/denotssource":  true, // reads TypeScript source
	"python/ipythoninstall":    true, // reads notebooks
	"erlang/mixlock":           true, // duplicate of elixir/mixlock
	"dotnet/depsjson":          true, // build output
	"dotnet/projectassetsjson": true, // build output
}

// manifestReaders read manifests. Their packages are dropped when a lockfile of the same ecosystem
// was read in the same folder or above it, because the lockfile states the exact versions.
var manifestReaders = map[string]bool{
	"rust/cargotoml":                     true,
	"python/pyprojecttoml":               true,
	"python/setup":                       true,
	"dotnet/csproj":                      true,
	"dotnet/nugetcpm":                    true,
	"dotnet/packagesconfig":              true,
	"julia/projecttoml":                  true,
	"java/gradleversioncatalog":          true,
	"java/gradleverificationmetadataxml": true,
	"javascript/denojson":                true,
}

// Project reads every dependency file in a part's folder.
func Project(ctx context.Context, root string, files []discover.File) (*Result, error) {
	exts, err := sourceExtractors()
	if err != nil {
		return nil, err
	}
	var kept []filesystem.Extractor
	for _, e := range exts {
		if !dropped[e.Name()] {
			kept = append(kept, e)
		}
	}
	res := &Result{}
	run(ctx, scalibrfs.DirFS(root), root, files, kept, res, "")
	dropShadowedManifests(res)
	findUnsupported(files, res)
	findUnpinned(scalibrfs.DirFS(root), files, res)
	sortResult(res)
	return res, nil
}

// OS reads operating system package databases in a filesystem (a fixture, or an unpacked image).
func OS(ctx context.Context, fsys scalibrfs.FS, root string, files []discover.File, image string) (*Result, error) {
	exts, err := osExtractors()
	if err != nil {
		return nil, err
	}
	res := &Result{}
	run(ctx, fsys, root, files, exts, res, image)
	sortResult(res)
	return res, nil
}

// Image reads everything an image holds: OS packages and installed language packages.
func Image(ctx context.Context, fsys scalibrfs.FS, files []discover.File, image string) (*Result, error) {
	exts, err := imageExtractors()
	if err != nil {
		return nil, err
	}
	res := &Result{}
	run(ctx, fsys, "/", files, exts, res, image)
	sortResult(res)
	return res, nil
}

type fileAPI struct {
	path string
	info fs.FileInfo
}

func (f fileAPI) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f fileAPI) Path() string               { return f.path }

func run(ctx context.Context, fsys scalibrfs.FS, root string, files []discover.File, exts []filesystem.Extractor, res *Result, image string) {
	for _, f := range files {
		if f.Info == nil {
			res.FilesNotRead = append(res.FilesNotRead, inventory.FileNotRead{Path: f.Path, Reason: "could not be opened"})
			continue
		}
		api := fileAPI{path: f.Path, info: f.Info}
		for _, e := range exts {
			if !e.FileRequired(api) {
				continue
			}
			pkgs, err := extractOne(ctx, fsys, root, f, e)
			if err != nil {
				res.FilesNotRead = append(res.FilesNotRead, inventory.FileNotRead{
					Path: f.Path, Reason: fmt.Sprintf("%s could not read it: %s", e.Name(), oneLine(err.Error())),
				})
				continue
			}
			eco := EcosystemOfReader(e.Name())
			if len(pkgs) > 0 {
				if s := string(pkgs[0].Ecosystem().Ecosystem); s != "" {
					eco = s
				}
			}
			res.FilesRead = append(res.FilesRead, inventory.FileRead{Path: f.Path, Ecosystem: eco, Reader: e.Name(), Packages: len(pkgs)})
			for _, p := range pkgs {
				res.Found = append(res.Found, Found{Pkg: p, File: f.Path, Reader: e.Name()})
			}
		}
	}
	_ = image
}

func extractOne(ctx context.Context, fsys scalibrfs.FS, root string, f discover.File, e filesystem.Extractor) (pkgs []*extractor.Package, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the reader failed: %v", r)
		}
	}()
	rd, err := fsys.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	inv, err := e.Extract(ctx, &filesystem.ScanInput{FS: fsys, Path: f.Path, Root: root, Info: f.Info, Reader: rd})
	if err != nil {
		return nil, err
	}
	return inv.Packages, nil
}

// lockReaders are readers whose output states exact versions.
func isLockReader(name string) bool {
	return !manifestReaders[name] && name != "java/pomxml" && name != "python/requirements"
}

func dropShadowedManifests(res *Result) {
	// folders (and their ecosystem) where a lock reader produced packages
	locked := map[string]bool{}
	for _, fr := range res.FilesRead {
		if isLockReader(fr.Reader) && fr.Packages > 0 {
			locked[fr.Ecosystem+"|"+path.Dir(fr.Path)] = true
		}
	}
	shadowed := func(eco, file string) bool {
		for dir := path.Dir(file); ; dir = path.Dir(dir) {
			if locked[eco+"|"+dir] {
				return true
			}
			if dir == "." || dir == "/" {
				return false
			}
		}
	}
	var kept []Found
	for _, f := range res.Found {
		if manifestReaders[f.Reader] && shadowed(string(f.Pkg.Ecosystem().Ecosystem), f.File) {
			continue
		}
		kept = append(kept, f)
	}
	res.Found = kept
}

// unsupportedFiles name dependency files of ecosystems SCALIBR does not read.
var unsupportedFiles = map[string]string{
	"build.sbt":         "Scala (sbt)",
	"project.clj":       "Clojure (Leiningen)",
	"deps.edn":          "Clojure (deps.edn)",
	"shard.lock":        "Crystal (Shards)",
	"Cartfile.resolved": "Swift (Carthage)",
	"build.zig.zon":     "Zig",
	"vcpkg.json":        "C and C++ (vcpkg)",
	"rebar.lock":        "Erlang (rebar3)",
	"bun.lockb":         "JavaScript (bun binary lockfile)",
	"elm.json":          "Elm",
}

func findUnsupported(files []discover.File, res *Result) {
	for _, f := range files {
		if eco := unsupportedFiles[path.Base(f.Path)]; eco != "" {
			res.Unsupported = append(res.Unsupported, inventory.Unsupported{Path: f.Path, Ecosystem: eco})
		}
	}
}

// EcosystemOfReader names the ecosystem of a reader that found no packages.
func EcosystemOfReader(name string) string {
	switch {
	case strings.HasPrefix(name, "javascript/"):
		return "npm"
	case strings.HasPrefix(name, "ruby/"):
		return "RubyGems"
	case strings.HasPrefix(name, "python/"):
		return "PyPI"
	case strings.HasPrefix(name, "go/"):
		return "Go"
	case strings.HasPrefix(name, "rust/"):
		return "crates.io"
	case strings.HasPrefix(name, "java/"):
		return "Maven"
	case strings.HasPrefix(name, "dotnet/"):
		return "NuGet"
	case strings.HasPrefix(name, "php/"):
		return "Packagist"
	case strings.HasPrefix(name, "dart/"):
		return "Pub"
	case strings.HasPrefix(name, "elixir/"), strings.HasPrefix(name, "erlang/"):
		return "Hex"
	case name == "swift/podfilelock":
		return "CocoaPods"
	case strings.HasPrefix(name, "swift/"):
		return "SwiftURL"
	case strings.HasPrefix(name, "haskell/"):
		return "Hackage"
	case strings.HasPrefix(name, "r/"):
		return "CRAN"
	case strings.HasPrefix(name, "cpp/"):
		return "ConanCenter"
	case strings.HasPrefix(name, "julia/"):
		return "Julia"
	case name == "os/dpkg":
		return "Debian"
	case name == "os/apk":
		return "Alpine"
	case name == "os/rpm":
		return "Red Hat"
	}
	if i := strings.Index(name, "/"); i > 0 {
		return name[i+1:]
	}
	return name
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func sortResult(res *Result) {
	sort.SliceStable(res.Found, func(i, j int) bool {
		a, b := res.Found[i], res.Found[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Pkg.Name != b.Pkg.Name {
			return a.Pkg.Name < b.Pkg.Name
		}
		return a.Pkg.Version < b.Pkg.Version
	})
	sort.Slice(res.FilesNotRead, func(i, j int) bool { return res.FilesNotRead[i].Path < res.FilesNotRead[j].Path })
	sort.Slice(res.Unsupported, func(i, j int) bool { return res.Unsupported[i].Path < res.Unsupported[j].Path })
	sort.Slice(res.Unpinned, func(i, j int) bool { return res.Unpinned[i].Path < res.Unpinned[j].Path })
}
