// Package inventory holds the model of everything a part contains, and its JSON contract.
//
// The JSON shape is versioned by SchemaVersion and described by schema/inventory.schema.json.
// The server ingests exactly this shape, so any change to a field here must bump SchemaVersion
// and the committed schema together (a test enforces it).
package inventory

import (
	"encoding/json"
	"fmt"
	"io"
)

// SchemaVersion is the version of the inventory JSON contract.
const SchemaVersion = "1"

// Scope values.
const (
	ScopeProduction  = "production"
	ScopeDevelopment = "development"
)

// Relation values: how a package relates to the part.
const (
	RelationDirect     = "direct"
	RelationTransitive = "transitive"
	RelationUnknown    = "unknown"
)

// Runtime kinds.
const (
	KindRuntime  = "runtime"
	KindDatabase = "database"
	KindHosting  = "hosting"
)

// Inventory is what one part contains on one commit, and how it was taken.
type Inventory struct {
	SchemaVersion string `json:"schema_version"`
	CLIVersion    string `json:"cli_version"`
	TakenAt       string `json:"taken_at"`
	TakenBy       string `json:"taken_by"`
	Part          Part   `json:"part"`

	Packages   []Package   `json:"packages"`
	OSPackages []OSPackage `json:"os_packages"`
	Runtimes   []Runtime   `json:"runtimes"`
	Images     []Image     `json:"images"`

	FilesRead    []FileRead    `json:"files_read"`
	FilesNotRead []FileNotRead `json:"files_not_read"`
	Unsupported  []Unsupported `json:"unsupported"`
	Unpinned     []Unpinned    `json:"unpinned"`
	Conflicts    []Conflict    `json:"conflicts"`
}

// Part is the folder the inventory was taken of.
type Part struct {
	Root             string `json:"root"`
	Commit           string `json:"commit"`
	Branch           string `json:"branch"`
	ProductionBranch string `json:"production_branch"`
}

// Step is one package on a dependency path.
type Step struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Package is one language package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// Version is the exact version from a lockfile; empty when only a range is known.
	Version string `json:"version"`
	// Range is the declared range when no lockfile pins the package.
	Range string `json:"range"`
	PURL  string `json:"purl"`
	// Scope is production or development.
	Scope string `json:"scope"`
	// ScopeRecorded is false when the file does not say, in which case Scope is production (louder).
	ScopeRecorded bool   `json:"scope_recorded"`
	Relation      string `json:"relation"`
	SourceFile    string `json:"source_file"`
	// Paths are the shortest dependency paths from the part's root to this package, the package last.
	Paths [][]Step `json:"paths"`
	// MorePaths counts the paths beyond those kept.
	MorePaths int `json:"more_paths"`
	// PathsRecorded is false when the file records no dependency edges.
	PathsRecorded bool `json:"paths_recorded"`
}

// OSPackage is one operating system package from an image or a filesystem.
type OSPackage struct {
	Distribution  string `json:"distribution"`
	Release       string `json:"release"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
	PURL          string `json:"purl"`
	SourceFile    string `json:"source_file"`
	Image         string `json:"image"`
}

// Runtime is a runtime, database or hosting runtime the part runs on.
type Runtime struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	SourceFile string `json:"source_file"`
}

// Image is a container image the CLI was asked to read.
type Image struct {
	Reference string `json:"reference"`
	Read      bool   `json:"read"`
	Reason    string `json:"reason"`
	Packages  int    `json:"packages"`
}

// FileRead is a dependency file that was read.
type FileRead struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
	Reader    string `json:"reader"`
	Packages  int    `json:"packages"`
}

// FileNotRead is a dependency file that was found and could not be read.
type FileNotRead struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Unsupported is a file of an ecosystem the CLI does not read.
type Unsupported struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
}

// Unpinned is a manifest with no lockfile beside it; its packages carry ranges only.
type Unpinned struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
}

// Conflict is one runtime whose version differs between sources.
type Conflict struct {
	Name     string    `json:"name"`
	Runtimes []Runtime `json:"runtimes"`
}

// Complete reports whether the CLI looked at everything it found.
// An incomplete inventory is never read as clean.
func (inv *Inventory) Complete() bool {
	if len(inv.FilesNotRead) > 0 || len(inv.Unsupported) > 0 {
		return false
	}
	for _, img := range inv.Images {
		if !img.Read {
			return false
		}
	}
	return true
}

// NothingFound reports that the folder held nothing to check: no dependency file was read or found
// unreadable, no ecosystem was found unsupported, no manifest was found, and no image or root
// filesystem was named. That is never a clean result: the code may not be there at all.
func (inv *Inventory) NothingFound() bool {
	return len(inv.FilesRead) == 0 && len(inv.FilesNotRead) == 0 && len(inv.Unsupported) == 0 &&
		len(inv.Unpinned) == 0 && len(inv.Images) == 0 && len(inv.Packages) == 0 && len(inv.OSPackages) == 0
}

// Normalize replaces nil slices with empty ones so the JSON never carries null lists.
func (inv *Inventory) Normalize() {
	if inv.Packages == nil {
		inv.Packages = []Package{}
	}
	for i := range inv.Packages {
		if inv.Packages[i].Paths == nil {
			inv.Packages[i].Paths = [][]Step{}
		}
	}
	if inv.OSPackages == nil {
		inv.OSPackages = []OSPackage{}
	}
	if inv.Runtimes == nil {
		inv.Runtimes = []Runtime{}
	}
	if inv.Images == nil {
		inv.Images = []Image{}
	}
	if inv.FilesRead == nil {
		inv.FilesRead = []FileRead{}
	}
	if inv.FilesNotRead == nil {
		inv.FilesNotRead = []FileNotRead{}
	}
	if inv.Unsupported == nil {
		inv.Unsupported = []Unsupported{}
	}
	if inv.Unpinned == nil {
		inv.Unpinned = []Unpinned{}
	}
	if inv.Conflicts == nil {
		inv.Conflicts = []Conflict{}
	}
}

// Write writes the inventory as indented JSON.
func (inv *Inventory) Write(w io.Writer) error {
	inv.Normalize()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(inv)
}

// Read reads an inventory, refusing unknown fields and other schema versions.
func Read(r io.Reader) (*Inventory, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var inv Inventory
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("reading inventory: %w", err)
	}
	if inv.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("inventory schema version %q, this CLI reads %q", inv.SchemaVersion, SchemaVersion)
	}
	inv.Normalize()
	return &inv, nil
}
