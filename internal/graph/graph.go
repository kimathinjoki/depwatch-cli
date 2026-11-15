// Package graph reads the dependency edges each lockfile records, and from them every package's
// shortest paths from the part's root, whether it is direct, and whether it ships to production.
//
// OSV-SCALIBR reports packages but no edges, so watchdep reads edges from the lockfile itself.
// Where a file records no edges, nothing is guessed: the package's path reads "path not recorded".
package graph

import (
	"sort"
	"strings"
)

// MaxPaths is how many of the shortest paths are kept per package; the rest are counted.
const MaxPaths = 5

// pathCountCap bounds the path count so a dense graph cannot overflow it.
const pathCountCap = 1_000_000

// Node is one package at one version.
type Node struct {
	Name    string
	Version string
}

// Key identifies a node.
func (n Node) Key() string { return n.Name + "@" + n.Version }

// Root is one of the part's direct dependencies.
type Root struct {
	Key string
	Dev bool
}

// Graph is what one lockfile records.
type Graph struct {
	Nodes map[string]Node
	Edges map[string][]string
	Roots []Root
	// RootsKnown is false when the file's manifest was missing, so roots were inferred as the
	// packages nothing else depends on, and their scope is not recorded.
	RootsKnown bool
	// EdgesRecorded is false for files that list packages without saying who uses whom.
	EdgesRecorded bool
	// Relations, for files without edges that still say direct or transitive, by node key or name.
	Relations map[string]string
	// DevNames, for files without edges that still say a direct dependency is development only.
	DevNames map[string]bool
	// NormalizeName folds names the way the ecosystem compares them (PyPI ignores case and -_.).
	NormalizeName func(string) string
}

func newGraph() *Graph {
	return &Graph{Nodes: map[string]Node{}, Edges: map[string][]string{}, EdgesRecorded: true, RootsKnown: true}
}

func (g *Graph) addNode(name, version string) string {
	n := Node{Name: name, Version: version}
	g.Nodes[n.Key()] = n
	return n.Key()
}

func (g *Graph) addEdge(from, to string) {
	for _, e := range g.Edges[from] {
		if e == to {
			return
		}
	}
	g.Edges[from] = append(g.Edges[from], to)
}

func (g *Graph) addRoot(key string, dev bool) {
	for i, r := range g.Roots {
		if r.Key == key {
			// a dependency declared in both production and development groups is production
			g.Roots[i].Dev = r.Dev && dev
			return
		}
	}
	g.Roots = append(g.Roots, Root{Key: key, Dev: dev})
}

// inferRoots makes every node no other node depends on a root. Used when the manifest is missing.
func (g *Graph) inferRoots() {
	used := map[string]bool{}
	for _, tos := range g.Edges {
		for _, t := range tos {
			used[t] = true
		}
	}
	keys := sortedNodeKeys(g)
	for _, k := range keys {
		if !used[k] {
			g.addRoot(k, false)
		}
	}
	g.RootsKnown = false
}

// Info is what the graph says about one package.
type Info struct {
	Paths     [][]Node
	MorePaths int
	// Scope is "production" or "development"; empty when the graph cannot say.
	Scope    string
	Relation string // "direct", "transitive", or "" when unknown
	// Reached is false when no root reaches the package (the file lists it but nothing uses it).
	Reached bool
}

// Resolve computes every node's shortest paths, path count, scope and relation.
func (g *Graph) Resolve() map[string]Info {
	out := map[string]Info{}
	if !g.EdgesRecorded {
		return out
	}
	for k := range g.Edges {
		sort.Strings(g.Edges[k])
	}
	roots := append([]Root(nil), g.Roots...)
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].Key < roots[j].Key })

	// Breadth first over paths, keeping the first MaxPaths arrivals at each node: those are its
	// shortest simple paths. Only kept paths are extended, so the work is bounded.
	type item struct{ path []string }
	kept := map[string][][]string{}
	queue := []item{}
	direct := map[string]bool{}
	for _, r := range roots {
		if _, ok := g.Nodes[r.Key]; !ok {
			continue
		}
		direct[r.Key] = true
		queue = append(queue, item{path: []string{r.Key}})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		last := it.path[len(it.path)-1]
		if len(kept[last]) >= MaxPaths {
			continue
		}
		kept[last] = append(kept[last], it.path)
		for _, next := range g.Edges[last] {
			if _, ok := g.Nodes[next]; !ok || contains(it.path, next) {
				continue // unknown node or a cycle
			}
			p := make([]string, len(it.path)+1)
			copy(p, it.path)
			p[len(it.path)] = next
			queue = append(queue, item{path: p})
		}
	}

	// Scope: production when any production root reaches the node.
	prod := g.reach(roots, false)
	any := g.reach(roots, true)
	counts := g.countPaths(roots)

	for k := range g.Nodes {
		info := Info{}
		if any[k] {
			info.Reached = true
			if prod[k] {
				info.Scope = "production"
			} else {
				info.Scope = "development"
			}
			if direct[k] {
				info.Relation = "direct"
			} else {
				info.Relation = "transitive"
			}
		}
		for _, p := range kept[k] {
			steps := make([]Node, len(p))
			for i, key := range p {
				steps[i] = g.Nodes[key]
			}
			info.Paths = append(info.Paths, steps)
		}
		if c := counts[k]; c > len(info.Paths) {
			info.MorePaths = c - len(info.Paths)
		}
		out[k] = info
	}
	return out
}

// reach marks every node reachable from the roots; with includeDev false, from production roots only.
func (g *Graph) reach(roots []Root, includeDev bool) map[string]bool {
	seen := map[string]bool{}
	var stack []string
	for _, r := range roots {
		if r.Dev && !includeDev {
			continue
		}
		if _, ok := g.Nodes[r.Key]; ok && !seen[r.Key] {
			seen[r.Key] = true
			stack = append(stack, r.Key)
		}
	}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, n := range g.Edges[k] {
			if _, ok := g.Nodes[n]; ok && !seen[n] {
				seen[n] = true
				stack = append(stack, n)
			}
		}
	}
	return seen
}

// countPaths counts paths from the roots to each node over the graph with its cycles broken
// (edges back to a node still being visited are dropped), capped at pathCountCap.
func (g *Graph) countPaths(roots []Root) map[string]int {
	// Order nodes so every kept edge goes forward, by depth first search from the roots.
	state := map[string]int{} // 0 unvisited, 1 on stack, 2 done
	var order []string
	forward := map[string][]string{}
	var visit func(k string)
	visit = func(k string) {
		state[k] = 1
		for _, n := range g.Edges[k] {
			if _, ok := g.Nodes[n]; !ok {
				continue
			}
			switch state[n] {
			case 1:
				continue // back edge: a cycle
			case 0:
				visit(n)
			}
			forward[k] = append(forward[k], n)
		}
		state[k] = 2
		order = append(order, k)
	}
	for _, r := range roots {
		if _, ok := g.Nodes[r.Key]; ok && state[r.Key] == 0 {
			visit(r.Key)
		}
	}
	counts := map[string]int{}
	for _, r := range roots {
		if _, ok := g.Nodes[r.Key]; ok {
			counts[r.Key]++
		}
	}
	// order is post-order; reverse it for a topological order of the forward edges.
	for i := len(order) - 1; i >= 0; i-- {
		k := order[i]
		for _, n := range forward[k] {
			counts[n] += counts[k]
			if counts[n] > pathCountCap {
				counts[n] = pathCountCap
			}
		}
	}
	return counts
}

// Lookup finds the node for a package an extractor reported: by exact name and version, or by name
// when the lockfile holds that name only once (extractors and lockfiles sometimes spell a version
// differently, for example with a platform suffix or a leading v).
func (g *Graph) Lookup(name, version string) (string, bool) {
	norm := g.NormalizeName
	if norm == nil {
		norm = func(s string) string { return s }
	}
	want := Node{Name: norm(name), Version: version}.Key()
	var byName []string
	for k, n := range g.Nodes {
		if norm(n.Name) == norm(name) {
			if (Node{Name: norm(n.Name), Version: n.Version}).Key() == want {
				return k, true
			}
			byName = append(byName, k)
		}
	}
	if len(byName) == 1 {
		return byName[0], true
	}
	sort.Strings(byName)
	for _, k := range byName {
		if strings.TrimPrefix(g.Nodes[k].Version, "v") == strings.TrimPrefix(version, "v") {
			return k, true
		}
	}
	return "", false
}

func contains(p []string, k string) bool {
	for _, x := range p {
		if x == k {
			return true
		}
	}
	return false
}

func sortedNodeKeys(g *Graph) []string {
	keys := make([]string, 0, len(g.Nodes))
	for k := range g.Nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// NormalizePyPI folds a Python package name as PEP 503 does.
func NormalizePyPI(s string) string {
	s = strings.ToLower(s)
	r := strings.NewReplacer("_", "-", ".", "-")
	s = r.Replace(s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}
