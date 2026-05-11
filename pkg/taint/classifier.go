package taint

import (
	"path/filepath"
	"strings"
)

// ClassifierConfig drives the tool classifier. The tag lists are
// walked in order; every matching rule unions into the result.
// ToolsetTaints maps an opaque toolset id to the declarations from
// that toolset's `taints:` block.
//
// EnvTags from the YAML schema are not consumed yet — once shell
// receives env-derived classification (the design's `env` sentinel),
// add an EnvTags field here and a `shell` case below.
type ClassifierConfig struct {
	PathTags []TagRule
	URLTags  []TagRule

	// ToolsetTaints associates a toolset declaration with the tools
	// it owns. The map key is informational (used for logging only);
	// the Tools list is what the classifier actually matches against.
	ToolsetTaints map[string]ToolsetClasses
}

// TagRule pairs a glob pattern with the classes to add when it
// matches. The glob dialect supports `*` (matches a single path
// segment), `?` (a single non-slash char), and `**` (zero or more
// path segments).
type TagRule struct {
	Match string
	Add   Label
}

// ToolsetClasses are the parsed per-toolset declarations.
type ToolsetClasses struct {
	Tools  []string
	Reads  Label
	Writes Label
}

// Classifier returns the effective (reads, writes) for a tool call.
type Classifier struct {
	cfg          ClassifierConfig
	toolToReads  map[string]Label
	toolToWrites map[string]Label
}

// NewClassifier indexes the per-toolset declarations once so
// Classify lookups are O(1) on the toolset side.
func NewClassifier(cfg ClassifierConfig) *Classifier {
	c := &Classifier{
		cfg:          cfg,
		toolToReads:  map[string]Label{},
		toolToWrites: map[string]Label{},
	}
	for _, ts := range cfg.ToolsetTaints {
		for _, name := range ts.Tools {
			c.toolToReads[name] = c.toolToReads[name].Union(ts.Reads)
			c.toolToWrites[name] = c.toolToWrites[name].Union(ts.Writes)
		}
	}
	return c
}

// Classify returns the union of every applicable classifier:
// per-toolset declaration plus built-in seed defaults plus any tag
// rule that matches the tool's arguments. Per-toolset declarations
// are additive (never override) so widening in YAML cannot undo a
// tightening.
func (c *Classifier) Classify(tool string, args map[string]any) (reads, writes Label) {
	reads = c.toolToReads[tool]
	writes = c.toolToWrites[tool]

	switch tool {
	case "fetch":
		if url, ok := stringArg(args, "url", "urls"); ok {
			t := c.matchTags(c.cfg.URLTags, url)
			reads = reads.Union(t)
			writes = writes.Union(t)
		}
	case "shell":
		writes = writes.With(ClassPrivileged)
	case "write_file", "edit_file":
		writes = writes.With(ClassPrivileged)
		if path, ok := stringArg(args, "path"); ok {
			writes = writes.Union(c.matchTags(c.cfg.PathTags, path))
		}
	case "read_file":
		if path, ok := stringArg(args, "path"); ok {
			reads = reads.Union(c.matchTags(c.cfg.PathTags, path))
		}
	}
	return reads, writes
}

// matchTags returns the union of every tag rule whose pattern matches
// value.
func (c *Classifier) matchTags(rules []TagRule, value string) Label {
	var out Label
	for _, r := range rules {
		if globMatch(r.Match, value) {
			out = out.Union(r.Add)
		}
	}
	return out
}

// stringArg returns the first key whose value is a non-empty string.
// fetch can take either a single `url` or a `urls` array; we accept
// both so the schema doesn't have to be normalised before calling in.
func stringArg(args map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		v, ok := args[k]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			return s, true
		}
		if arr, ok := v.([]any); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// globMatch reports whether pattern matches value under a glob
// dialect with `**` as "zero or more path segments". Falls back to
// filepath.Match for the segment-level matching.
func globMatch(pattern, value string) bool {
	pat := strings.Split(pattern, "/")
	val := strings.Split(value, "/")
	return matchSegs(pat, val)
}

// matchSegs walks pattern and value segment by segment. `**` consumes
// zero or more value segments and is the only piece that requires
// recursion; everything else is a single-segment filepath.Match.
func matchSegs(pat, val []string) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case "**":
			// `**` at end matches anything remaining.
			if len(pat) == 1 {
				return true
			}
			rest := pat[1:]
			for i := 0; i <= len(val); i++ {
				if matchSegs(rest, val[i:]) {
					return true
				}
			}
			return false
		default:
			if len(val) == 0 {
				return false
			}
			ok, err := filepath.Match(pat[0], val[0])
			if err != nil || !ok {
				return false
			}
			pat = pat[1:]
			val = val[1:]
		}
	}
	return len(val) == 0
}
