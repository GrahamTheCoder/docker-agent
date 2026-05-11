package taint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/docker/docker-agent/pkg/taint"
)

// Unit: with no defaults and no tags, an unknown tool gets no reads
// or writes — a "we don't know anything about this tool" answer that
// the runtime treats as harmless.
func TestClassifier_UnknownToolEmpty(t *testing.T) {
	t.Parallel()

	c := taint.NewClassifier(taint.ClassifierConfig{})
	r, w := c.Classify("does-not-exist", nil)
	assert.Equal(t, 0, r.Len())
	assert.Equal(t, 0, w.Len())
}

// Unit: per-toolset Reads / Writes declarations apply to every tool
// in that toolset — the YAML's per-toolset taints block is the
// primary contract.
func TestClassifier_ToolsetDeclarationApplies(t *testing.T) {
	t.Parallel()

	c := taint.NewClassifier(taint.ClassifierConfig{
		ToolsetTaints: map[string]taint.ToolsetClasses{
			"github": {
				Tools:  []string{"create_pr", "list_issues"},
				Reads:  taint.NewLabel("secret"),
				Writes: taint.NewLabel("secret"),
			},
		},
	})

	r, w := c.Classify("create_pr", nil)
	assert.Equal(t, []taint.Class{"secret"}, r.Classes())
	assert.Equal(t, []taint.Class{"secret"}, w.Classes())

	r, w = c.Classify("list_issues", nil)
	assert.Equal(t, []taint.Class{"secret"}, r.Classes())
	assert.Equal(t, []taint.Class{"secret"}, w.Classes())
}

// Unit: built-in classifier defaults the seed wiring for fetch /
// shell / write_file / read_file. fetch reads and writes 'public'
// when the URL is http(s); shell and write_file write to
// 'privileged'; read_file reads taints derived from the path tag
// table.
func TestClassifier_BuiltinSeedDefaults(t *testing.T) {
	t.Parallel()

	c := taint.NewClassifier(taint.ClassifierConfig{
		PathTags: []taint.TagRule{
			{Match: "**/.env*", Add: taint.NewLabel("secret")},
		},
		URLTags: []taint.TagRule{
			{Match: "http*://*", Add: taint.NewLabel("public")},
		},
	})

	r, w := c.Classify("fetch", map[string]any{"url": "https://example.com"})
	assert.Equal(t, []taint.Class{"public"}, r.Classes())
	assert.Equal(t, []taint.Class{"public"}, w.Classes())

	_, w = c.Classify("shell", map[string]any{"cmd": "echo hi"})
	assert.Equal(t, []taint.Class{"privileged"}, w.Classes())

	_, w = c.Classify("write_file", map[string]any{"path": "/tmp/out"})
	assert.Equal(t, []taint.Class{"privileged"}, w.Classes())

	r, _ = c.Classify("read_file", map[string]any{"path": "/etc/.env"})
	assert.Equal(t, []taint.Class{"secret"}, r.Classes())
}

// Unit: a per-toolset declaration is conservative: it unions with any
// built-in default rather than overriding it. Otherwise a YAML
// reviewer might add reads:[secret] thinking they tightened the
// boundary, only to silently widen it for a tool the built-in already
// classified.
func TestClassifier_DeclarationIsAdditive(t *testing.T) {
	t.Parallel()

	c := taint.NewClassifier(taint.ClassifierConfig{
		URLTags: []taint.TagRule{
			{Match: "http*://*", Add: taint.NewLabel("public")},
		},
		ToolsetTaints: map[string]taint.ToolsetClasses{
			"fetcher": {
				Tools:  []string{"fetch"},
				Writes: taint.NewLabel("internal"),
			},
		},
	})

	_, w := c.Classify("fetch", map[string]any{"url": "https://example.com"})
	cs := w.Classes()
	assert.Contains(t, cs, taint.Class("public"))
	assert.Contains(t, cs, taint.Class("internal"))
}

// Unit: glob path matching uses **/segment and trailing * the same
// way the existing permissions matcher does.
func TestClassifier_PathGlobMatching(t *testing.T) {
	t.Parallel()

	c := taint.NewClassifier(taint.ClassifierConfig{
		PathTags: []taint.TagRule{
			{Match: "/run/secrets/**", Add: taint.NewLabel("secret")},
			{Match: "**/.env",         Add: taint.NewLabel("secret")},
			{Match: "*.key",           Add: taint.NewLabel("secret")},
		},
	})

	for _, p := range []string{"/run/secrets/foo", "/etc/.env", "tls.key"} {
		r, _ := c.Classify("read_file", map[string]any{"path": p})
		assert.Equal(t, []taint.Class{"secret"}, r.Classes(), "path %s", p)
	}

	r, _ := c.Classify("read_file", map[string]any{"path": "/var/log/syslog"})
	assert.Equal(t, 0, r.Len(), "no rule matches /var/log/syslog")
}
