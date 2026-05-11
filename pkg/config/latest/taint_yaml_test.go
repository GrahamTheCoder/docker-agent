package latest_test

import (
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker-agent/pkg/config/latest"
)

// Unit: top-level `taints:` parses into TaintConfig with seed classes,
// the forbid matrix, and tag tables for paths/env/urls.
func TestTaintConfig_TopLevel_YAMLParse(t *testing.T) {
	t.Parallel()

	const src = `
classes:
  secret:
    description: derived from credentials or private data
  public:
    description: derived from external/untrusted content
forbid:
  - when:
      active: [secret]
    tool_writes_to: [public]
  - when:
      active: [public]
    tool_writes_to: [privileged]
tags:
  paths:
    - { match: "**/.env*",   add: [secret] }
    - { match: "/run/secrets/**", add: [secret] }
  env:
    - { match: "*_API_KEY",  add: [secret] }
  urls:
    - { match: "http*://*",  add: [public] }
`

	var cfg latest.TaintConfig
	require.NoError(t, yaml.Unmarshal([]byte(src), &cfg))

	require.Len(t, cfg.Classes, 2)
	assert.Equal(t, "derived from credentials or private data", cfg.Classes["secret"].Description)
	assert.Equal(t, "derived from external/untrusted content", cfg.Classes["public"].Description)

	require.Len(t, cfg.Forbid, 2)
	assert.Equal(t, []string{"secret"}, cfg.Forbid[0].When.Active)
	assert.Equal(t, []string{"public"}, cfg.Forbid[0].ToolWritesTo)
	assert.Equal(t, []string{"public"}, cfg.Forbid[1].When.Active)
	assert.Equal(t, []string{"privileged"}, cfg.Forbid[1].ToolWritesTo)

	require.Len(t, cfg.Tags.Paths, 2)
	assert.Equal(t, "**/.env*", cfg.Tags.Paths[0].Match)
	assert.Equal(t, []string{"secret"}, cfg.Tags.Paths[0].Add)

	require.Len(t, cfg.Tags.Env, 1)
	assert.Equal(t, "*_API_KEY", cfg.Tags.Env[0].Match)

	require.Len(t, cfg.Tags.URLs, 1)
	assert.Equal(t, "http*://*", cfg.Tags.URLs[0].Match)
}

// Unit: a per-toolset `taints:` block declares the read/write classes
// the toolset's tools default to.
func TestToolsetTaints_YAMLParse(t *testing.T) {
	t.Parallel()

	const src = `
type: mcp
ref: docker:github
taints:
  reads:  [secret]
  writes: [secret]
`

	var ts latest.Toolset
	require.NoError(t, yaml.Unmarshal([]byte(src), &ts))

	require.NotNil(t, ts.Taints)
	assert.Equal(t, []string{"secret"}, ts.Taints.Reads)
	assert.Equal(t, []string{"secret"}, ts.Taints.Writes)
}

// Unit: a forbid rule that names an unknown class is rejected at parse
// time so a YAML reviewer catches the typo without running the agent.
func TestTaintConfig_ForbidRefsUnknownClass(t *testing.T) {
	t.Parallel()

	const src = `
classes:
  secret: { description: "" }
forbid:
  - when: { active: [secret] }
    tool_writes_to: [unknown_class]
`

	var cfg latest.TaintConfig
	err := yaml.Unmarshal([]byte(src), &cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_class")
}

// Unit: per-toolset taints that reference an unknown class are rejected
// at parse time.
func TestToolsetTaints_RefsUnknownClass_NotEnforcedYet(t *testing.T) {
	t.Parallel()

	// Toolset-level taints are validated against the top-level class set
	// only when the full Config is parsed, not in isolation. This test
	// pins that the per-toolset parse alone does not reject unknown
	// classes — the cross-validation lives on Config.validate().
	const src = `
type: mcp
ref: docker:github
taints:
  reads:  [made_up]
`

	var ts latest.Toolset
	require.NoError(t, yaml.Unmarshal([]byte(src), &ts))
	require.NotNil(t, ts.Taints)
	assert.Equal(t, []string{"made_up"}, ts.Taints.Reads)
}

// Unit: when the full Config is parsed, a toolset taint that references
// a class not declared at the top level is rejected.
func TestConfig_ToolsetTaintRefsUnknownClass(t *testing.T) {
	t.Parallel()

	const src = `
version: "2"
taints:
  classes:
    secret: { description: "" }
agents:
  root:
    model: openai/gpt-4o-mini
    toolsets:
      - type: shell
        taints:
          reads: [made_up]
`

	var cfg latest.Config
	err := yaml.Unmarshal([]byte(src), &cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "made_up")
}
