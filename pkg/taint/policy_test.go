package taint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker-agent/pkg/taint"
)

// Unit: an empty policy permits everything.
func TestPolicy_NoRulesAllowsEverything(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy(nil)
	d := p.Decide(taint.NewLabel("secret"), taint.NewLabel("public"))

	assert.True(t, d.Allowed)
	assert.Empty(t, d.Reason)
	assert.Empty(t, d.Triggered)
}

// Unit: the canonical "secret active forbids public sink" rule fires
// when both the active set and the writes set match.
func TestPolicy_SecretActiveDeniesPublicSink(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("public")},
	})

	d := p.Decide(taint.NewLabel("secret"), taint.NewLabel("public"))
	require.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "secret")
	assert.Contains(t, d.Reason, "public")
	assert.Len(t, d.Triggered, 1)
}

// Unit: a rule fires only when ALL its `when.active` classes are
// active. A rule conditioned on {secret, internal} does not fire when
// only {secret} is active.
func TestPolicy_RuleNeedsAllActiveClasses(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret", "internal"), Writes: taint.NewLabel("public")},
	})

	d := p.Decide(taint.NewLabel("secret"), taint.NewLabel("public"))
	assert.True(t, d.Allowed, "rule should not fire without 'internal' active")
}

// Unit: a rule fires when ANY of its `tool_writes_to` classes appears
// in the tool's declared writes (matrix is OR over write classes).
func TestPolicy_RuleFiresOnAnyWriteOverlap(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("public", "external")},
	})

	d := p.Decide(taint.NewLabel("secret"), taint.NewLabel("external"))
	require.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "external")
}

// Unit: multiple rules are OR'd. If any fires, the call is denied.
func TestPolicy_MultipleRulesORed(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("public")},
		{When: taint.NewLabel("public"), Writes: taint.NewLabel("privileged")},
	})

	// Reverse direction: 'public' active, writing to 'privileged'.
	d := p.Decide(taint.NewLabel("public"), taint.NewLabel("privileged"))
	require.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "public")
	assert.Contains(t, d.Reason, "privileged")
}

// Unit: when several rules fire, Decide names them all in Triggered
// so audit consumers can render the full reason.
func TestPolicy_AllFiringRulesReportedInTriggered(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("public")},
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("external")},
	})

	d := p.Decide(taint.NewLabel("secret"), taint.NewLabel("public", "external"))
	require.False(t, d.Allowed)
	assert.Equal(t, []int{0, 1}, d.Triggered)
}

// Unit: a tool that writes to nothing is always allowed regardless of
// the active set (read-only tool semantics).
func TestPolicy_PureReadAllowed(t *testing.T) {
	t.Parallel()

	p := taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("public")},
	})
	d := p.Decide(taint.NewLabel("secret"), taint.NewLabel())
	assert.True(t, d.Allowed)
}
