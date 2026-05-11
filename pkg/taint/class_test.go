package taint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker-agent/pkg/taint"
)

// Unit: Label is a set with deterministic ordering and standard set ops.
func TestLabel_AddContainsLen(t *testing.T) {
	t.Parallel()

	var l taint.Label
	assert.Equal(t, 0, l.Len())
	assert.False(t, l.Contains("secret"))

	l = l.With("secret")
	assert.True(t, l.Contains("secret"))
	assert.Equal(t, 1, l.Len())

	// Idempotent: adding the same class twice does not grow the set.
	l = l.With("secret")
	assert.Equal(t, 1, l.Len())

	l = l.With("public")
	assert.Equal(t, 2, l.Len())
}

// Unit: Label.Classes returns class names in lexicographic order so
// rendered messages and audit logs are deterministic.
func TestLabel_ClassesIsSorted(t *testing.T) {
	t.Parallel()

	l := taint.NewLabel("public", "secret", "alpha")
	assert.Equal(t, []taint.Class{"alpha", "public", "secret"}, l.Classes())
}

// Unit: Union is the standard set union; the inputs are not mutated.
func TestLabel_Union(t *testing.T) {
	t.Parallel()

	a := taint.NewLabel("secret")
	b := taint.NewLabel("public", "secret")

	got := a.Union(b)
	assert.Equal(t, []taint.Class{"public", "secret"}, got.Classes())
	assert.Equal(t, []taint.Class{"secret"}, a.Classes(), "a not mutated")
	assert.Equal(t, []taint.Class{"public", "secret"}, b.Classes(), "b not mutated")
}

// Unit: Intersect returns the classes present in both labels.
func TestLabel_Intersect(t *testing.T) {
	t.Parallel()

	a := taint.NewLabel("secret", "internal")
	b := taint.NewLabel("public", "secret")

	got := a.Intersect(b)
	assert.Equal(t, []taint.Class{"secret"}, got.Classes())
}

// Unit: Subset returns true iff every class in the receiver is present
// in the other label.
func TestLabel_Subset(t *testing.T) {
	t.Parallel()

	require.True(t, taint.NewLabel().Subset(taint.NewLabel("secret")))
	require.True(t, taint.NewLabel("secret").Subset(taint.NewLabel("secret", "public")))
	require.False(t, taint.NewLabel("secret", "public").Subset(taint.NewLabel("secret")))
}
