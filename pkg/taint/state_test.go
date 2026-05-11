package taint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker-agent/pkg/taint"
)

func newTestPolicy() taint.Policy {
	return taint.NewPolicy([]taint.ForbidRule{
		{When: taint.NewLabel("secret"), Writes: taint.NewLabel("public")},
		{When: taint.NewLabel("public"), Writes: taint.NewLabel("privileged")},
	})
}

// Unit: a fresh state has an empty active set and decides allow.
func TestState_FreshAllowsEverything(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	assert.Equal(t, 0, s.Active().Len())

	d := s.Decide(taint.NewLabel(), taint.NewLabel("public"))
	assert.True(t, d.Allowed)
}

// Unit: Propagate stamps the resulting message label as the union of
// the tool's read set and the active set ("sticky" propagation), and
// returns it.
func TestState_PropagateIsStickyAndReturnsLabel(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())

	// First call introduces 'secret' (reads from an .env file).
	got := s.Propagate("msg-1", taint.NewLabel("secret"))
	assert.Equal(t, []taint.Class{"secret"}, got.Classes())
	assert.Equal(t, []taint.Class{"secret"}, s.Active().Classes())

	// Second call reads nothing new but still inherits the active set.
	got = s.Propagate("msg-2", taint.NewLabel())
	assert.Equal(t, []taint.Class{"secret"}, got.Classes())
}

// Unit: after a 'secret'-introducing call, an attempt to write to
// 'public' is denied and the deny names the introducer message id.
func TestState_DenyNamesIntroducer(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	s.Propagate("intro-msg", taint.NewLabel("secret"))

	d := s.Decide(s.Active(), taint.NewLabel("public"))
	require.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "secret")
	assert.Contains(t, d.Reason, "public")

	intros := s.Introducers("secret")
	assert.Equal(t, []string{"intro-msg"}, intros)
}

// Unit: clearing the introducer of a class removes that class from
// the active set; downstream messages whose taint was derived solely
// from the cleared introducer also clear (transitive closure).
func TestState_ClearIntroducerRemovesClassAndDownstream(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	s.Propagate("intro", taint.NewLabel("secret")) // introduces secret
	s.Propagate("derived", taint.NewLabel())       // inherits secret only via 'intro'

	require.Equal(t, []taint.Class{"secret"}, s.Active().Classes())

	cleared := s.Clear("intro")

	assert.Equal(t, 0, s.Active().Len(),
		"clearing the introducer should drain the active set")
	assert.ElementsMatch(t, []string{"intro", "derived"}, cleared,
		"transitively cleared messages are reported")
}

// Unit: when a class has multiple introducers, clearing one does not
// remove the class — the others still keep it active.
func TestState_ClearOneOfManyIntroducersKeepsClass(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	s.Propagate("intro-a", taint.NewLabel("secret"))
	s.Propagate("intro-b", taint.NewLabel("secret"))

	cleared := s.Clear("intro-a")

	assert.Equal(t, []taint.Class{"secret"}, s.Active().Classes(),
		"intro-b still introduces secret")
	assert.Equal(t, []string{"intro-a"}, cleared)
}

// Unit: a downstream inheritor of TWO independent introducers must
// NOT clear when only one is cleared. This is the spec's "downstream
// that derived its taint solely from the cleared introducer also
// clears" property — solely is the operative word.
func TestState_ClearKeepsInheritorWithSurvivingSource(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	s.Propagate("intro-secret", taint.NewLabel("secret"))
	s.Propagate("intro-public", taint.NewLabel("public"))
	s.Propagate("inheritor", taint.NewLabel()) // inherits both

	cleared := s.Clear("intro-secret")

	assert.Equal(t, []string{"intro-secret"}, cleared,
		"only intro-secret should clear; inheritor still derives 'public' from intro-public")
	assert.Equal(t, []taint.Class{"public"}, s.Active().Classes())
}

// Unit: a downstream node that independently introduced a class must
// not clear when an unrelated upstream introducer is cleared.
func TestState_ClearKeepsNodeWithIndependentReads(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	s.Propagate("intro-secret", taint.NewLabel("secret"))
	s.Propagate("indep", taint.NewLabel("public")) // own contribution

	cleared := s.Clear("intro-secret")

	assert.Equal(t, []string{"intro-secret"}, cleared)
	assert.Equal(t, []taint.Class{"public"}, s.Active().Classes())
}

// Unit: clearing an unknown message id is a no-op and reports nothing.
func TestState_ClearUnknownIsNoOp(t *testing.T) {
	t.Parallel()

	s := taint.NewState(newTestPolicy())
	s.Propagate("intro", taint.NewLabel("secret"))

	cleared := s.Clear("does-not-exist")
	assert.Empty(t, cleared)
	assert.Equal(t, []taint.Class{"secret"}, s.Active().Classes())
}
