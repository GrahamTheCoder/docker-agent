package taint

import (
	"fmt"
	"strings"
)

// ForbidRule is one row of the forbid matrix. The rule fires when
// every class in When is currently active AND any class in Writes
// appears in the tool's declared write set.
type ForbidRule struct {
	When   Label
	Writes Label
}

// Policy is a stateless evaluator over a list of forbid rules.
type Policy struct {
	rules []ForbidRule
}

// NewPolicy constructs a Policy from the given rules. Nil and the
// empty slice produce an allow-everything policy.
func NewPolicy(rules []ForbidRule) Policy {
	if len(rules) == 0 {
		return Policy{}
	}
	cp := make([]ForbidRule, len(rules))
	copy(cp, rules)
	return Policy{rules: cp}
}

// Decision is the result of evaluating a tool call against the
// policy. Triggered carries the indices of every rule that fired so
// audit consumers can name them.
type Decision struct {
	Allowed   bool
	Reason    string
	Triggered []int
}

// Decide returns the verdict for a tool call whose effective active
// set is `active` and whose declared writes are `writes`. Stateless;
// callers (typically [State]) supply the active set.
func (p Policy) Decide(active, writes Label) Decision {
	if writes.Len() == 0 {
		return Decision{Allowed: true}
	}
	var triggered []int
	var reasons []string
	for i, r := range p.rules {
		if !r.When.Subset(active) {
			continue
		}
		overlap := r.Writes.Intersect(writes)
		if overlap.Len() == 0 {
			continue
		}
		triggered = append(triggered, i)
		reasons = append(reasons, fmt.Sprintf(
			"%s active forbids writing to %s",
			classList(r.When), classList(overlap),
		))
	}
	if len(triggered) == 0 {
		return Decision{Allowed: true}
	}
	return Decision{
		Allowed:   false,
		Reason:    "taint: " + strings.Join(reasons, "; "),
		Triggered: triggered,
	}
}

// classList renders a label's classes as a comma-separated list. Used
// only in human-readable Reason strings.
func classList(l Label) string {
	cs := l.Classes()
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = string(c)
	}
	return "{" + strings.Join(parts, ",") + "}"
}
