// Package taint implements the information-flow taint tracking
// described in docs/design/taint-tracking.md. See pkg/taint/README.md
// for the layer's spec and contract with the runtime.
package taint

import "sort"

// Class is the opaque identifier for a taint class. Names are defined
// in the YAML `taints.classes` block (or the seed defaults `secret`,
// `public`, `privileged`).
type Class string

// Label is a set of taint classes attached to a message, a tool
// result, or carried as the active set on a session. Labels are
// immutable: every mutator returns a new value.
type Label struct {
	// classes is sorted on every construction so equality and
	// rendering are deterministic without an extra normalisation pass.
	classes []Class
}

// NewLabel constructs a Label from the given class names, deduplicating
// and sorting.
func NewLabel(cs ...Class) Label {
	if len(cs) == 0 {
		return Label{}
	}
	seen := make(map[Class]struct{}, len(cs))
	out := make([]Class, 0, len(cs))
	for _, c := range cs {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return Label{classes: out}
}

// Len returns the number of classes in the label.
func (l Label) Len() int { return len(l.classes) }

// Contains reports whether c is present.
func (l Label) Contains(c Class) bool {
	for _, x := range l.classes {
		if x == c {
			return true
		}
		if x > c {
			return false
		}
	}
	return false
}

// Classes returns the classes in lexicographic order. The slice is a
// copy; mutating it does not affect the label.
func (l Label) Classes() []Class {
	if len(l.classes) == 0 {
		return nil
	}
	out := make([]Class, len(l.classes))
	copy(out, l.classes)
	return out
}

// With returns a new label with c added.
func (l Label) With(c Class) Label {
	if l.Contains(c) {
		return l
	}
	cs := append(l.Classes(), c)
	return NewLabel(cs...)
}

// Union returns the set union.
func (l Label) Union(other Label) Label {
	if l.Len() == 0 {
		return other
	}
	if other.Len() == 0 {
		return l
	}
	cs := make([]Class, 0, l.Len()+other.Len())
	cs = append(cs, l.classes...)
	cs = append(cs, other.classes...)
	return NewLabel(cs...)
}

// Intersect returns the set intersection.
func (l Label) Intersect(other Label) Label {
	if l.Len() == 0 || other.Len() == 0 {
		return Label{}
	}
	out := make([]Class, 0, min(l.Len(), other.Len()))
	for _, c := range l.classes {
		if other.Contains(c) {
			out = append(out, c)
		}
	}
	return Label{classes: out}
}

// Subset reports whether every class in l is also in other.
func (l Label) Subset(other Label) bool {
	for _, c := range l.classes {
		if !other.Contains(c) {
			return false
		}
	}
	return true
}
