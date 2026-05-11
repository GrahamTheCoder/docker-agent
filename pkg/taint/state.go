package taint

// State holds the live taint state for a single session.
//
// Each call to Propagate appends a node to the message DAG with the
// classes that call introduced (its read set). Every node also
// inherits the active set at the time of the call as parent classes
// — this is the "sticky" propagation rule. Clearance walks the DAG
// from the cleared node, removing classes that no surviving uncleared
// node still introduces or transitively inherits.
//
// State is not safe for concurrent use. The runtime serialises tool
// calls per session, which is the only writer; readers (audit, TUI)
// must take the session mutex before calling Active / Introducers.
type State struct {
	policy Policy

	// nodes is the message DAG, in append order. We don't need a map
	// from id -> index because clearance walks linearly and the
	// number of nodes per session is small (at most one per
	// tool-call message).
	nodes []node
}

// node is a single message's contribution to the taint state.
type node struct {
	id      string
	reads   Label // classes this call introduced from its read set
	cleared bool  // marked true by Clear (directly or transitively)
}

// NewState constructs an empty state with the given forbid policy.
func NewState(p Policy) *State {
	return &State{policy: p}
}

// Active returns the union of every uncleared node's effective label
// (its own reads, plus everything still active from earlier
// uncleared nodes).
//
// "Active" is recomputed from the DAG every call; that's O(n²) over
// the node count but n is bounded by the message count and the
// constant factor is tiny — the alternative (caching) means rebuilding
// the cache on every clearance, which is the same work in a worse
// shape.
func (s *State) Active() Label {
	var l Label
	for _, n := range s.nodes {
		if n.cleared {
			continue
		}
		l = l.Union(n.reads)
	}
	return l
}

// Propagate records that a tool call (resulting in message id) read
// the classes in `reads`. Returns the label that should be stamped
// on the resulting session.Message: the union of `reads` and the
// active set at the moment of the call ("sticky" propagation).
func (s *State) Propagate(id string, reads Label) Label {
	carried := s.Active()
	s.nodes = append(s.nodes, node{id: id, reads: reads})
	return carried.Union(reads)
}

// Decide consults the policy with the supplied active set against the
// tool's declared writes. Callers usually pass `s.Active()` for
// `active`; taking it as a parameter keeps the call site explicit and
// makes Decide easy to test without wiring through Propagate.
func (s *State) Decide(active, writes Label) Decision {
	return s.policy.Decide(active, writes)
}

// Introducers returns the message ids of every uncleared node whose
// own reads include c. The list is in chronological order.
func (s *State) Introducers(c Class) []string {
	var ids []string
	for _, n := range s.nodes {
		if n.cleared {
			continue
		}
		if n.reads.Contains(c) {
			ids = append(ids, n.id)
		}
	}
	return ids
}

// Clear marks the given message id as cleared and transitively
// clears every later node whose taint was derived *solely* from the
// cleared chain — i.e. whose effective label drops to empty once the
// cleared nodes are excluded. A node with its own independent reads,
// or one that still inherits from a surviving introducer, is left
// alone. Returns the ids of all newly cleared nodes in chronological
// order, or nil if id is unknown or already cleared.
func (s *State) Clear(id string) []string {
	idx := s.indexOf(id)
	if idx < 0 || s.nodes[idx].cleared {
		return nil
	}
	s.nodes[idx].cleared = true
	cleared := []string{id}

	for i := idx + 1; i < len(s.nodes); i++ {
		if s.nodes[i].cleared {
			continue
		}
		if s.effectiveLabelAt(i).Len() > 0 {
			continue
		}
		s.nodes[i].cleared = true
		cleared = append(cleared, s.nodes[i].id)
	}
	return cleared
}

// effectiveLabelAt returns the label this node carries with the
// current cleared flags respected: its own reads plus the union of
// every uncleared earlier node's reads.
func (s *State) effectiveLabelAt(i int) Label {
	var l Label
	for j := 0; j < i; j++ {
		if s.nodes[j].cleared {
			continue
		}
		l = l.Union(s.nodes[j].reads)
	}
	return l.Union(s.nodes[i].reads)
}

// indexOf returns the slice index of the node with the given id, or
// -1.
func (s *State) indexOf(id string) int {
	for i, n := range s.nodes {
		if n.id == id {
			return i
		}
	}
	return -1
}
