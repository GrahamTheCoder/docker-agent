# pkg/taint

## Spec

Information-flow taint tracking for agent tool calls. A small extensible
set of taint *classes* flows along the session as tools run; a forbid
matrix rejects cross-flows.

Two seed classes are wired by default: `secret` (anything derived from
credentials or private data) and `public` (anything derived from
external / untrusted content). Users can declare more.

Submodules describe their own internals; this layer states what each
must provide to the runtime.

### Children

- `class.go` — the class vocabulary. A `Class` is a string identifier;
  a `Label` is the set-of-classes attached to a message or tool result.
- `state.go` — the per-session live state: which classes are currently
  active, which message introduced each one, which introducer messages
  have been cleared by the user. Exposes `Propagate(reads) Label` and
  `Decide(reads, writes) Decision` so the runtime can call into it from
  exactly two places (post-tool labelling and pre-tool enforcement).
- `policy.go` — the forbid matrix evaluator. Stateless given a snapshot
  of the active set and a tool's declared write classes.
- `classifier.go` — given a tool name and its arguments, returns the
  effective read and write classes. Built from the per-toolset YAML
  declarations plus the path/env/url tag tables.

### Contract with the runtime

- The runtime calls `Classifier.Classify(toolName, args)` immediately
  before approval to get `(reads, writes)`.
- The runtime calls `State.Decide(reads, writes)` as one new branch in
  `executeWithApproval` (`pkg/runtime/tool_dispatch.go`). A `DenyDecision`
  surfaces a reason that names the introducer message.
- After a tool returns, the runtime calls `State.Propagate(reads)` to
  obtain the `Label` to stamp on the resulting `session.Message`.

### Contract with config

`pkg/config/latest` exposes a `taints:` block that this package
consumes verbatim. The YAML is the audit surface — declarations on
each toolset plus the top-level forbid matrix determine the
classifier's behaviour. This package does not parse YAML directly.

### Drift

Not yet implemented. Phase rollout from
`docs/design/taint-tracking.md`:

- Phase 1 (in progress): config schema additions in
  `pkg/config/latest`; no runtime behaviour change. This package is
  bootstrapping its own types in parallel so Phase 2 has somewhere to
  land.
- Phase 2: `class.go`, `state.go`, `policy.go`, `classifier.go` here
  with unit tests covering sticky propagation, clearance closure, and
  the deny matrix.
- Phase 3: one new branch in `executeWithApproval`.
- Phase 4: `docker agent taint show|clear` CLI + TUI + git-backed log.
- Phase 5: min-cut helper for "smallest set of clearances to unblock".
