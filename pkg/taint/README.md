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
  Exports `ClassSecret` / `ClassPublic` / `ClassPrivileged` so callers
  never have to refer to the seed names by string literal.
- `state.go` — the per-session live state: which classes are currently
  active, which message introduced each one, which introducer messages
  have been cleared by the user. Exposes `Propagate(reads) Label` and
  `Decide(active, writes) Decision`. A node clears transitively iff
  its taint came *solely* from the cleared chain (own reads empty AND
  every inherited class came only from cleared introducers); a node
  with independent reads or a surviving alternate introducer is left
  alone. Not safe for concurrent use — the runtime serialises tool
  calls per session.
- `policy.go` — the forbid matrix evaluator. Stateless given a
  snapshot of the active set and a tool's declared write classes.
  Returns every triggered rule index so audit consumers can render
  the full reason.
- `classifier.go` — given a tool name and its arguments, returns the
  effective read and write classes. Built from the per-toolset YAML
  declarations plus the path/url tag tables. Per-toolset declarations
  are unioned (never overriding) so a YAML widening cannot
  accidentally undo a tightening.

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

Runtime is not yet calling into this package. The remaining work,
following `docs/design/taint-tracking.md`:

- One new branch in `pkg/runtime/tool_dispatch.go:executeWithApproval`
  that builds a `Classifier` from `Config.Taints` + `Toolset.Taints`
  on session start, threads a `*State` per session, and consults
  `State.Decide` between the team-permissions check and the
  read-only-hint shortcut. Post-tool, calls `State.Propagate` to stamp
  the resulting `session.Message`.
- `Message.Taint *Label` and `Message.TaintOrigin []string` on
  `pkg/session/session.go`, persisted with the session.
- `docker agent taint show|clear` CLI + TUI + git-backed audit log.
- A min-cut helper for "smallest set of clearances to unblock a
  denied call" once the prior phases have real session data to test
  on.
- The built-in classifier defaults for `fetch` / `shell` / `read_file`
  / `write_file` / `edit_file` are baked into the Go switch. The
  design contemplates them as YAML-overridable defaults; today
  per-toolset declarations can only union with them, never replace.
  Move them to a data-driven table once a real workload demands the
  override.
- `taints.tags.env` is parsed in the YAML schema but not consumed by
  the classifier. Wire it in alongside a `shell` env-derived read set
  when the runtime gains shell-env classification.
