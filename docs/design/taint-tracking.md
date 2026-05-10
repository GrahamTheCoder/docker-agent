# Taint Tracking for Docker Agent

Status: Draft / proposal. Not yet implemented.

## Problem

When an agent has access to both confidential data (secrets, private files,
internal APIs) and a public egress (HTTP fetch, public posting tools, etc.),
two classes of failure dominate:

1. **Exfiltration** — the model is induced (via prompt injection or honest
   confusion) to send secret-derived content out over a public channel.
2. **Public-input contamination** — content fetched from the public web is
   treated as trusted and ends up driving writes to privileged sinks
   (shell commands, files inside a deploy pipeline, posts to internal
   services).

The mitigation today is "review every action" (`ask` permissions, manual
approval) or "deny on regex". Both are coarse: the first wears out the
human, the second misses the long tail.

A practical middle ground is **information-flow taint tracking** at the tool
boundary, with the following properties:

- Each tool call is *labeled* with the set of taints active at the moment it
  runs (a subset of `{secret, public}` — extensible).
- A tool *reads* one or more taint sources and *writes* into one or more
  taint sinks. The label of any output it produces unions those input
  taints with its read-set.
- The session carries a running taint set. Any tool whose read-set contains
  `secret` makes everything it writes `secret`-tainted; any later tool whose
  sink class is "public network egress" while `secret` is in the active
  set is rejected without user approval — and vice versa for `public →
  privileged sink`.
- Taint can only be **cleared by a human review** of the *single message*
  that introduced the taint. Once that introducer is cleared, every
  downstream message that derived its taint solely from that introducer
  also clears (transitively). The agent is therefore free to keep running
  while the human is offline; the blast radius the human must inspect at
  review time stays small.

The design goal is that **a reviewer of the YAML alone can convince
themselves the system is secure**, given that each subcomponent honors its
declared read/write taints. Boundaries should be visible declaratively, not
hidden in Go code.

## Where this slots into the current codebase

`docker-agent` already has the events we need; we mostly need a place to
hang state and a small wrapper around the existing approval path.

### Existing hook points (do not need to be invented)

| Site | File | What it gives us |
|---|---|---|
| `LocalRuntime.executeWithApproval` | `pkg/runtime/tool_dispatch.go` | The single funnel every user tool passes through. Already evaluates `permissions.Checker`, `--yolo`, `ReadOnlyHint`, then asks the user. The natural choke point for a taint check. |
| `pre_tool_use` hook | `pkg/hooks/...`, dispatched in `executePreToolHook` | Can already deny or rewrite a tool call. Sufficient to *prototype* taint enforcement without touching Go. |
| `post_tool_use` hook | same | Sees `tool_response`. Sufficient to *prototype* taint propagation (label the response). |
| `on_tool_approval_decision` hook | runtime | Already emits a structured "who approved what" record. Reusable as the audit log of taint-cleared decisions. |
| `permissions.Checker.CheckWithArgs` | `pkg/permissions/permissions.go` | Already understands `tool:arg=glob` patterns. A taint-aware checker can sit alongside it without changing this code. |
| `Tool.Annotations` (`ToolAnnotations`) | `pkg/tools/tools.go` | Already carries `ReadOnlyHint`. Natural place to attach declared read/write taint classes. |
| `Toolset` config | `pkg/config/latest/types.go` | YAML-level place to declare per-toolset read/write classes (so the YAML stays the source of truth). |
| `session.Session` | `pkg/session/session.go` | Already mutex-protected, already persisted, already supports branching (`pkg/session/branch.go`). Natural place to keep the live taint state and the per-message taint labels. |
| `ToolCallResult.Meta` | `pkg/tools/tools.go` | Already a free-form `any` on every tool result. Suitable channel for surfacing taint output from in-process tools. |

### What's missing

1. A **taint-label vocabulary** — a small extensible set, with `secret` and
   `public` as the seed classes. Class definitions live in YAML.
2. A **per-message taint label** on `session.Item` / `session.Message`. This
   is what makes the "clear the introducer, downstream clears with it"
   property cheap to compute: the graph is just the message DAG.
3. A **taint state** on `session.Session` derived from the labels of the
   currently-active (un-cleared) messages.
4. A **policy engine** that, given (a) the active taint state, (b) the
   tool's declared read/write classes, decides allow/deny/escalate. This
   is the only new check at the approval-chain point, and it composes with
   the existing `permissions.Checker`.
5. A **clearance UI** (CLI subcommand + TUI panel) that lets a user clear a
   specific introducer message; downstream clears follow automatically.
6. A **git-backed audit log** of taint transitions, so the
   "clearance is reversible because everything is in git" claim holds.

## Vocabulary

```
TaintClass:    name (string), egress|ingress|both, description
TaintLabel:    set of TaintClass names currently attached to a message/result
TaintSource:   declared classes a tool READS  (e.g. fetch reads `public`,
               filesystem.read of a `*.env` reads `secret`)
TaintSink:     declared classes a tool WRITES (e.g. fetch.POST writes `public`,
               filesystem.write writes whichever taint is active in the session)
```

Two seed classes are wired in by default:

- `secret` — anything derived from credentials, env files, private repos,
  internal APIs.
- `public` — anything derived from a fetched/external/untrusted source.

The rule that does the work is a single matrix in YAML:

```yaml
taints:
  classes:
    secret: { description: "derived from credentials or private data" }
    public: { description: "derived from external/untrusted content" }
  forbid:
    # an active 'secret' taint forbids any tool that writes to 'public'
    - when: { active: [secret] }
      tool_writes_to: [public]
    # an active 'public' taint forbids tools that write into the
    # privileged side (shell, internal APIs, secret-tagged paths)
    - when: { active: [public] }
      tool_writes_to: [privileged]
```

Forbid rules are evaluated *before* the existing
`permissions.Allow/Ask/Deny` chain. A forbid hit is hard-denied with a
reason; the human can clear the introducer and retry.

## Declaring read/write classes in YAML

Two layers, both visible at the top of the YAML:

### 1. Built-in classification per tool kind

Codified once, in Go, but surfaced as defaults the YAML can override:

```yaml
taints:
  classifiers:
    builtin:
      fetch:                       { reads: [public], writes: [public] }
      filesystem.write_file:       { reads: [],       writes: [active] }
      filesystem.read_file:        { reads: [path],   writes: [] }
      shell:                       { reads: [env],    writes: [active] }
```

`active` is a sentinel meaning "the union of the session's currently active
taints" — i.e. the propagation rule. `path` and `env` are tag-lookup
sentinels: their concrete value is computed from the tool's arguments
against the next layer.

### 2. Path/env/url tag mapping

```yaml
taints:
  tags:
    paths:
      - { match: "**/.env*",          add: [secret] }
      - { match: ".anthropic_api_key", add: [secret] }
      - { match: "/run/secrets/**",    add: [secret] }
      - { match: "**/public/**",       add: [public] }
    env:
      - { match: "*_API_KEY",          add: [secret] }
      - { match: "*_TOKEN",            add: [secret] }
    urls:
      - { match: "https://internal.*", add: [secret] }
      - { match: "http*://*",          add: [public] }   # catch-all
```

This is enough to express "reading `.env` taints the result with `secret`"
and "fetching `https://example.com` taints the result with `public`"
without any per-tool wiring beyond the declared class.

### 3. Per-toolset override

A toolset block in the YAML can override the defaults locally:

```yaml
toolsets:
  - type: mcp
    ref: docker:github
    taints:
      reads:  [secret]       # treat all responses as secret-tainted
      writes: [secret]       # PRs etc. count as a privileged sink
```

This is what makes the YAML the contract: a reviewer looking at the agent
file sees `taints.reads / taints.writes` on every toolset and can reason
about the cut.

## Propagation

When a tool returns:

1. Compute the tool's effective read-set R (declared + tag lookup on
   args).
2. Compute the result label L = R ∪ propagated taint from any other
   message that fed this tool's arguments (the arg-source set — see
   below).
3. Stamp the resulting `session.Message` with L.
4. Update the session's active taint set to the union of L over all
   un-cleared messages currently in scope.

The "arg-source set" is approximated by looking at which prior message
IDs are textually referenced — but the cheaper and safer default is:
**the active taint set at the time of the call**. This is the standard
"sticky" propagation; precision can be improved later with explicit
provenance tracking on `Message`.

## Enforcement (the `executeWithApproval` insertion)

```
yolo? -> allow
session/team permissions? -> allow | deny | ask
TAINT CHECK (new):
   active_taints = session.activeTaints()
   for rule in cfg.taints.forbid:
     if rule.when.active ⊆ active_taints
        and rule.tool_writes_to ∩ tool.declaredWrites != ∅:
        return Deny("would write {sinks} while {active} is tainted; clear msg #N first")
ReadOnlyHint? -> allow
default -> ask
```

This is one new branch added in `tool_dispatch.go`; everything else stays.

## Clearance

The "clear an introducer, downstream clears with it" property is the user
experience win. It needs:

- A **taint origin** field on each tainted message: `taint.origin =
  message_id` for the message that first introduced each class.
- A `docker agent taint clear <message_id> [--class secret]` command (and a
  TUI binding) that:
  - Marks the introducer message as cleared by `<user>` at `<timestamp>`.
  - Walks the message DAG forward; any message whose taint label can be
    explained entirely by cleared introducers also clears.
  - Records the clearance as a git commit in the session's git-backed log
    (every session is already a directory of artifacts; we add a
    `.taint-log.git`).
- A `taint show` view: list active taints, their introducers, and the
  blast-radius messages that would clear.

The graph is the message-DAG, so "minimum cut" / "what set of clears
unblocks the most work" reduces to standard min-cut on a small graph
(a handful to hundreds of nodes, max).

## Audit / git

Every taint event (introduction, propagation, clearance, denial) is a
line in the session's append-only log, signed/commited to git. The git
history gives:

- the precise message that introduced each taint,
- the human who cleared it (and when),
- a deterministic re-derivation of the active set at any point in time.

This is what makes the system *reviewable* and the clearance
*non-destructive*: an over-eager clearance can be audited and rolled back
because git keeps the prior state.

## Options considered

### A. **All in YAML via hooks** (no Go changes)

`pre_tool_use` reads a sidecar `.taint.json`, makes the deny decision, and
the post-tool hook updates the file. Pros: zero core changes; ships
immediately as an example. Cons: state is out of band; no integration
with the existing `permissions.Checker` ordering; per-message labels
aren't part of the session; clearance UI has nowhere to live.

Verdict: **good first prototype**, ship as `examples/taint.yaml` to
validate the model end-to-end before any core change.

### B. **First-class taint state on `session.Session`, policy engine as a Go package, declarative config in YAML**

Add `pkg/taint`, surface a `Taints` block in `latest.Config` and per-toolset
`Toolset.Taints`, insert one branch into `executeWithApproval`, and add
`docker agent taint {show,clear}` subcommands. Keeps the YAML as the
audit surface; keeps the runtime change minimal (one new check, additive).

Verdict: **the recommended target.** Most of the substrate already exists.

### C. **Make taint a special case of `permissions.Checker`**

Encode `secret`/`public` as virtual tool-argument keys and let the pattern
language do the matching. Pros: nothing new to learn. Cons: the active
session state is what does the work, and `Checker.CheckWithArgs` is
stateless by design; bending it would muddy the contract for everyone
else. Better to keep the checkers orthogonal.

Verdict: **reject** as the primary mechanism. Re-use the *pattern syntax*
inside `taints.tags` so users don't learn two glob dialects, but keep the
checkers separate.

### D. **Track provenance per-byte (full IFC)**

Tag every byte of every message with its source set, propagate through the
model call by re-prompting with provenance, etc. Maximum precision,
maximum cost, weeks of work, and the model has no way to honor a per-byte
contract. Out of scope.

Verdict: **reject for v1.** Sticky session-level taint plus per-message
labels is the right precision/cost trade-off; provenance-on-message can
be added later without breaking the API.

## Recommended plan (Option B)

Phased so each phase ships value on its own.

### Phase 0 — Prototype as a pure-YAML example (no core changes)

- `examples/taint.yaml`: a working agent with `pre_tool_use` and
  `post_tool_use` shell hooks that read/write `~/.docker-agent-taint.json`.
- Two example flows: a `secret → public` exfil attempt that gets blocked,
  and a `public → shell` injection attempt that gets blocked.
- Validates the vocabulary and the rule matrix.

Acceptance: running the example with a prompt that tries to exfil
prints a deny reason that names the introducer message.

### Phase 1 — Declare taints in the schema

- Extend `pkg/config/latest/types.go`:
  - `Config.Taints *TaintConfig`
  - `Toolset.Taints *ToolsetTaints` (reads, writes)
- Update `agent-schema.json` (mandated by `AGENTS.md`).
- Parse and validate, but do not yet enforce. Add `docker agent taint
  print-classification <agent.yaml>` to dump the effective per-tool
  classification — gives users a way to audit the YAML statically.

Acceptance: `taint print-classification` shows the read/write set for
every tool the agent will expose; schema docs published.

### Phase 2 — Session-level taint state + per-message labels

- New `pkg/taint` package.
  - `type Class string`
  - `type Label map[Class]struct{}` (set semantics)
  - `type State` holds active set + introducer-message map + the
    cleared-introducer set.
  - `State.Propagate(msg, readSet)` returns the new message label.
  - `State.Allow(toolReads, toolWrites)` returns `(decision, reason,
    introducer_ids)`.
- Add `Message.Taint *Label` and `Message.TaintOrigin []string` to
  `pkg/session/session.go`. Persist with the session.
- Wire the propagator into `executeToolWithHandler` *after* the tool
  returns (post-tool labelling).

Acceptance: unit tests in `pkg/taint` cover sticky propagation,
clearance closure, and the deny matrix.

### Phase 3 — Enforce at the approval point

- One new branch in `pkg/runtime/tool_dispatch.go`,
  `executeWithApproval`, between the team-permissions check and the
  read-only-hint shortcut.
- A taint-deny emits the same `addToolErrorResponse` shape as a
  permissions deny, plus a structured `on_tool_approval_decision` hook
  with `approval_source: "taint_deny"` and a reason that names the
  introducer.

Acceptance: example flows from Phase 0 now work *without* the YAML
hooks; the runtime enforces.

### Phase 4 — Clearance UX

- `docker agent taint show [--session <id>]`
- `docker agent taint clear <message_id> [--class <class>] [--reason ...]`
- TUI key-binding (likely under the existing approval panel).
- Git-backed log of clearance events.

Acceptance: a session that hit a deny can be cleared by the user from
the CLI, run continues, and the git log shows who cleared what.

### Phase 5 — Graph helpers

- `taint suggest-cut <message_id>` — given a denied call, return the
  minimum set of clearances that would unblock it (standard min s–t cut
  on the introducer DAG). Useful when many introducers contributed to
  the active set and the human wants the smallest review surface.

Acceptance: on a constructed session with N>1 contributing introducers,
the suggestion returns the actual minimum.

## Open questions

1. **Does the model see the taint state?** Leaning yes — surface active
   taints in `turn_start` `additional_context` so the model can self-route
   ("I won't try to fetch while secret is active"). It's a soft signal,
   not a substitute for enforcement.
2. **How do MCP tool responses get classified?** v1: by toolset config
   declaration (`taints.reads/writes` on the toolset). v2: read MCP tool
   annotations if the server exposes anything we can use.
3. **What about sub-agents?** A sub-agent inherits the parent's active
   taint set. Delegation crosses the same enforcement point. Already
   covered by the `on_agent_switch` event for audit.
4. **What about RAG?** Treat the RAG store's source as the class. A
   private corpus is `secret`; a web crawl corpus is `public`.
5. **Performance.** All checks are O(|classes|) per tool call; classes
   are a handful. Free.

## Why this is worth doing

- The audit story for `docker-agent` becomes: *"show me the YAML"*. A
  reviewer can read taint declarations on every toolset and the forbid
  matrix at the top, and reason about exfil/contamination without
  reading Go.
- The human is no longer the bottleneck for "agent keeps running while
  I'm away from the desk" — review is async and scoped to the
  introducer.
- Nothing in this design is mandatory: agents that don't set
  `taints:` behave exactly as today. The feature is opt-in and
  composable with the existing `permissions` and `hooks` blocks.
