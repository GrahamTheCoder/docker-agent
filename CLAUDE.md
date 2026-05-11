# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

This is a single Go project (`module github.com/docker/docker-agent`). Existing
contributor guidance lives in `AGENTS.md` (build/test/lint commands and the
config-schema rule); this file adds the working convention on top.

## Commands

Use the `mise` tasks defined in `mise.toml`:

- `mise build` — build `./bin/docker-agent`.
- `mise test` — Go test suite (clears API keys for determinism).
- `mise lint` — `golangci-lint` per `.golangci.yml`.
- `mise format` — `golangci-lint fmt`.
- `mise dev` — lint, test, build in sequence.

Run a single package's tests with `go test ./pkg/<pkg>/...`. Run a single test
with `go test ./pkg/<pkg> -run TestName`.

## Atomic commit strategy

Committing as you go is **mandatory** when moving between phases. Never wait
until the end of a task to commit everything.

The repo uses Conventional Commits (`feat(scope): ...`, `refactor(provider):
...`, `docs(design): ...`). Within that, use these workflow prefixes when
relevant:

- `{scope} spec:` — README/spec change naming the upcoming subtasks
- `{scope} red:` — failing test added; include why this test
- `{scope} green:` — minimum change to pass; include how it works
- `{scope} refactor:` — refactor; include the reason
- `{scope} improve:` — non-functional improvement; include the reason

Guidelines:

- Keep changes atomic — one logical change per commit.
- Use `git commit --fixup` if you spot something that should have been earlier.
- Delete replaced code immediately. Never keep dead code "just in case" — git
  has it. Old `// removed` comments and re-exports of unused types are noise.

## Working convention

The spec is modular. Each layer (folder) describes only how the layers
**directly below** interact: decisions, requirements, reasoning, and (briefly)
discarded alternatives.

Every directory of consequence has a `README.md` containing:

- A `## Spec` section describing **desired state** of this layer.
- An optional `### Drift` subsection naming the gap between spec and code,
  and what to do about it. May reference an earlier git hash where helpful.

A file-top docstring is a valid home for spec + drift when a single-file
submodule is small enough not to warrant a README. Same rules apply. When a
file grows past ~150 lines, break out a subfolder with its own README rather
than letting the doc block sprawl.

Scoping rules:

- A README describes only its **direct children**. It must not describe the
  internals of a child — that's the child's README's job.
- A parent defines *what* it needs from a child, not *how* the child is
  structured. If the parent layer reads short, even better.
- Exception: any README may state how it uses a library module under
  `pkg/<category>/<lib>` (Go's natural "library" location in this repo).

Spec vs drift:

- Spec describes desired state only. Don't write "currently does X, should do
  Y" in the spec — that's drift.
- Drift is the **current** gap. If the code already matches spec, drift is
  absent. The spec is not a changelog: don't version-stamp shipped work, don't
  catalogue modules with status tables, don't narrate the path the
  implementation took. Git is the changelog.
- The pre-drift portion of a Spec section should rarely exceed ~50 lines.

Order of work:

1. Update Spec sections to reflect intent; record planned changes in Drift.
2. Add explicit implementation plan to Drift if non-trivial.
3. Implement TDD-style:
   - **Think** — pick the simplest test that moves toward the spec.
   - **Red** — write one test. If new types are needed to compile, stub the
     minimum in the test file first.
   - **Green** — minimum change to pass.
   - **Refactor** — when duplication appears, restructure toward the spec.
     Files >150 lines or Spec sections >50 lines hint that a submodule wants
     breaking out — recurse into the new module with the same loop.
4. Use a subagent to blind-review against the spec. Note open questions and
   remaining drift.
5. Loop until drift is gone or blocked on an answer you don't have.
6. Critically review code quality:
   - Simplify, reduce AI slop, prioritise readability.
   - Fold comments into names where possible; keep comments only when they
     carry rationale that names cannot. Defensive error handling for cases
     the type system already prevents is slop.
   - Run `mise lint` and `mise test`.
7. Standardise tools/processes in the README; reflect general rules in the
   nearest README (or `CLAUDE.md` if AI-specific).

Tests:

- Mark each test as **unit** (single layer), **integration** (two layers), or
  **system** (all layers below). Test name or comment is fine.
- Test names should make the spec item under test obvious. Acceptable to
  write a system-level acceptance test first that stays red through the TDD
  loop.
- Aim for near-full coverage of spec behaviour. **Test spec behaviour, not
  implementation details.** The best way to raise coverage is usually to
  delete slop, not to write more tests.

Library hoisting:

- A module used by exactly one parent stays under that parent.
- Once two modules import it, hoist it under `pkg/<category>/<lib>` and
  reference it from both. Library modules can be referenced from anywhere;
  internal submodules of a library are only referenced by the library's own
  README.

### Why

We're avoiding the common AI failure mode: generate a wall of code, then
patch it with low-context surgical edits per bug. Going back to the spec,
splitting the layer further, and rewriting/refactoring the affected slice is
almost always cheaper than chasing edits.

## Config schema rule (from AGENTS.md)

When adding new YAML features, change **only** `pkg/config/latest`; older
`pkg/config/v0..v7` are frozen. Update `agent-schema.json` and add an
example in `examples/` that demonstrates the feature.
