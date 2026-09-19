# AGENTS.md

## Purpose

This file defines how coding agents work in this repository. Agents must follow
[STYLE.md](STYLE.md) for Rust design, testing, error handling, documentation,
performance, and platform conventions. The requirements below cover review,
validation, and the agent workflow.

## Code Review Expectations

A change is not complete until:

- The code is formatted.
- Clippy pedantic passes.
- Unit tests are written and passing.
- Edge cases are tested.
- Public documentation is updated.
- README changes are made if behavior or usage changed.
- Errors are meaningful and documented.
- Responsibilities are appropriately separated.
- The design remains maintainable.

Reviewers and agents should reject changes that are clever but fragile, under-tested, poorly documented, or difficult to maintain.

## Required Validation Checklist

Before considering work complete, run the applicable commands:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-features
cargo test --doc
cargo doc --all-features --no-deps
```

When configured for the project, also run:

```bash
cargo audit
cargo deny check
cargo nextest run --all-features
```

For projects with benchmarks, run the relevant benchmark suite when performance-sensitive code changes.

## Agent Behavior Requirements

When an AI or automation agent modifies this repository, it must:

- Follow this file and [STYLE.md](STYLE.md).
- Prefer small, reviewable changes.
- Explain non-obvious design decisions.
- Update tests and documentation with code changes.
- Avoid broad rewrites unless explicitly requested.
- Preserve existing public behavior unless a change is intentional.
- Keep generated code idiomatic and maintainable.
- Avoid adding dependencies without justification.
- Avoid suppressing warnings without justification.
- Leave the repository in a state where the required validation checklist can pass.

If requirements conflict, prioritize correctness, safety, maintainability, and explicit communication.

## Definition of Done

Work is done only when:

- The code solves the requested problem.
- The implementation is idiomatic Rust.
- Responsibilities are appropriately segregated.
- The code is maintainable and understandable.
- All meaningful behavior is tested.
- Edge cases and error cases are covered.
- Public APIs are professionally documented.
- Intra-doc hyperlinks are used where helpful.
- The README is updated if needed.
- Clippy pedantic compliance is preserved.
- Formatting, tests, docs, and validation commands pass.

# Agent workflow

These orchestration instructions apply to the primary agent. Subagents must not
spawn additional agents unless explicitly instructed by the primary agent.

## Implementation tasks

For every non-trivial code change:

1. Spawn the [`planner`](.codex/agents/planner.toml) agent first.
   - Give it the complete request and relevant constraints.
   - Ask it to inspect the repository and produce an implementation plan.
   - Wait for it to finish before implementation begins.

2. Spawn the [`implementer`](.codex/agents/implementer.toml) agent.
   - Provide the original request and conclusions from the
     [`planner`](.codex/agents/planner.toml).
   - Ask it to implement the change, add or update tests, and run the appropriate
     formatting, linting, and test commands.
   - Only the [`implementer`](.codex/agents/implementer.toml) should edit source
     files during this phase.

3. After implementation, spawn the [`reviewer`](.codex/agents/reviewer.toml) agent.
   - Provide the original requirements and ask it to review the resulting diff.
   - The [`reviewer`](.codex/agents/reviewer.toml) must check correctness,
     regressions, security, test coverage, documentation, and repository
     conventions.
   - The [`reviewer`](.codex/agents/reviewer.toml) must not edit files.

4. If the [`reviewer`](.codex/agents/reviewer.toml) finds actionable problems:
   - Send the findings back to the [`implementer`](.codex/agents/implementer.toml).
   - Have the [`implementer`](.codex/agents/implementer.toml) correct them.
   - Run the [`reviewer`](.codex/agents/reviewer.toml) again on the corrected diff.

5. The primary agent performs final verification and reports:
   - What changed
   - Tests and checks executed
   - Any unresolved risks or reviewer findings

## Exceptions

The primary agent may skip this workflow for:

- Read-only questions
- Trivial documentation or spelling corrections
- Tasks where the user explicitly requests a different workflow

Do not run multiple write-capable agents concurrently on the same working tree.
