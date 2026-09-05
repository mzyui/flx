# Doc Rewrite Design — flx (dev branch)

Date: 2026-09-05
Branch: `dev` (origin/dev @ cf95341)
Scope: `src/**/*.rs` (~66 files, incl. `src/rotator/`, `src/base_dirs.rs`, `src/cli/style.rs`)

## Goal
Rewrite all code documentation to short English, delete unnecessary comments. Zero behavior change.

## Decisions (approved)
- Language: English.
- Coverage: all `src/` rustdoc (`//!`, `///`) + inline (`//`).
- Out of scope: `README.md`, `examples/`, `tests/`, `benches/`, CLI help strings (user-facing behavior).
- Style: max 1 line, <100 cols, `/// <Verb> ...`.
- No `Examples`/`Errors`/`Panics` sections; `src/error.rs` variants get 1 line each.
- `src/lib.rs` crate docs trimmed to 1 line (existing example removed for consistency).

## Delete criteria ("gak perlu")
Delete entirely when:
1. Restates the name (`/// Gets the proxy` on `fn proxy()`).
2. States the obvious (`// increment i`, `// loop providers`).
3. Commented-out code, orphan `TODO` without issue reference.
4. Decorative dividers (`// ── ...`) unless separating logical modules.
5. Redundant field docs when struct doc already covers it.
Keep 1 line only for non-obvious why/how: complex regex, custom TLS handshake, anti-replay judge tokens, backpressure, GeoIP fallback, rotator readiness logic.

## Touch list
All files under `src/` on `dev`, notably:
`api.rs`, `lib.rs`, `error.rs`, `resolver.rs`, `filters.rs`, `fetcher/*`, `validator/**/*`, `providers/*`, `proxy/*`, `negotiators/*`, `geolookup/*`, `cli/*` (excl. help text), `rotator/*`, `base_dirs.rs`, `user_agent.rs`, `test_support.rs`.

## Verification
- `cargo fmt --check` clean (docs must not break formatting).
- `cargo clippy --all-targets --all-features` warning-free.
- `cargo test` passes.
- `cargo doc --no-deps` zero warnings.
- `git diff --stat` + manual spot-check: only comment lines changed, no `+` logic lines.

## Risks
- `origin/dev` is active (rotator/serve work); rebase conflicts possible — mitigate by single focused commit, no code moves.
- Over-deletion of subtle invariant comments — mitigate by keeping 1 line for complex logic listed above.
