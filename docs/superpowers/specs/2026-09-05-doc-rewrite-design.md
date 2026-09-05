# Doc Rewrite Design — flx (dev branch)

Date: 2026-09-05
Branch: `dev` (origin/dev @ cf95341)
Scope: `src/**/*.rs` (~66 files, incl. `src/rotator/`, `src/base_dirs.rs`, `src/cli/style.rs`)

## Goal
Rewrite all code documentation to short English, delete unnecessary comments. Zero behavior change.

## Decisions (approved + rev 2026-09-05: two-tier)
- Language: English.
- Coverage: all `src/` rustdoc (`//!`, `///`) + inline (`//`).
- Out of scope: `README.md`, `examples/`, `tests/`, `benches/`, CLI help strings (user-facing behavior).
- Tier 2 (default, internal/trivial): max 1 line, <100 cols, `/// <Verb> ...`; delete if restates name/obvious.
- Tier 1 (important public functions/types): full rustdoc per Rust conventions — summary line + extended description + sections as applicable (`# Arguments`, `# Returns`, `# Errors`, `# Panics`, `# Examples` with compilable snippet, `no_run` for network). Keep tight, no fluff.
- Tier 1 set: `Flx::fetch/collect`, `load_proxy_files`, `ProxyValidator` public API, `ProxyFetcher` public API, `rotator::{server,pool}` public fns, `resolver::resolve`, `geolookup::{sync_database, GeoLookup::lookup}`, `ValidatorConfig/FetcherConfig` constructors with invariants, `error.rs` user-facing variants (1-3 lines + when-returned).
- No `Examples`/`Errors`/`Panics` for Tier 2; Tier 1 includes them only when applicable.
- `src/lib.rs` crate docs: 1-line summary + minimal example (kept, as Tier 1 entry).

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
