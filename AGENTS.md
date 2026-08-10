# AGENTS.md

Fluxy is a Rust proxy scraper/validator (library `fluxy` + CLI binary `fluxy`).
Edition 2021, no rust-toolchain pin, no clap or CI job that runs tests.

## Verified commands

- `cargo check` — works.
- `cargo clippy --all-targets --all-features -- -D warnings` — must stay clean.
- `cargo check --no-default-features` and `cargo clippy --lib --no-default-features -- -D warnings` — both verified green; the bin is behind `required-features = ["clap"]`, so always sanity-check the no-default-features build when touching modules the CLI gated.
- `cargo test --lib` — 63 unit tests, inline in `src/` (`#[cfg(test)] mod tests`); there are no `tests/*.rs` integration files (only `tests/fixtures/` with certs).
- `cargo test --bin fluxy` — the 10 CLI/`process_result` JSON tests in `src/cli/main.rs`. Plain `cargo test` and `cargo test --all-targets` stop after the lib target, so run `--bin fluxy` separately to cover the CLI tests.
- `cargo fmt` — the current tree does NOT pass `cargo fmt --check`; run `cargo fmt` before committing or the diff will be noisy. Docs (`docs/remediation-phases.md`) treat fmt + clippy `-D warnings` + `--no-default-features` builds as mandatory gates.

## Known broken test (do not chase env issues)

`validator::checker::tests::self_signed_judge_passes_preflight_with_insecure` fails deterministically. Root cause: the in-test TLS judge server (`spawn_self_signed_judge`, `src/validator/checker.rs`) extracts the token with a case-sensitive `strip_prefix("X-Fluxy-Token:")`, but hyper serializes header names lowercase, so the token is parsed as empty and the echo can never match → "did not echo X-Fluxy-Token". Fix is a case-insensitive header match; verified locally to make the test pass. This is the unfinished F-32 regression (see `docs/`).

## Architecture (not obvious from filenames)

- Flow: `ProxyFetcher::gather` (`src/fetcher/`) produces a bounded `mpsc` stream of candidates → `ProxyValidator::validate` (`src/validator/`, default 500 workers) → output stream rendered in `src/cli/process_result`, which hand-rolls the JSON array (opening `[`, commas, `]`). Don't reformat that; tests pin no-trailing-comma behavior.
- Fetcher runs providers in two deterministic phases: `Primary` tier first, then `Fallback`, with a barrier between (`ProviderTier`, `src/providers/models.rs`). `Config::fallback_threshold` (`src/fetcher/config.rs`) can skip fallbacks.
- Validation is online-judge based: every candidate must echo Fluxy's unique `X-Fluxy-Token` header; judges are preflighted at startup and dropped on failure (run aborts if none pass). HTTPS cert validation is on by default; `--insecure` disables it. Token replay and `--insecure` behavior are covered by regression tests (F-30/F-32).
- GeoIP is opt-in via `--countries`. It downloads `GeoLite2-City.mmdb` (from the P3TERX mirror) into the platform data dir on first use with a 120s timeout / 128MB cap; partial/corrupt files are deleted and re-downloaded. `Config` guards `countries != []` against `enable_geo_lookup == false` (F-34).
- `Proxy.geo` is serialized into JSON output (F-35 regression test in `src/proxy/models.rs`).
- `proxyscan` provider is intentionally absent (`src/providers/`): its download endpoint returns 404.

## Conventions

- When patching code in `src/`, never add audit references (item numbers like "B.17", "re-audit", "F-xx") to documentation or code comments. Keep code comments about the code itself; audit/effort notes belong only in `docs/*` (and even there, only when the user asks for them).

## Gotchas

- The working tree has uncommitted WIP (`git status`: Cargo.toml, examples/provider_check.rs, src/cli/main.rs, src/validator/{checker,mod}.rs). Don't commit unless asked.
- `Cargo.lock` is committed on purpose (repo has a binary).
- Tests use local `TcpListener`s and are offline-safe, except `fetcher::gather_allows_country_filter_with_geo_lookup` which may attempt the real GeoIP download if it gets past the config guard.
- Docs `docs/*.md` are Indonesian-language concurrency audits referencing open items F-08/F-14/F-25/F-30/F-32/F-33; `docs/remediation-phases.md` lists the canonical verification command set.