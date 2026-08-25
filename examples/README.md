# flx by example

Runnable samples for the flx library — one file per concept, each small enough to read in one sitting. Run any of them from the repository root:

```bash
cargo run --example fetch
```

## Fetch

[`fetch.rs`](examples/fetch.rs) is the smallest useful program: scrape from the built-in providers, validate every candidate as plain HTTP, and print the survivors as `ip:port`.

```rust
let proxies = Flx::fetch().validate_http().limit(10).collect().await?;
```

`Flx::fetch()` starts a builder over the built-in provider set. A validation target is mandatory — `.validate_http()` mirrors the CLI default of plain HTTP checks; use `.types([...])` or `.groups(...)` to pick others, or `.no_validate()` to skip checking entirely.

## Validate a file

[`validate.rs`](examples/validate.rs) reads candidates from an `ip:port` file instead of scraping. Lines may be bare (`1.2.3.4:8080`, inheriting every requested protocol) or scheme-prefixed (`socks5://…`, pinning their own type).

```rust
let proxies = Flx::from_file("proxies.txt")?
    .types([Protocol::Http(Anonymity::Unknown), Protocol::Socks5])
    .collect()
    .await?;
```

The path `-` reads standard input, and `Flx::from_files([...])` accepts many files at once.

## SOCKS only

[`socks.rs`](examples/socks.rs) validates a list against SOCKS5 alone. SOCKS proxies have no anonymity level — passing the tunnel handshake is the whole test — so results print as ready-to-use `socks5://ip:port` URIs.

## AND groups

[`groups.rs`](examples/groups.rs) requires one endpoint to support **both** protocols of a group: HTTP forwarding *and* a SOCKS5 tunnel. Every member of a group is always probed, and the group passes only when all slots succeed.

```rust
Flx::fetch()
    .groups(vec![vec![Protocol::Http(Anonymity::Unknown), Protocol::Socks5]])
```

## Streaming with progress

[`stream.rs`](examples/stream.rs) swaps `collect()` for `stream_with_progress()`: validated proxies arrive one at a time while live counters tick, and the final tallies are readable once the stream ends.

```rust
let mut run = Flx::fetch().validate_http().limit(20).stream_with_progress().await?;
while let Some(proxy) = run.next().await { /* ... */ }
let progress = run.progress(); // passed / done / total
```

## Failure reports

[`failures.rs`](examples/failures.rs) enables `.report_failures()`, which opens a side channel emitting one machine-readable record per failed probe — IP, port, protocol, and a classified reason (`timeout`, `rejected`, …).

Take the receiver before draining the stream; an undrained channel silently drops failures once its buffer fills.

## Filters and sorting

[`filter.rs`](examples/filter.rs) composes the stream adapters: keep only anonymous/elite results, bound the response time, sort fastest-first, then take ten.

```rust
stream.filter_levels([Anonymity::Anonymous, Anonymity::Elite])
      .filter_max_response_time(2.0)
      .into_sorted(SortKey::AvgResponseTime, SortOrder::Asc)
      .take(10)
```

Filtering is lazy per item; sorting buffers everything upstream before emitting.

## GeoIP filtering

[`geo.rs`](examples/geo.rs) annotates every result with GeoLite2 data and keeps a single country. `.with_geo()` annotates without filtering; `.countries(["ID"])` filters and implies the lookup. The first run downloads the GeoLite2 database (a few tens of MB); `flx geo-update` refreshes it later.

## Parse-only passthrough

[`passthrough.rs`](examples/passthrough.rs) calls `.no_validate()` to normalize a list without touching the judges: parse, deduplicate, re-emit.

## Builder cheat sheet

Every knob on the `Flx` builder, grouped:

| Group | Methods |
|---|---|
| Source | `fetch`, `from_file(s)`, `providers`, `exclude_providers`, `source_urls`, `offline`, `cache_ttl`, `refresh_cache`, `fetch_concurrency`, `fetch_delay`, `provider_timeout`, `fallback_threshold`, `fetch_phase_timeout` |
| Validation | `types`, `groups`, `validate_http`, `no_validate`, `concurrency`, `timeout`, `max_attempts`, `retry_delay`, `http_judges`, `https_judges`, `insecure`, `support_cookies`, `support_referer`, `probe_missed_types`, `report_failures` |
| GeoIP | `with_geo`, `with_ip_type`, `ip_type`, `countries` |
| Output | `limit` |
| Terminal | `stream`, `stream_with_progress`, `collect` |

## License

MIT — see [LICENSE](../LICENSE).
