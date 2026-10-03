# flx

Fast proxy scraper and validator written in Rust. Scrapes free proxies from 14 providers, validates them against online judges (HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT), filters by anonymity, country, and response time, and exports in 9 formats. Ships as a CLI (`flx`) and a Rust library.

![demo](https://vhs.charm.sh/vhs-3tm46j5tEl6LYWePbsAuOw.gif)

## Quick start

```bash
cargo install --git https://github.com/mzyui/flx
flx geo-update   # one-time GeoIP database download (needed for -c/-g)
flx find -l 20
```

Or grab prebuilt binaries from the [releases page](https://github.com/mzyui/flx/releases) (Linux, macOS, Windows, Android/Termux).

## Features

- Scrape from 12 primary + 2 fallback providers, a file, stdin, or your own plaintext URL
- Validate with end-to-end deadlines over hyper + rustls, with anti-replay judge tokens
- Filter by protocol, anonymity, country, IP type, response time, and persistent health score
- GeoIP via GeoLite2 City + ASN (`flx geo-update` to sync)
- 9 output formats including JSON, CSV, PAC, and proxychains config
- Streaming pipeline with backpressure, parse cache, and graceful Ctrl+C finalization
- Optional interactive TUI (`--tui`, behind the `tui` feature) and rotating proxy server (`flx serve`, behind the `serve` feature, experimental)

## Installation

Requires a Rust toolchain (edition 2021). TLS is pure-Rust (rustls) — no OpenSSL needed.

```bash
cargo install --git https://github.com/mzyui/flx
```

Build from source:

```bash
git clone https://github.com/mzyui/flx
cd flx
cargo install --path .
```

With optional features:

```bash
cargo install --path . --features tui    # interactive --tui flag
cargo install --path . --features serve  # experimental flx serve
```

## Usage

### Scrape

Scrape without validating. `-o` infers the format from the file extension.

```bash
flx grab -l 20
flx grab -f json -o proxies.json
```

### Validate

Validate proxies from the providers, a file, or stdin (`-` reads stdin). Plain `flx find` defaults to HTTP checks.

```bash
flx find -l 5
flx find -f proxies.txt
cat list.txt | flx find -f -
```

### Protocol types

Validate HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT:80, CONNECT:25.

| Syntax   | Meaning                                | Example               |
|----------|----------------------------------------|-----------------------|
| `TYPE`   | validate this protocol                 | `flx find HTTP SOCKS5` |
| `A+B`    | AND-group: endpoint must pass both     | `flx find HTTP+HTTPS` |
| `TYPE:X` | pin anonymity level                    | `flx find HTTP:Elite` |
| `TYPE=n` | cap results for this type (not in `+`) | `flx find HTTP=8 HTTPS=2` |

### Output formats

`text`, `json`, `json-lines`, `pretty-json`, `csv`, `prefix`, `pac`, `proxychains`, and the human-readable `default`.

```bash
flx find -l 5 -f json
flx find -l 5 -f csv | column -t -s,
flx find -l 5 -f proxychains > /etc/proxychains.conf
flx find -l 5 -f pac -o proxy.pac
```

When `-f` is `default`: `-o out.json|jsonl|csv|pac` infers the format from the extension, otherwise a TTY gets the human-readable table and a pipe gets `json-lines`.

### Filters and sorting

```bash
flx find -a elite --levels anonymous elite
flx find --max-response-time 2 --min-response-time 0.1 --exclude-type SOCKS4
flx find -s response-time --order desc --shuffle
flx find --min-score 75 --sort score --order desc
```

### Health scores

`flx` stores probe history by default at `<data-dir>/flx/health/health.jsonl`; use `--health-file` for another path or `--no-health` to disable it. Scores range from 0 to 100:

- Reliability contributes 60% (`successful probes / all probes`).
- Speed contributes 25% and decreases linearly from 100 at 0 seconds to 0 at 5 seconds.
- Best observed HTTP(S) anonymity contributes 15% (`transparent=0`, `anonymous=50`, `elite=100`).

A proxy without history has no score and is excluded by `--min-score`. A score describes previous flx probes, not a guarantee that the proxy is currently available.

### GeoIP

`-c` filters by country, `-g` annotates without filtering. Every lookup also carries ASN data and an IP-type classification (residential / datacenter / mobile).

```bash
flx geo-update
flx find -c US,DE --exclude-country RU,CN -l 5
```

### Providers and cache

12 primary providers (`proxyscrape`, `openproxylist`, `geonode`, `free-proxy-list`, `freeproxy-world`, `proxylist-org`, `my-proxy`, `proxynova`, `hproxy`, `proxydb`, `hidemy.name`, `spys.one`) plus 2 fallbacks (`github-raw`, `stormsia`) used when primaries come up short.

```bash
flx find --list-providers
flx find -p geonode,proxyscrape --exclude-provider github-raw
flx find --source-url https://example.com/proxies.txt
flx find --offline --cache-ttl 30 --refresh-cache
```

### Tuning

```bash
flx find -m 1000 --timeout 5 --max-attempts 3
flx find --support-cookies --support-referer --no-verify-tls
flx find --report-failures failures.jsonl
```

### Interactive TUI

Requires the `tui` Cargo feature (`cargo build --features tui`). Add `--tui` to a `find` or `grab` run to watch it live; all flags apply as usual. Needs an interactive terminal.

```bash
flx find --tui -l 20
flx grab --tui -c US,DE
```

Press `?` inside the TUI for the full keymap (`/` filter, `s`/`S` sort, `Enter` drill-down, `e` export, `Ctrl+C` exit).

### Serve (experimental)

Disabled by default — build with `--features serve` to enable. Exposes the validated pool as a local rotating endpoint; every validation flag applies, and the pool revalidates in the background while dropping dead proxies.

```bash
cargo build --features serve
./target/debug/flx serve --port 8080
./target/debug/flx serve --port 9000 --strategy random --min-ready 10
```

### Config file

Persist defaults in TOML. CLI flags always win; a project `.flx.toml` overrides the user config key-by-key.

```bash
flx config init     # write template to ~/.config/flx/config.toml
flx config wizard   # interactive setup
flx config show     # print merged configuration
flx --config ./custom.toml find
flx --no-config find
```

Minimal example:

```toml
[fetch]
countries = ["US", "DE"]

[output]
format = "json-lines"
limit = 50

[validate]
types = ["HTTP:Elite", "SOCKS5"]
timeout = 5
```

`[output]` also accepts `min_score`, `sort = "score"`, `health_file`, and `no_health`. Run `flx config init` for the full commented template.

## Library usage

The `Flx` builder mirrors the CLI defaults:

```rust
use flx::{Anonymity, Flx, Protocol, SortOrder};

let proxies = Flx::fetch()
    .types([Protocol::Http(Anonymity::Elite)])
    .health_file("./health.jsonl")
    .min_score(75.0)
    .sort_score(SortOrder::Desc)
    .countries(["US", "DE"])
    .limit(20)
    .collect()
    .await?;
```

A guided walkthrough of every sample lives in [`examples/README.md`](examples/README.md).

## Development

```bash
cargo build
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features
cargo fmt
```

## License

flx is licensed under the MIT license. See the [`LICENSE`](LICENSE) file for more information.
