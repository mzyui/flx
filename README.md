# flx

Fast proxy scraper and validator written in Rust. Collects free proxies from 12 primary providers + GitHub raw mirrors, validates them against online judges (HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT), filters by anonymity, country, IP type, and response time, and exports in 9 formats. Ships as a CLI (`flx`) and a Rust library.

![demo](https://vhs.charm.sh/vhs-3tm46j5tEl6LYWePbsAuOw.gif)

## Features

- Scrape from 12 primary providers + GitHub raw mirrors, or plug in your own plaintext source
- Validate with end-to-end deadlines over hyper + rustls, with anti-replay judge tokens
- Filter and sort by protocol, anonymity level, country, IP type (residential / datacenter / mobile), and response time
- GeoIP via GeoLite2 City + ASN, with a one-command database sync
- 9 output formats including JSON, CSV, PAC, and proxychains config
- Streaming-first pipeline with backpressure, atomic parse cache, and graceful Ctrl+C finalization
- Interactive TUI to watch a `find` or `grab` run live with `--tui` (behind the `tui` feature, optional)
- Optional rotating proxy server (`flx serve`, behind the `serve` feature, experimental)

## Installation

```bash
cargo install --git https://github.com/mzyui/flx
```

Or build from source:

```bash
git clone https://github.com/mzyui/flx
cd flx
cargo install --path .
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

### Interactive TUI (optional)

> [!NOTE]
> Requires the `tui` Cargo feature: `cargo build --features tui` or `cargo install --path . --features tui`. The `--tui` flag is hidden without it.

Add `--tui` to a `find` or `grab` run to watch it live instead of streaming to stdout. All flags apply as usual.

```bash
flx find --tui -l 20
flx grab --tui -c US,DE
```

> [!TIP]
> Press `?` inside the TUI for the full keymap. Move with arrows or `j`/`k`, live-filter with `/` as you type, sort with `s` / `S`, inspect a row with `Enter`, export with `e`, and exit with `Ctrl+C` (press twice to exit after cancelling a live run). Press `Esc` while filtering to restore the previous query.

The TUI uses a minimalist full-width layout: a compact header, a separated status line, a borderless results table, and a contextual footer. At 60–79 columns it hides lower-priority fields; below `60×12` it shows a terminal-size message. Detail is a rich drill-down view opened with `Enter` or `d`, showing endpoint, protocols, location, performance, and recent failure metadata; `Esc` returns without losing the selected row. `e` opens an export-format chooser before asking for the destination path. Mouse scrolling and row selection are optional keyboard-equivalent shortcuts; configuration remains controlled by the normal CLI flags and config file.

> [!NOTE]
> `--tui` needs an interactive terminal and only works with `find` and `grab`. It uses a bounded inline viewport, so the shell scrollback remains visible and the TUI does not switch to the alternate screen.

### Serve (beta)

> [!WARNING]
> Experimental and disabled by default. Build with `cargo build --features serve` to enable it. Release binaries hide `serve` until it stabilizes.

Expose the validated pool as a local rotating endpoint. Every validation flag applies, the pool revalidates in the background and drops dead proxies.

```bash
cargo build --features serve
./target/debug/flx serve --port 8080
flx serve --port 9000 --strategy random --min-ready 10
```

### Protocol types

Validate HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT:80, CONNECT:25. Combine with `+`, pin anonymity with `:`, cap per-type with `=n`.

```bash
flx find -f proxies.txt HTTP SOCKS5 HTTPS
flx find HTTP+HTTPS HTTP:Elite
flx find HTTP=8 HTTPS=2
```

### Output formats

`text`, `json`, `json-lines`, `pretty-json`, `csv`, `prefix`, `pac`, `proxychains`, and the human-readable default.

```bash
flx find -l 5 -f json
flx find -l 5 -f csv | column -t -s,
flx find -l 5 -f proxychains > /etc/proxychains.conf
flx find -l 5 -f pac -o proxy.pac
```

### Filters and sorting

```bash
flx find -a elite --levels anonymous elite
flx find --max-response-time 2 --min-response-time 0.1 --exclude-type SOCKS4
flx find -s response-time --order desc --shuffle
```

### GeoIP

`-c` filters by country, `-g` annotates without filtering. Every lookup also carries ASN data and an IP-type classification.

```bash
flx geo-update
flx find -c US,DE --exclude-country RU,CN -l 5
```

### Providers and cache

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

### Config file

Persist defaults in TOML. CLI flags always win; a project `.flx.toml` overrides the user config key-by-key.

```bash
flx config init     # write template to ~/.config/flx/config.toml
flx config wizard   # interactive setup
flx config show     # print merged configuration
flx --config ./custom.toml find
flx --no-config find
```

## Library usage

The `Flx` builder mirrors the CLI defaults:

```rust
use flx::{Anonymity, Flx, Protocol};

let proxies = Flx::fetch()
    .types([Protocol::Http(Anonymity::Elite)])
    .countries(["US", "DE"])
    .limit(20)
    .collect()
    .await?;
```

A guided walkthrough of every sample lives in [`examples/README.md`](examples/README.md).

## Development

Requires a Rust toolchain (edition 2021). TLS is pure-Rust (rustls).

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features
cargo fmt
```
