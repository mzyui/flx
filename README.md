<div align="center">
  <img src="https://socialify.git.ci/mzyui/flx/image?description=1&font=Source+Code+Pro&forks=1&issues=1&language=1&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Auto"></img>
</div>

flx is a fast proxy scraper & validator written in Rust. It collects free proxies from 13 sources, validates them against online judges (HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT), filters by anonymity / country / IP type / response time, and exports in 9 formats. It ships as both a CLI (`flx`) and a Rust library.

## Demo

![demo](https://vhs.charm.sh/vhs-3tm46j5tEl6LYWePbsAuOw.gif)

## Features

- **Scrape** from 12 primary providers + GitHub raw mirrors, or plug in your own plaintext source
- **Validate** with end-to-end deadlines over hand-rolled hyper + rustls networking — anti-replay judge tokens keep fake judges out
- **Filter & sort** by protocol, anonymity level, country, IP type (residential / datacenter / mobile), and response time
- **GeoIP** via GeoLite2 City + ASN, with a one-command database sync
- **9 output formats** including JSON, CSV, PAC, and proxychains config
- **Streaming-first pipeline** with backpressure, atomic parse cache, and graceful Ctrl+C finalization
- **Proxy rotating server** — expose validated proxies through a local rotating endpoint (`flx serve`)

## Install

```bash
cargo install --git https://github.com/mzyui/flx
```

Or build from source (requires `pkg-config` and `libssl-dev`):

```bash
git clone https://github.com/mzyui/flx
cd flx
cargo install --path .
```

## Scrape

Scrape without validating, or render the results straight to a file. `-o` infers the format from the file extension.

```bash
flx grab -l 20
flx grab -f json -o proxies.json
```

## Validate

Validate proxies scraped from the providers, read from a file, or piped in from stdin (`--files`, `-` reads stdin). Plain `flx find` defaults to HTTP checks.

```bash
flx find -l 5
flx find -f proxies.txt
cat list.txt | flx find -f -
```

## Serve (beta)

Expose the validated pool as a local rotating proxy: point any client at the endpoint and every connection is forwarded through a different working proxy. Start it like `find` — every validation flag (`-a`, `-c`, `-m`, `--timeout`, protocol types, ...) applies — and the endpoint keeps revalidating in the background, rotating round-robin (default) or randomly and dropping proxies that die.

```bash
flx serve                                    # 127.0.0.1:8080, round-robin
flx serve --port 9000 --strategy random      # random rotation
flx serve --pool-size 200 --refresh-secs 120 # larger pool, faster revalidation
flx serve --auth user:pass                   # require basic proxy authentication
```

## Protocol types

Pick the types to validate: HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT:80, CONNECT:25. Combine types with `+` and annotate anonymity with a colon (HTTP:Elite).

```bash
flx find -f proxies.txt HTTP SOCKS5 HTTPS
flx find HTTP+HTTPS HTTP:Elite
```

## Output formats

Nine formats: `text`, `json`, `json-lines`, `pretty-json`, `csv`, `prefix`, `pac`, `proxychains`, and the human-readable default.

```bash
flx find -l 5 -f json
flx find -l 5 -f csv | column -t -s,
flx find -l 5 -f proxychains > /etc/proxychains.conf
flx find -l 5 -f pac -o proxy.pac
```

## Filters and sorting

Keep only the proxies that fit: minimum anonymity, response-time windows, excluded types, or a sort order.

```bash
flx find -a elite --levels anonymous elite
flx find --max-response-time 2 --min-response-time 0.1 --exclude-type SOCKS4
flx find -s response-time --order desc --shuffle
```

## GeoIP and IP type

`-c` filters by country and `-g` annotates without filtering; `geo-update` refreshes the GeoLite2 database. Classify endpoints as residential, datacenter, or mobile.

```bash
flx geo-update
flx find -c US,DE --exclude-country RU,CN -l 5
flx find --ip-type residential --with-ip-type
```

## Providers and cache

Choose or skip providers, add your own plaintext source, or run entirely from the local cache.

```bash
flx find --list-providers
flx find -p geonode,proxyscrape --exclude-provider github-raw
flx find --source-url https://example.com/proxies.txt
flx find --offline --cache-ttl 30 --refresh-cache
```

## Tuning and strict checks

Tune the validation throughput, require cookie/referer forwarding, disable TLS verification, and log every failure to a JSON-lines report.

```bash
flx find -m 1000 --timeout 5 --max-attempts 3
flx find --support-cookies --support-referer --no-verify-tls
flx find --report-failures failures.jsonl
```

## Config file

Persist your defaults in TOML. CLI flags always win over the config, and a project `.flx.toml` overrides the user config key-by-key.

```bash
flx config init                 # write a commented template to ~/.config/flx/config.toml
flx config wizard               # interactively set up a config file
flx config wizard --yes         # write one with every default (no questions)
flx config path                 # show which files are in effect
flx config show                 # print the merged configuration
flx --config ./custom.toml find # use one specific file (or $FLX_CONFIG)
flx --no-config find            # ignore every config file
```

The user config lives at `$XDG_CONFIG_HOME/flx/config.toml` (default `~/.config/flx/config.toml`); a `.flx.toml` in the current directory overrides it. Loaded even for `grab`; `--verbose` overrides a `quiet = true` set by the config.

## Library usage

flx is also a library. The `Flx` builder mirrors the CLI defaults:

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

Requires a Rust toolchain (edition 2021); TLS is pure-Rust (rustls), no OpenSSL dependency.

```bash
cargo build                              # build library + binary
cargo test                               # run the test suite (~283 tests)
cargo clippy --all-targets --all-features
cargo fmt
cargo bench                              # criterion benchmarks (parsers, proxy)
```

## Contributing

PRs and issue reports are welcome. Before submitting a PR, make sure:

- `cargo test` passes (the suite needs `pkg-config` and `libssl-dev`)
- `cargo clippy --all-targets --all-features` is warning-free
- `cargo fmt --check` is clean

A few conventions to keep in mind: name constants instead of magic numbers, keep per-source/per-proxy failures non-fatal (log and continue), compile regexes/selectors once in statics, and add offline tests (`TcpListener` on port 0, no external network) for any new or changed behavior.

## License

MIT — see [LICENSE](LICENSE).

