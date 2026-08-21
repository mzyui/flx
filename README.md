<div align="center">
  <img src="https://socialify.git.ci/mzyui/flx/image?description=1&font=Source+Code+Pro&forks=1&issues=1&language=1&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Auto"></img>
</div>

Flx is a Rust proxy scraper and validator. It pulls candidates from 17 sources (16 primary sites plus a GitHub mirror fallback), verifies them against online judges that must echo a unique token, and lets you filter the results by protocol, anonymity, country, IP type, and response time before exporting them in one of nine formats.

## Install

```bash
cargo install --git https://github.com/mzyui/flx
```

## Demo

Live recording of a real run against the built-in providers.

![flx demo](assets/demo.gif)

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

Suggestions and bug reports: https://github.com/mzyui/flx/issues