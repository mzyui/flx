<div align="center">
  <img src="https://socialify.git.ci/zevtyardt/fluxy/image?description=1&font=Source+Code+Pro&forks=1&issues=1&language=1&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Auto"></img>
</div>

---

**Fluxy** (pronounced `flox-si`) is the exciting successor to `proxy.rs`. Currently in its early development stages, Fluxy is set to revolutionize proxy management.

#### Example 📝

> [!NOTE]
> GeoIP lookup is opt-in. Fluxy downloads the MaxMind database on first use.
> `--countries` enables lookup **and** filters by ISO country code;
> `--with-geo` enables the lookup only, annotating every proxy with its country
> in the output without filtering.

Here's the debug output showing the proxy validator process:

```sh
fluxy -t HTTP -l 3 --with-geo --log debug -f json
fluxy::fetcher: DEBUG Proxy gathering started (40 primary sources, 31 fallback sources)
fluxy::validator: DEBUG Proxy validator started (500 workers)
fluxy::validator: INFO using 1 healthy HTTP judge(s)
fluxy::resolver: DEBUG My IP: 182.9.1.23 (loaded from cache)

[
  {"ip":"103.106.241.74","port":8080,"geo":{"iso_code":"BD","name":"Bangladesh","region_iso_code":null,"region_name":null,"city_name":null},"average_response_time":1.047709538,"type":{"protocol":{"Http":"Transparent"},"checked_on":1786278305.2077749}},
  {"ip":"103.208.103.6","port":8080,"geo":{"iso_code":"ID","name":"Indonesia","region_iso_code":null,"region_name":null,"city_name":null},"average_response_time":0.988683692,"type":{"protocol":{"Http":"Transparent"},"checked_on":1786278305.433337}},
  {"ip":"1.231.81.166","port":3128,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"11","region_name":"Seoul","city_name":"Jongno-gu"},"average_response_time":1.5939489999999998,"type":{"protocol":{"Http":"Transparent"},"checked_on":1786278305.6440628}}
]

fluxy::validator: INFO Proxy validator completed: 3/748 proxies validated (2.267563077s)
fluxy::fetcher: DEBUG Proxy gathering completed: 748 proxies found (2.27s)
```

## Public judge for end-to-end validation

HTTP, HTTPS/CONNECT, SOCKS4, and SOCKS5 validation uses preflighted online judge
pools. Every candidate must echo Fluxy's unique `X-Fluxy-Token`; unhealthy or
incompatible candidates are removed before validation starts, and healthy judges
are selected round-robin.

Preflight is streaming: validation begins as soon as the first judge passes,
while the remaining candidates finish preflighting in the background — a dead
judge no longer holds up startup until its timeout.

The built-in defaults work without a local judge binary or shared secret:

```sh
cargo run --release --bin fluxy -- \
  -t HTTP HTTPS SOCKS4 SOCKS5 \
  --timeout 5
```

Custom pools can be supplied with comma-separated `--http-judge-urls` and
`--https-judge-urls`. HTTPS certificate validation is enabled by default. Use
`--insecure` only for an explicitly trusted self-signed judge; HTTP judges do not
provide transport authentication and should be treated accordingly.

## Provider source cache

Fetching every proxy list is the slowest part of startup. Fluxy caches each
source body under the platform data dir and reuses it within a freshness window,
so repeat runs skip most of the network startup cost.

- `--cache-ttl <minutes>` — reuse cached source bodies within this window
  (default `15`; `0` disables the cache entirely).
- `--refresh-cache` — ignore the cache and fetch every source again; the freshly
  fetched bodies still repopulate the cache.

The public IP used for anonymity classification is cached to disk for 24 hours
the same way, so DNS/HTTPS discovery runs at most once per day.
