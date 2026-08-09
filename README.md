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
 fluxy -t HTTP -l 10 --log debug -f json
fluxy::fetcher: DEBUG Proxy gathering started (27 sources)
fluxy::validator: DEBUG Proxy validator started (500 workers)
fluxy::resolver: DEBUG My IP: 114.10.152.29 (resolved in 47.73877ms)

[
  {"ip":"65.1.244.232","port":80,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.032629307749999996,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.729317}},
  {"ip":"52.196.1.182","port":80,"geo":{"iso_code":"JP","name":"Japan","region_iso_code":"13","region_name":"Tokyo","city_name":"Tokyo"},"average_response_time":0.04735451925,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.7895415}},
  {"ip":"3.37.125.76","port":3128,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"28","region_name":"Incheon","city_name":"Incheon"},"average_response_time":0.051829942500000004,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8131318}},
  {"ip":"43.200.77.128","port":3128,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"28","region_name":"Incheon","city_name":"Incheon"},"average_response_time":0.04032374975,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8233922}},
  {"ip":"13.208.56.180","port":80,"geo":{"iso_code":"JP","name":"Japan","region_iso_code":"27","region_name":"Osaka","city_name":"Osaka"},"average_response_time":0.05889850025,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8411582}},
  {"ip":"3.108.115.48","port":1080,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.071890385,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.880884}},
  {"ip":"35.79.120.242","port":3128,"geo":{"iso_code":"JP","name":"Japan","region_iso_code":"13","region_name":"Tokyo","city_name":"Tokyo"},"average_response_time":0.05932753875,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8997948}},
  {"ip":"43.202.154.212","port":80,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"28","region_name":"Incheon","city_name":"Incheon"},"average_response_time":0.0605324615,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.9165545}},
  {"ip":"13.234.24.116","port":1080,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.09377788449999999,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798626.034847}},
  {"ip":"15.206.25.41","port":3128,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.11225623075,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798626.055605}}
]

fluxy::validator: DEBUG Proxy validator completed: 10/10542 proxies validated (1.281753231s)
fluxy::fetcher: DEBUG Proxy gathering completed: 19946 proxies found (1.488841769s)
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
