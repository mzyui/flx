## Fluxy 🚀

**Fluxy** (pronounced `flox-si`) is the exciting successor to `proxy.rs`. Currently in its early development stages, Fluxy is set to revolutionize proxy management.

### Goals 🎯

- **Dual Functionality**: Acts as both a library and a CLI tool.
- **Memory Efficiency**: Keeps memory usage below **50 MB** by leveraging Rust's capabilities.
- **Performance Optimization**: A commitment to continuous speed and efficiency improvements.
- **User-Friendly Customization**: Designed for simplicity and ease of customization for all users.

### Progress 🔄

On the first use, Fluxy automatically downloads **maxminddb** for geo lookup purposes.

```sh
fluxy::fetcher: DEBUG Proxy gather started. Collecting proxies from 26 sources
Some(
    Proxy {
        ip: 147.75.101.247,
        port: 80,
        geo: GeoData {
            iso_code: Some("NL"),
            name: Some("The Netherlands"),
            region_iso_code: Some("NH"),
            region_name: Some("North Holland"),
            city_name: Some("Amsterdam"),
        },
        avg_response_time: 0.0,
        types: [
            Http(Unknown),
            Https,
            Connect(80),
            Connect(25),
        ],
    },
)
fluxy::fetcher: DEBUG Proxy gather completed in 106.19664ms. 433 proxies were found.
```

Fluxy can discover a proxy in less than **150 ms** (specifically, **106.19664 ms**). ⚡
