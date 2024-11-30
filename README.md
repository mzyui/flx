## Fluxy 🚀

**Fluxy** (pronounced `flox-si`) is the exciting successor to `proxy.rs`. Currently in its early development stages, Fluxy is set to revolutionize proxy management.

### Goals 🎯

- **Dual Functionality**: Acts as both a library and a CLI tool.
- **Memory Efficiency**: Keeps memory usage below **50 MB** by leveraging Rust's capabilities.
- **Performance Optimization**: A commitment to continuous speed and efficiency improvements.
- **User-Friendly Customization**: Designed for simplicity and ease of customization for all users.

#### Example 📝

In the example below, Fluxy is used to search for 500 unchecked proxies with the specified config:

```rust
let config = ProxyFetcherConfig {
    filters: ProxyFilter {
        countries: vec!["ID".into()],
        types: vec![Protocol::Https],
    },
    ..Default::default()
};
```

#### Debug Output 🖥️

> [!NOTE]
> On the first use, Fluxy automatically downloads **maxminddb** for geo lookup purposes.

Here's the debug output showing the proxy gathering process:

```sh
fluxy::fetcher: DEBUG Proxy gather started. Collecting proxies from 26 sources.
<Proxy ID 0.00s [HTTP, HTTPS, CONNECT:80, CONNECT:25] 14.102.155.202:8080>
<Proxy ID 0.00s [HTTP, HTTPS, CONNECT:80, CONNECT:25] 27.50.29.82:8080>
...
<Proxy ID 0.00s [HTTP, HTTPS, CONNECT:80, CONNECT:25] 36.67.99.31:7023>
<Proxy ID 0.00s [HTTP, HTTPS, CONNECT:80, CONNECT:25] 36.91.135.141:40>
fluxy::fetcher: DEBUG Proxy gather completed in 132.21904ms. 733 proxies were found.
```

Fluxy can discover a proxy in less than **150 ms** (specifically, **132.21904 ms**). ⚡
