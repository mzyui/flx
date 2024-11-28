## Fluxy 🚀

Fluxy, pronounced `flox-si`, is the successor to `proxy.rs`. This project is currently in its early development stages.

#### Goals 🎯

1. **Dual Functionality**: Serve as both a library and a CLI tool.
2. **Memory Efficiency**: Maintain memory usage below 50 MB by leveraging Rust's capabilities.
3. **Performance Optimization**: Continuously improve speed and efficiency.
4. **User-Friendly Customization**: Ensure simplicity and ease of customization for all users.

#### Benchmark 📊
```sh
fluxy::fetcher: DEBUG Proxy gathering started. Collecting proxies from 20 sources.
fluxy: INFO Some(
    Proxy {
        ip: 194.163.153.9,
        port: 3128,
        country: Unknown,
        avg_response_time: 0.0,
        types: [
            Http(Unknown),
            Https,
            Connect(80),
            Connect(25),
        ],
    },
)
fluxy::fetcher: DEBUG Proxy gathering completed in 66.671004ms. 323 proxies were found.
```

Fluxy can discover a proxy in less than 100 ms (specifically, 66.671004 ms) with 13~ MiB total memory usage.

![1000111258](https://github.com/user-attachments/assets/d4e2f52a-f8c6-4613-ac69-602784a90546)
