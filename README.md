<div align="center">
  <img src="https://socialify.git.ci/mzyui/flx/image?description=1&font=Source+Code+Pro&forks=1&issues=1&language=1&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Auto"></img>
</div>

```bash
cargo install --git https://github.com/mzyui/flx
```

```bash
root@hermes ~# flx find -l 5
<Proxy -- 0.31s [HTTP: Anonymous] 8.215.112.240:7777>
<Proxy -- 0.45s [HTTP: Elite] 165.154.7.156:8888>
<Proxy -- 0.93s [HTTP: Elite] 51.159.97.242:10006>
<Proxy -- 1.02s [HTTP: Elite] 151.115.99.193:10006>
<Proxy -- 1.06s [HTTP: Anonymous] 34.134.231.117:3129>

5 valid · 63 failed · 568 checked in 1.075870154s (527.9/s)
```

## Gateway serve

`flx serve` runs a local forward-proxy gateway backed by the fetched and
validated pool. Each client session is pinned to one upstream proxy, so the
exit IP stays stable for the session.

```bash
flx serve --port 8080                # fetch + validate, then proxy on 127.0.0.1:8080
flx serve --file proxies.txt --port 8080
flx serve --auth user:pass --host 0.0.0.0 --port 3128
```

Supported: CONNECT tunnels (HTTP/HTTPS/SOCKS4/SOCKS5 upstreams) and plain
HTTP forwarding with keep-alive reuse, chunked bodies, `Expect: 100-continue`,
and `101` upgrade handoff. Use `flx serve --help` for the full flag list
(`--session`, `--session-timeout`, `--refresh`, `--use-fastest`,
`--max-sessions`, `--max-clients`, `--pool-size`, `--pool-wait`).
