use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ProviderTier, ScrapeMode, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

/// How a GitHub-hosted plaintext feed advertises its proxy protocols.
#[derive(Clone, Copy)]
enum SourceKind {
    Http,
    Typed(Protocol),
    All,
}

struct SourceSpec {
    url: &'static str,
    kind: SourceKind,
}

/// Scrapes GitHub-hosted proxy list mirrors and community feeds.
pub struct GithubRepoProvider;

static SOURCES: [SourceSpec; 45] = [
    SourceSpec {
        url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt",
        kind: SourceKind::Http,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt",
        kind: SourceKind::Typed(Protocol::Http(Anonymity::Unknown)),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/https.txt",
        kind: SourceKind::Typed(Protocol::Https(Anonymity::Unknown)),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxio-io/proxy-list/main/http.txt",
        kind: SourceKind::Typed(Protocol::Http(Anonymity::Unknown)),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxio-io/proxy-list/main/https.txt",
        kind: SourceKind::Typed(Protocol::Https(Anonymity::Unknown)),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://vakhov.github.io/fresh-proxy-list/http.txt",
        kind: SourceKind::Typed(Protocol::Http(Anonymity::Unknown)),
    },
    SourceSpec {
        url: "https://vakhov.github.io/fresh-proxy-list/https.txt",
        kind: SourceKind::Typed(Protocol::Https(Anonymity::Unknown)),
    },
    SourceSpec {
        url: "https://vakhov.github.io/fresh-proxy-list/socks4.txt",
        kind: SourceKind::Typed(Protocol::Socks4),
    },
    SourceSpec {
        url: "https://vakhov.github.io/fresh-proxy-list/socks5.txt",
        kind: SourceKind::Typed(Protocol::Socks5),
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt",
        kind: SourceKind::All,
    },
    SourceSpec {
        url: "https://raw.githubusercontent.com/kael-odin/awesome-free-proxy-list/main/proxies/all.txt",
        kind: SourceKind::All,
    },
];

#[async_trait]
impl ProxyProvider for GithubRepoProvider {
    fn name(&self) -> &'static str {
        "github-raw"
    }

    fn tier(&self) -> ProviderTier {
        ProviderTier::Fallback
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            SOURCES
                .iter()
                .map(|spec| {
                    let source = match spec.kind {
                        SourceKind::Http => Source::http(spec.url),
                        SourceKind::Typed(protocol) => Source::typed(spec.url, protocol),
                        SourceKind::All => Source::all(spec.url),
                    };
                    source.map(|source| {
                        source
                            .with_mode(ScrapeMode::Plaintext)
                            .with_timeout(Duration::from_secs(20))
                    })
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_raw_includes_all_github_hosted_plaintext_sources() {
        let provider = GithubRepoProvider;
        let sources = provider.sources();

        assert_eq!(provider.tier(), ProviderTier::Fallback);
        assert_eq!(sources.len(), 45);
        assert!(sources
            .iter()
            .all(|source| source.mode == ScrapeMode::Plaintext));
        assert!(sources
            .iter()
            .any(|source| source.url.to_string().contains("vakhov.github.io")));
        assert!(sources
            .iter()
            .any(|source| source.url.to_string().contains("theriturajps")));
    }
}
