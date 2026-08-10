use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ProviderTier, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

/// A provider for fetching proxy lists from GitHub repositories.
///
/// Historically the highest-yield provider in the reference `mzyui/proxy-list`
/// engine, contributing roughly 97% of unique proxies there. That figure is not
/// computed here and depends on external source availability and timing.
pub struct GithubRepoProvider;

/// `(path after raw.githubusercontent.com, protocol)` for every tracked list.
///
/// Ported from `mzyui/proxy-list` (engine/src/providers/github-raw.js). Sources
/// that contributed 0% unique entries there (clarketm/proxy-list, iplocate's
/// combined all-proxies.txt) are deliberately excluded here too.
static SOURCES: [(&str, Protocol); 31] = [
    (
        "TheSpeedX/PROXY-List/master/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    ("TheSpeedX/PROXY-List/master/socks4.txt", Protocol::Socks4),
    ("TheSpeedX/PROXY-List/master/socks5.txt", Protocol::Socks5),
    (
        "monosans/proxy-list/main/proxies/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "monosans/proxy-list/main/proxies/socks4.txt",
        Protocol::Socks4,
    ),
    (
        "monosans/proxy-list/main/proxies/socks5.txt",
        Protocol::Socks5,
    ),
    (
        "proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
        Protocol::Socks4,
    ),
    (
        "proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        Protocol::Socks5,
    ),
    ("hookzof/socks5_list/master/proxy.txt", Protocol::Socks5),
    (
        "ShiftyTR/Proxy-List/master/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "ErcinDedeoglu/proxies/main/proxies/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "ErcinDedeoglu/proxies/main/proxies/socks4.txt",
        Protocol::Socks4,
    ),
    (
        "ErcinDedeoglu/proxies/main/proxies/socks5.txt",
        Protocol::Socks5,
    ),
    (
        "iplocate/free-proxy-list/main/protocols/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "iplocate/free-proxy-list/main/protocols/https.txt",
        Protocol::Https(Anonymity::Unknown),
    ),
    (
        "iplocate/free-proxy-list/main/protocols/socks4.txt",
        Protocol::Socks4,
    ),
    (
        "iplocate/free-proxy-list/main/protocols/socks5.txt",
        Protocol::Socks5,
    ),
    (
        "zloi-user/hideip.me/main/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    ("zloi-user/hideip.me/main/socks4.txt", Protocol::Socks4),
    ("zloi-user/hideip.me/main/socks5.txt", Protocol::Socks5),
    (
        "roosterkid/openproxylist/main/HTTPS_RAW.txt",
        Protocol::Https(Anonymity::Unknown),
    ),
    (
        "roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        Protocol::Socks4,
    ),
    (
        "roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        Protocol::Socks5,
    ),
    (
        "sunny9577/proxy-scraper/master/proxies.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "databay-labs/free-proxy-list/master/http.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "databay-labs/free-proxy-list/master/socks4.txt",
        Protocol::Socks4,
    ),
    (
        "databay-labs/free-proxy-list/master/socks5.txt",
        Protocol::Socks5,
    ),
    (
        "VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt",
        Protocol::Http(Anonymity::Unknown),
    ),
    (
        "VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt",
        Protocol::Socks4,
    ),
    (
        "VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt",
        Protocol::Socks5,
    ),
];

#[async_trait]
impl ProxyProvider for GithubRepoProvider {
    fn name(&self) -> &'static str {
        "github-raw"
    }

    /// These lists are aggregated mirrors of the other providers, so they run
    /// only after every primary source has been exhausted.
    fn tier(&self) -> ProviderTier {
        ProviderTier::Fallback
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            SOURCES
                .iter()
                .map(|(path, protocol)| {
                    let url = format!("https://raw.githubusercontent.com/{}", path);
                    let source = match protocol {
                        Protocol::Http(_) | Protocol::Https(_) => Source::http(&url),
                        _ => Source::typed(&url, *protocol),
                    };
                    // Some of these lists are multi-megabyte; the 3s default
                    // truncates them mid-download.
                    source.map(|source| source.with_timeout(Duration::from_secs(20)))
                })
                .collect(),
        )
    }
}
