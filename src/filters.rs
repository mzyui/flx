//! Post-validation filtering and ordering of proxy streams, shared by the
//! library API and the CLI.

use std::{pin::Pin, sync::Arc, task::Poll};

use futures_util::Stream;

use crate::proxy::models::{Anonymity, Protocol, Proxy};

/// Field a buffered sort orders by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    /// Aggregated average response time, fastest first when ascending.
    AvgResponseTime,
    /// GeoIP country code.
    Country,
    /// Best anonymity rank across validated types.
    Anonymity,
}

/// Direction a buffered sort applies to its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

/// Sorts proxies in place by `key`.
///
/// The CLI maps its string flags onto this; the stream API exposes it via
/// [`ProxyStreamExt::into_sorted`].
pub fn sort_proxies(proxies: &mut [Proxy], key: SortKey, order: SortOrder) {
    match key {
        SortKey::AvgResponseTime => proxies.sort_by(|a, b| {
            a.avg_response_time()
                .partial_cmp(&b.avg_response_time())
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        SortKey::Country => proxies.sort_by(|a, b| a.geo.iso_code.cmp(&b.geo.iso_code)),
        SortKey::Anonymity => proxies.sort_by_key(proxy_anonymity_rank),
    }
    if order == SortOrder::Desc {
        proxies.reverse();
    }
}

const XSHIFT_GOLDEN: u64 = 0x9e3779b97f4a7c15;

/// Fisher-Yates shuffle driven by a xorshift64 PRNG seeded from wall-clock
/// time and the pid: one flag does not justify a `rand` dependency.
pub fn shuffle_proxies(proxies: &mut [Proxy]) {
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(XSHIFT_GOLDEN)
        ^ u64::from(std::process::id());
    if state == 0 {
        state = XSHIFT_GOLDEN;
    }
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in (1..proxies.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        proxies.swap(i, j);
    }
}

/// Best anonymity rank across a proxy's validated types; types without an
/// anonymity level (SOCKS, CONNECT) count as `Unknown`.
pub fn proxy_anonymity_rank(proxy: &Proxy) -> u8 {
    proxy
        .proxy_types
        .iter()
        .filter_map(|proxy_type| match proxy_type.protocol {
            Protocol::Http(anonymity) | Protocol::Https(anonymity) => Some(anonymity.rank()),
            _ => None,
        })
        .max()
        .unwrap_or_else(|| Anonymity::Unknown.rank())
}

/// Maps any protocol to the anonymity-agnostic form of its family, so an
/// exclude-type filter naming `HTTP` also drops `HTTP:Elite` results.
pub fn protocol_family(protocol: Protocol) -> Protocol {
    match protocol {
        Protocol::Http(_) => Protocol::Http(Anonymity::Unknown),
        Protocol::Https(_) => Protocol::Https(Anonymity::Unknown),
        other => other,
    }
}

fn is_excluded(excluded: &[Protocol], proxy: &Proxy) -> bool {
    if excluded.is_empty() {
        return false;
    }
    // Proxies without validated results are judged on their advertised set.
    let types: Vec<Protocol> = if proxy.proxy_types.is_empty() {
        proxy.expected_types.to_vec()
    } else {
        proxy.proxy_types.iter().map(|pt| pt.protocol).collect()
    };
    types.iter().any(|protocol| {
        excluded
            .iter()
            .any(|excluded| protocol_family(*excluded) == protocol_family(*protocol))
    })
}

/// Composable post-validation filters and buffered ordering over any
/// `Stream<Item = Proxy>`, delivered via a blanket impl.
///
/// Filtering is lazy per item; [`into_sorted`](ProxyStreamExt::into_sorted)
/// and [`shuffled`](ProxyStreamExt::shuffled) must buffer the whole upstream
/// before emitting anything — an O(n) cost the names make explicit.
pub trait ProxyStreamExt: Stream<Item = Proxy> + Sized {
    /// Keeps proxies whose best anonymity rank reaches `min`. SOCKS and
    /// CONNECT count as `Anonymity::Unknown` (the highest rank).
    fn filter_min_anonymity(self, min: Anonymity) -> Filtered<Self> {
        let min_rank = min.rank();
        Filtered::new(self, move |proxy| proxy_anonymity_rank(proxy) >= min_rank)
    }

    /// Keeps proxies with at least one HTTP/HTTPS type whose anonymity is in
    /// `levels`.
    fn filter_levels(self, levels: impl IntoIterator<Item = Anonymity>) -> Filtered<Self> {
        let levels: Arc<[Anonymity]> = levels.into_iter().collect();
        Filtered::new(self, move |proxy| {
            proxy.proxy_types.iter().any(|proxy_type| {
                matches!(
                    proxy_type.protocol,
                    Protocol::Http(anonymity) | Protocol::Https(anonymity)
                        if levels.contains(&anonymity)
                )
            })
        })
    }

    /// Keeps proxies whose average response time is at least `seconds`.
    fn filter_min_response_time(self, seconds: f64) -> Filtered<Self> {
        Filtered::new(self, move |proxy| proxy.avg_response_time() >= seconds)
    }

    /// Keeps proxies whose average response time is at most `seconds`.
    fn filter_max_response_time(self, seconds: f64) -> Filtered<Self> {
        Filtered::new(self, move |proxy| proxy.avg_response_time() <= seconds)
    }

    /// Drops proxies matching any excluded protocol family. Unvalidated
    /// proxies fall back to their advertised types, mirroring the CLI.
    fn exclude_types(self, excluded: impl IntoIterator<Item = Protocol>) -> Filtered<Self> {
        let excluded: Arc<[Protocol]> = excluded.into_iter().collect();
        Filtered::new(self, move |proxy| !is_excluded(&excluded, proxy))
    }

    /// Buffers everything upstream, sorts by `key`, then emits the result.
    fn into_sorted(self, key: SortKey, order: SortOrder) -> BufferedStream<Self> {
        BufferedStream::new(self, Finish::Sort(key, order))
    }

    /// Buffers everything upstream, shuffles it, then emits the result.
    fn shuffled(self) -> BufferedStream<Self> {
        BufferedStream::new(self, Finish::Shuffle)
    }
}

impl<T: Stream<Item = Proxy>> ProxyStreamExt for T {}

/// A stream adapter applying a synchronous per-item predicate.
pub struct Filtered<S> {
    inner: Pin<Box<S>>,
    predicate: Box<dyn Fn(&Proxy) -> bool>,
}

impl<S: Stream<Item = Proxy>> Filtered<S> {
    fn new(inner: S, predicate: impl Fn(&Proxy) -> bool + 'static) -> Self {
        Self {
            inner: Box::pin(inner),
            predicate: Box::new(predicate),
        }
    }
}

impl<S: Stream<Item = Proxy>> Stream for Filtered<S> {
    type Item = Proxy;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            break match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(proxy)) => {
                    if (this.predicate)(&proxy) {
                        Poll::Ready(Some(proxy))
                    } else {
                        continue;
                    }
                }
                other => other,
            };
        }
    }
}

enum Finish {
    Sort(SortKey, SortOrder),
    Shuffle,
}

enum BufferedState {
    Collecting(Finish, Vec<Proxy>),
    Emitting(std::vec::IntoIter<Proxy>),
}

/// Stream adapter that buffers its upstream before re-emitting.
pub struct BufferedStream<S> {
    inner: Pin<Box<S>>,
    state: BufferedState,
}

impl<S: Stream<Item = Proxy>> BufferedStream<S> {
    fn new(inner: S, finish: Finish) -> Self {
        Self {
            inner: Box::pin(inner),
            state: BufferedState::Collecting(finish, Vec::new()),
        }
    }
}

impl<S: Stream<Item = Proxy>> Stream for BufferedStream<S> {
    type Item = Proxy;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                BufferedState::Collecting(_, _) => match this.inner.as_mut().poll_next(cx) {
                    Poll::Ready(Some(proxy)) => {
                        if let BufferedState::Collecting(_, buffer) = &mut this.state {
                            buffer.push(proxy);
                        }
                    }
                    Poll::Ready(None) => {
                        let BufferedState::Collecting(finish, mut buffer) = std::mem::replace(
                            &mut this.state,
                            BufferedState::Emitting(Vec::new().into_iter()),
                        ) else {
                            unreachable!("state checked above");
                        };
                        match finish {
                            Finish::Sort(key, order) => sort_proxies(&mut buffer, key, order),
                            Finish::Shuffle => shuffle_proxies(&mut buffer),
                        }
                        this.state = BufferedState::Emitting(buffer.into_iter());
                    }
                    Poll::Pending => return Poll::Pending,
                },
                BufferedState::Emitting(items) => return Poll::Ready(items.next()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        protocol_family, proxy_anonymity_rank, sort_proxies, ProxyStreamExt, SortKey, SortOrder,
    };
    use crate::proxy::models::{Anonymity, Protocol, Proxy, ProxyType};
    use futures_util::{stream, StreamExt as _};

    fn proxy(ip: u8) -> Proxy {
        Proxy::new(Ipv4Addr::new(10, 0, 0, ip), 8080 + u16::from(ip))
    }

    fn validated(ip: u8, protocol: Protocol, response_time: f64) -> Proxy {
        let mut proxy = proxy(ip);
        proxy.proxy_types.push(ProxyType::checked(protocol));
        proxy.runtimes.record(response_time);
        proxy
    }

    fn country(ip: u8, iso_code: &str) -> Proxy {
        let mut proxy = proxy(ip);
        let mut geo = (*proxy.geo).clone();
        geo.iso_code = Some(iso_code.into());
        proxy.geo = std::sync::Arc::new(geo);
        proxy
    }

    async fn collect<S: futures_util::Stream<Item = Proxy>>(stream: S) -> Vec<Proxy> {
        stream.collect::<Vec<_>>().await
    }

    #[test]
    fn rank_treats_socks_and_connect_as_unknown() {
        assert_eq!(proxy_anonymity_rank(&proxy(1)), Anonymity::Unknown.rank());
        let socks = validated(1, Protocol::Socks5, 0.1);
        assert_eq!(proxy_anonymity_rank(&socks), Anonymity::Unknown.rank());
        let elite = validated(1, Protocol::Http(Anonymity::Elite), 0.1);
        assert_eq!(proxy_anonymity_rank(&elite), Anonymity::Elite.rank());
    }

    #[test]
    fn family_erases_anonymity_within_http_and_https() {
        assert_eq!(
            protocol_family(Protocol::Http(Anonymity::Elite)),
            Protocol::Http(Anonymity::Unknown)
        );
        assert_eq!(protocol_family(Protocol::Socks5), Protocol::Socks5);
    }

    #[tokio::test]
    async fn min_anonymity_filter_keeps_unknown_ranked_proxies() {
        // Unknown (SOCKS/CONNECT) ranks highest on purpose; see AGENTS invariants.
        let proxies = vec![
            validated(1, Protocol::Http(Anonymity::Transparent), 0.1),
            validated(2, Protocol::Http(Anonymity::Elite), 0.1),
            validated(3, Protocol::Socks5, 0.1),
        ];
        let kept = collect(stream::iter(proxies).filter_min_anonymity(Anonymity::Elite)).await;
        // Elite (rank 2) and SOCKS/CONNECT-as-Unknown (rank 3) survive; only
        // Transparent falls below the bar.
        assert_eq!(
            kept.iter().map(|p| p.port).collect::<Vec<_>>(),
            [8082, 8083]
        );
    }

    #[tokio::test]
    async fn levels_filter_matches_only_named_anonymities() {
        let proxies = vec![
            validated(1, Protocol::Http(Anonymity::Transparent), 0.1),
            validated(2, Protocol::Https(Anonymity::Anonymous), 0.1),
            validated(3, Protocol::Socks5, 0.1),
        ];
        let kept =
            collect(stream::iter(proxies).filter_levels([Anonymity::Anonymous, Anonymity::Elite]))
                .await;
        assert_eq!(kept.iter().map(|p| p.port).collect::<Vec<_>>(), [8082]);
    }

    #[tokio::test]
    async fn response_time_filters_bound_both_ends() {
        let slow = validated(1, Protocol::Socks5, 5.0);
        let fast = validated(2, Protocol::Socks5, 0.05);
        let middle = validated(3, Protocol::Socks5, 1.0);
        let kept = collect(
            stream::iter(vec![slow, fast, middle])
                .filter_min_response_time(0.5)
                .filter_max_response_time(2.0),
        )
        .await;
        assert_eq!(kept.iter().map(|p| p.port).collect::<Vec<_>>(), [8083]);
    }

    #[tokio::test]
    async fn exclude_types_falls_back_to_advertised_types() {
        let mut unvalidated = proxy(4);
        unvalidated.expected_types =
            std::sync::Arc::from([Protocol::Http(Anonymity::Unknown), Protocol::Socks5]);
        let http_validated = validated(1, Protocol::Http(Anonymity::Elite), 0.1);
        let socks_validated = validated(2, Protocol::Socks5, 0.1);

        let kept = collect(
            stream::iter(vec![http_validated, socks_validated, unvalidated])
                .exclude_types([Protocol::Http(Anonymity::Elite)]),
        )
        .await;
        let ports: Vec<u16> = kept.iter().map(|p| p.port).collect();
        assert!(!ports.contains(&8081));
        assert!(
            !ports.contains(&8084),
            "advertised HTTP must be excluded too"
        );
        assert!(ports.contains(&8082));
    }

    #[tokio::test]
    async fn into_sorted_buffers_and_orders() {
        let proxies = vec![
            validated(1, Protocol::Socks5, 3.0),
            validated(2, Protocol::Socks5, 0.1),
            validated(3, Protocol::Socks5, 1.0),
        ];
        let sorted =
            collect(stream::iter(proxies).into_sorted(SortKey::AvgResponseTime, SortOrder::Asc))
                .await;
        let times: Vec<f64> = sorted.iter().map(|p| p.avg_response_time()).collect();
        let mut expected = times.clone();
        expected.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(times, expected);
    }

    #[test]
    fn sort_desc_reverses_ascending_order() {
        let mut proxies = vec![
            validated(1, Protocol::Socks5, 3.0),
            validated(2, Protocol::Socks5, 0.1),
            validated(3, Protocol::Socks5, 1.0),
        ];
        sort_proxies(&mut proxies, SortKey::AvgResponseTime, SortOrder::Desc);
        assert!(proxies[0].avg_response_time() >= proxies[2].avg_response_time());

        let by_country = vec![country(1, "US"), country(2, "ID")];
        let mut by_country = by_country;
        sort_proxies(&mut by_country, SortKey::Country, SortOrder::Asc);
        assert_eq!(
            by_country
                .iter()
                .map(|p| p.geo.iso_code.clone())
                .collect::<Vec<_>>(),
            [Some(Box::<str>::from("ID")), Some(Box::<str>::from("US"))]
        );

        let mut by_rank = vec![
            validated(1, Protocol::Http(Anonymity::Transparent), 0.1),
            validated(2, Protocol::Socks5, 0.1),
            validated(3, Protocol::Http(Anonymity::Elite), 0.1),
        ];
        sort_proxies(&mut by_rank, SortKey::Anonymity, SortOrder::Asc);
        assert_eq!(by_rank[2].port, 8082, "unknown rank sorts last ascending");
    }

    #[tokio::test]
    async fn shuffled_preserves_every_proxy() {
        let proxies: Vec<Proxy> = (0..32u8)
            .map(|ip| validated(ip, Protocol::Socks5, f64::from(ip) / 100.0))
            .collect();
        let mut before: Vec<String> = proxies.iter().map(|p| p.as_text().to_owned()).collect();
        let shuffled = collect(stream::iter(proxies).shuffled()).await;
        let mut after: Vec<String> = shuffled.iter().map(|p| p.as_text().to_owned()).collect();

        before.sort();
        after.sort();
        assert_eq!(before, after, "shuffle is a permutation");
    }
}
