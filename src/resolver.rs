use std::{
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use cached::proc_macro::cached;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

#[cached]
pub async fn my_ip() -> String {
    let start_time = Instant::now();
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222))], // OpenDNS server
                53,
                false,
            ),
        ),
        ResolverOpts::default(),
    );

    let my_ip = resolver
        .lookup_ip("myip.opendns.com")
        .await
        .unwrap_or_else(|e| panic!("Failed to lookup IP: {}", e))
        .iter()
        .next()
        .expect ("Failed to get public IP, please check internet connection or create an issue if necessary.");

    #[cfg(feature = "log")]
    log::debug!("My IP: {} (resolved in {:?})", my_ip, start_time.elapsed());
    my_ip.to_string()
}
