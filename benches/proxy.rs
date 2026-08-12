use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluxy::proxy::models::Proxy;
use fluxy::validator::checker::classify_anonymity;
use std::net::Ipv4Addr;

fn bench_classify_anonymity(c: &mut Criterion) {
    let my_ip = "192.168.1.100";
    let transparent_body = format!("REMOTE_ADDR = {my_ip}\nHTTP_VIA = proxy\n");
    let anonymous_body = "HTTP_VIA = 1.1 proxy\nHTTP_X_FORWARDED_FOR = 10.0.0.1\n";
    let elite_body = "no leak tokens here\njust some random text\n";

    c.bench_function("classify_anonymity_transparent", |b| {
        b.iter(|| {
            let result = classify_anonymity(black_box(&transparent_body), black_box(my_ip));
            black_box(result);
        })
    });

    c.bench_function("classify_anonymity_anonymous", |b| {
        b.iter(|| {
            let result = classify_anonymity(black_box(anonymous_body), black_box(my_ip));
            black_box(result);
        })
    });

    c.bench_function("classify_anonymity_elite", |b| {
        b.iter(|| {
            let result = classify_anonymity(black_box(elite_body), black_box(my_ip));
            black_box(result);
        })
    });
}

fn bench_proxy_as_json(c: &mut Criterion) {
    let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 1), 8080);
    proxy.runtimes.record(0.123);
    proxy.runtimes.record(0.456);

    c.bench_function("proxy_as_json", |b| {
        b.iter(|| {
            let json = black_box(&proxy).as_json();
            black_box(json);
        })
    });
}

criterion_group!(benches, bench_classify_anonymity, bench_proxy_as_json);
criterion_main!(benches);
