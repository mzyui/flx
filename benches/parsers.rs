use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluxy::providers::parsers::visit_plaintext;

fn large_plaintext_body() -> String {
    let mut body = String::with_capacity(5 * 1024 * 1024);
    for i in 0..80_000u32 {
        let a = (i >> 24) as u8;
        let b = (i >> 16) as u8;
        let c = (i >> 8) as u8;
        let d = i as u8;
        let port = 1024 + (i % 60000) as u16;
        body.push_str(&format!("{a}.{b}.{c}.{d}:{port}\n"));
    }
    body
}

fn bench_visit_plaintext(c: &mut Criterion) {
    let body = large_plaintext_body();
    c.bench_function("visit_plaintext_5mb", |b| {
        b.iter(|| {
            let mut count = 0usize;
            visit_plaintext(black_box(&body), |_row| {
                count += 1;
                true
            });
            black_box(count);
        })
    });
}

criterion_group!(benches, bench_visit_plaintext);
criterion_main!(benches);
