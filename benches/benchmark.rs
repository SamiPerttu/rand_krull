use criterion::{criterion_group, criterion_main, Criterion};

use rand_krull::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut krull1 = Krull64::new();
    c.bench_function("Krull64::step", move |b| b.iter(|| krull1.step()));
    let mut krull2 = Krull64::new();
    c.bench_function("Krull64::step_slow", move |b| b.iter(|| krull2.step_slow()));
    let mut krull3 = Krull65::new();
    c.bench_function("Krull65::step", move |b| b.iter(|| krull3.step()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
