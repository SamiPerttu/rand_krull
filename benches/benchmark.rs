use criterion::{criterion_group, criterion_main, Criterion};

use rand_krull::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut kr1 = Krull64::new();
    c.bench_function("Krull64::next", move |b| b.iter(|| kr1.next()));
    let mut kr2 = Krull64::new();
    c.bench_function("Krull64::next_128", move |b| b.iter(|| kr2.next_128()));
    let mut kr3 = Krull65::new();
    c.bench_function("Krull65::next", move |b| b.iter(|| kr3.next()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
