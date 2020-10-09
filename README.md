# [Krull64/65 Random Number Generators](https://github.com/SamiPerttu/rand_krull)

## Sample with Confidence

- High quality, non-cryptographic, medium-fast [RNGs](https://en.wikipedia.org/wiki/Random_number_generation).
- Designed by Sebastiano Vigna (Krull64) / Sami Perttu (Krull65).
- "Trivially strong" algorithms combining [LCGs](https://en.wikipedia.org/wiki/Linear_congruential_generator) with a strong output hash.
- 64-bit output, 192-bit (Krull64) or 256-bit (Krull65) state.
- 2\*\*64 (Krull64) or 2\*\*128 (Krull65) pairwise independent streams of period 2\*\*128.
- Streams are equidistributed with each 64-bit number appearing 2\*\*64 times.
- Full state space with no bad states and no bad seeds.
- Random access inside streams.
- No unsafe code and no `std` required.
- LCGs are run economically with [65-bit multipliers](https://arxiv.org/abs/2001.05304) using 64-to-128-bit widening multiplies.

Krull64/65 are intended as non-cryptographic workhorse RNGs
suitable for simulations and procedural content generation
that are solid, easy to use, and have a full feature set.

Krull64/65 will be frozen after a period of testing if no issues are found.

## Crate

This crate depends on [rand_core](https://crates.io/crates/rand_core), which is
a part of the [Rand project](https://github.com/rust-random/rand).

[Serde](https://serde.rs/) support is opt-in, so enable the `serde` feature if you need it.

## License

MIT
