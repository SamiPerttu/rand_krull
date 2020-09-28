# [Krull64 Random Number Generator](https://github.com/SamiPerttu/rand_krull)

## Sample with Confidence

- High quality, non-cryptographic, medium-fast RNG.
- 64-bit output, 256-bit state.
- 2\*\*128 streams of period 2\*\*128 supporting random access.
- Streams are equidistributed with each 64-bit output appearing 2\*\*64 times.
- Streams are pairwise independent and there are no bad states.
- Trivially seedable from any data up to 128 bits.
- Technically, it is a [PCG](http://www.pcg-random.org/)
  with a strong output hash designed to
  decorrelate streams and make use of the full state space.
- No unsafe code and no `std` required.

Krull64 is intended as a non-cryptographic workhorse RNG
suitable for simulations and procedural content generation
that is solid, easy to use, and has a full feature set.

Krull64 will be frozen after a period of testing if no issues are found.

## Crate

This crate depends on [rand_core](https://crates.io/crates/rand_core), which is
a part of the [Rand project](https://github.com/rust-random/rand).

[Serde](https://serde.rs/) support is opt-in, so enable the `serde` feature if you need it.

## License

MIT
