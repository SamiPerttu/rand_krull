#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use wrapping_arithmetic::wrappit;

// Krull64 features
// -"trivially strong" design by Sami Perttu
// -64-bit output, 192-bit state and footprint
// -full 192-bit state space with no bad states and no bad seeds
// -2**64 pairwise independent streams of length 2**128
// -streams are equidistributed with each 64-bit number appearing 2**64 times
// -random access inside streams
// -generation takes approximately 3.0 ns (where PCG-128 is 2.4 ns and Krull65 is 4.6 ns)

/// Krull64 non-cryptographic RNG. 64-bit output, 192-bit state.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Krull64 {
    /// LCG state low bits.
    lcg0: u64,
    /// LCG state high bits.
    lcg1: u64,
    /// Stream number.
    stream: u64,
}

// Stream position is measured in relation to an origin LCG state at position 0.
// We define the origin as equal to the stream number XOR some arbitrary constant
// in order to desynchronize the streams. Here we invert all the bits,
// which potentially enhances compression of RNGs at position 0 when serialized.
#[inline]
fn origin_0(stream: u64) -> u64 {
    !stream
}

#[inline]
fn origin_128(stream: u64) -> u128 {
    origin_0(stream) as u128
}

impl Krull64 {
    #[inline]
    fn lcg_128(&self) -> u128 {
        self.lcg0 as u128 | ((self.lcg1 as u128) << 64)
    }

    #[inline]
    fn multiplier(&self) -> u64 {
        super::LCG_M65_1 as u64
    }

    #[inline]
    fn multiplier_128(&self) -> u128 {
        super::LCG_M65_1
    }

    #[inline]
    fn increment_128(&self) -> u128 {
        // LCG increment is odd in full period sequences.
        // Unlike with LCG multipliers, any odd increment works fine.
        // Flip of increment bit B causes changes with a period of 2**(128 - B):
        // LCG sequences that differ only in high bits of the increment are correlated.
        // So it's important to rely on the low increment bits only.
        // The increment is a mirror image of the state in this sense,
        // as in state it is the low bits that repeat.
        ((self.stream as u128) << 1) | 1
    }

    /// Origin is LCG state at position 0 in current stream.
    #[inline]
    fn origin_0(&self) -> u64 {
        origin_0(self.stream)
    }

    /// Origin is LCG state at position 0 in current stream.
    #[inline]
    fn origin_128(&self) -> u128 {
        origin_128(self.stream)
    }

    /// Generates the next 64-bit random number.
    #[wrappit]
    #[inline]
    pub fn step(&mut self) -> u64 {
        // We can get a widening 64-to-128-bit multiply by casting the arguments from 64 bits.
        // We also add the increment in 128-bit to get the carry for free.
        let lcg = (self.lcg0 as u128) * self.multiplier() as u128 + self.increment_128();
        self.lcg1 = ((lcg >> 64) as u64) + self.lcg1 * self.multiplier() + self.lcg0;
        self.lcg0 = lcg as u64;
        self.get()
    }

    /// Generates the next 128-bit random number.
    #[inline]
    pub fn step_128(&mut self) -> u128 {
        self.step() as u128 | ((self.step() as u128) << 64)
    }

    /// Returns the current 64-bit output.
    #[wrappit]
    #[inline]
    pub fn get(&self) -> u64 {
        // Take high 64 bits from the LCG, they are the most random.
        // The 1-to-1 mapping guarantees equidistribution
        // as the rest of the pipeline is bijective.
        let x = self.lcg1;

        // We want the output stage to pass tests also as an indexed RNG.
        // It was tested with PractRand to 1 TB in this use.
        // The output hash is a combination of stages from SplitMix64
        // combined with a final stage from a hash by degski.
        let x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
        let x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
        let x = (x ^ (x >> 31)) * 0xd6e8feb86659fd93;
        x ^ (x >> 32)
    }

    /// 128-bit version of step() for benchmarking.
    #[wrappit]
    #[inline]
    pub fn step_slow(&mut self) -> u64 {
        let lcg = self.lcg_128() * self.multiplier_128() + self.increment_128();
        self.lcg0 = lcg as u64;
        self.lcg1 = (lcg >> 64) as u64;
        self.get()
    }

    /// Creates a new Krull64 RNG.
    /// Stream and position are set to 0.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Krull64 {
            lcg0: origin_0(0),
            lcg1: 0,
            stream: 0,
        }
    }

    /// Creates a new Krull64 RNG from a 32-bit seed.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_32(seed: u32) -> Self {
        Krull64::from_64(seed as u64)
    }

    /// Creates a new Krull64 RNG from a 64-bit seed.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_64(seed: u64) -> Self {
        Krull64 {
            lcg0: origin_0(seed),
            lcg1: 0,
            stream: seed,
        }
    }

    /// Creates a new Krull64 RNG from a 128-bit seed.
    /// Each seed accesses a unique sequence of length 2**64.
    /// All seeds work equally well.
    /// Sets stream to a XOR of the high and low bits of seed
    /// to decorrelate nearby seeds in both arguments.
    /// Sets high bits of position from low bits of seed.
    pub fn from_128(seed: u128) -> Self {
        let mut krull = Krull64::from_64(((seed >> 64) ^ seed) as u64);
        krull.set_position((seed as u128) << 64);
        krull
    }

    /// Jumps forward (if steps > 0) or backward (if steps < 0) or does nothing (if steps = 0).
    /// The stream wraps around, so signed steps can be interpreted as unsigned.
    pub fn jump(&mut self, steps: i128) {
        let lcg = crate::lcg::get_state(
            self.multiplier_128(),
            self.increment_128(),
            self.lcg_128(),
            steps as u128,
        );
        self.lcg0 = lcg as u64;
        self.lcg1 = (lcg >> 64) as u64;
    }

    /// Returns current position in stream. The full state of the generator is (stream, position).
    pub fn position(&self) -> u128 {
        crate::lcg::get_iterations(
            self.multiplier_128(),
            self.increment_128(),
            self.origin_128(),
            self.lcg_128(),
        )
    }

    /// Sets position in stream.
    pub fn set_position(&mut self, position: u128) {
        let lcg = crate::lcg::get_state(
            self.multiplier_128(),
            self.increment_128(),
            self.origin_128(),
            position,
        );
        self.lcg0 = lcg as u64;
        self.lcg1 = (lcg >> 64) as u64;
    }

    /// Resets stream position to 0. Equivalent to set_position(0).
    #[inline]
    pub fn reset(&mut self) {
        self.lcg0 = self.origin_0();
        self.lcg1 = 0;
    }

    /// Returns current stream. The full state of the generator is (stream, position).
    #[inline]
    pub fn stream(&self) -> u64 {
        self.stream
    }

    /// Sets stream and initializes position to 0.
    pub fn set_stream(&mut self, stream: u64) {
        self.stream = stream;
        self.reset();
    }
}

use super::{Error, RngCore, SeedableRng};

impl RngCore for Krull64 {
    fn next_u32(&mut self) -> u32 {
        self.step() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.step()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = dest.len();
        let mut i = 0;
        while i < bytes {
            let x = self.step();
            let j = bytes.min(i + 8);
            // Always use Little-Endian.
            dest[i..j].copy_from_slice(&x.to_le_bytes()[0..(j - i)]);
            i = j;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Krull64 {
    type Seed = [u8; 16];

    /// Creates a new Krull64 RNG from a seed.
    /// All seeds work equally well.
    fn from_seed(seed: Self::Seed) -> Self {
        // Always use Little-Endian.
        Krull64::from_128(u128::from_le_bytes(seed))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    #[test]
    pub fn run_tests() {
        let krull64_expected: [u64; 16] = [
            0x57c1b6c1df5ed4d2,
            0x1efdba83398cf412,
            0xa02d8dfda06ac9ce,
            0xf6e3f32be5e81841,
            0xc2a690083e597e0d,
            0x3b1b2ed3fa6c15aa,
            0x241c691340a479b2,
            0x88c24c8d79bb67c1,
            0x09f213c4fc2b61dc,
            0xa4b6ad95c713c951,
            0xa43904ae3341edf7,
            0xee2dca4d5fd5f8fa,
            0x27bdddbeaa4aadb0,
            0x98c78e68dbf634b2,
            0xf0edc57017a0d5a5,
            0x8647ea5de51eca23,
        ];
        let mut krull64 = Krull64::from_64(0);
        for x in krull64_expected {
            assert_eq!(x, krull64.next_u64());
        }

        let mut r: u128 = 0;
        let mut rnd = || -> u128 {
            r = r.wrapping_mul(LCG_M128_1).wrapping_add(0xffff);
            r
        };

        for _ in 0..1 << 12 {
            let seed = rnd() as u64;
            let mut krull1 = Krull64::new();
            assert_eq!(0, krull1.stream());
            assert_eq!(0, krull1.position());
            krull1.set_stream(seed);
            assert_eq!(seed, krull1.stream());
            assert_eq!(0, krull1.position());
            let mut krull2 = Krull64::from_64(seed);
            assert_eq!(seed, krull2.stream());
            assert_eq!(0, krull2.position());

            let pos2 = rnd();
            let pos1 = pos2 & rnd();
            krull1.set_position(pos1);
            krull2.set_position(pos2);
            assert_eq!(pos1, krull1.position());
            assert_eq!(pos2, krull2.position());
            krull1.jump((pos2 - pos1) as i128);
            assert_eq!(pos2, krull1.position());
            assert_eq!(krull1.next_u64(), krull2.next_u64());
            krull1.jump(-1);
            assert_eq!(pos2, krull1.position());
            krull2.jump(-1);
            assert_eq!(pos2, krull2.position());
            krull1.jump(-((pos2 - pos1) as i128));
            assert_eq!(pos1, krull1.position());

            let n = 1 + (rnd() & 0x3ff);
            for _ in 0..n {
                krull1.next_u64();
            }
            assert_eq!(pos1 + n, krull1.position());

            assert_eq!(seed, krull1.stream());

            let bytes = 1 + (rnd() & 0x7f);
            let mut buffer1 = [0u8; 0x80];
            let mut buffer2 = [0u8; 0x80];
            krull1.reset();
            assert_eq!(0, krull1.position());
            krull1.fill_bytes(&mut buffer1[0..bytes as usize]);
            krull2.reset();
            for i in 0..0x10 {
                let x = krull2.next_u64();
                buffer2[(i << 3)..((i + 1) << 3)].copy_from_slice(&x.to_le_bytes());
            }
            assert!(buffer1[0..bytes as usize]
                .iter()
                .zip(buffer2[0..bytes as usize].iter())
                .all(|(x, y)| x == y));
        }
    }
}
