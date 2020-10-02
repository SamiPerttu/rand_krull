use wrapping_arithmetic::wrappit;
#[cfg(feature = "serde")] use serde::{Deserialize, Serialize};

// Krull65 features
// -"trivially strong" design by Sami Perttu
// -64-bit output, 256-bit state
// -uses the full 256-bit state space with no bad states and no bad seeds
// -2**128 pairwise independent streams of length 2**128
// -streams are equidistributed with each 64-bit number appearing 2**64 times
// -random access inside streams

/// Krull65 non-cryptographic RNG. 64-bit output, 256-bit state.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq)]
pub struct Krull65 {
    /// LCG A state, low 64 bits.
    a0: u64,
    /// LCG A state, high 64 bits.
    a1: u64,
    /// LCG B state, low 64 bits.
    b0: u64,
    /// LCG b state, high 64 bits.
    b1: u64,
}

// As recommended, this Debug implementation does not expose internal state.
impl core::fmt::Debug for Krull65 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Krull65 {{}}")
    }
}

#[inline] fn origin_a0() -> u64 {
    0
}

#[inline] fn origin_a_128() -> u128 {
    origin_a0() as u128
}

#[inline] fn origin_b0() -> u64 {
    1
}

#[inline] fn origin_b_128() -> u128 {
    origin_b0() as u128
}

impl Krull65 {

    pub fn print(&self) {
        println!("A {:16x}.. B {:16x}.. output {:16x} position {}", self.a1, self.b1, self.get(), self.position());
    }

    #[inline] fn multiplier_a(&self) -> u64 {
        super::LCG_M65_1 as u64
    }

    #[inline] fn multiplier_a_128(&self) -> u128 {
        super::LCG_M65_1
    }

    #[inline] fn multiplier_b(&self) -> u64 {
        super::LCG_M65_4 as u64
    }

    #[inline] fn multiplier_b_128(&self) -> u128 {
        super::LCG_M65_4
    }

    #[inline] fn increment_a_128(&self) -> u128 {
        // Pick a big constant that is odd.
        super::LCG_M128_1
    }

    #[inline] fn increment_b_128(&self) -> u128 {
        // Pick a big constant that is odd.
        super::LCG_M128_4
    }

    #[inline] fn a_128(&self) -> u128 {
        self.a0 as u128 | ((self.a1 as u128) << 64)
    }

    #[inline] fn set_a_128(&mut self, a: u128) {
        self.a0 = a as u64;
        self.a1 = (a >> 64) as u64;
    }

    #[inline] fn b_128(&self) -> u128 {
        self.b0 as u128 | ((self.b1 as u128) << 64)
    }

    #[inline] fn set_b_128(&mut self, b: u128) {
        self.b0 = b as u64;
        self.b1 = (b >> 64) as u64;
    }

    /// Advances to the next state.
    #[wrappit] #[inline] fn step(&mut self) {
        // We can get a widening 64-to-128-bit multiply by casting the arguments from 64 bits.
        // We also add the increment in 128-bit to get the carry for free.
        let a = (self.a0 as u128) * (self.multiplier_a() as u128) + self.increment_a_128();
        self.a1 = ((a >> 64) as u64) + self.a1 * self.multiplier_a() + self.a0;
        self.a0 = a as u64;
        let b = (self.b0 as u128) * (self.multiplier_b() as u128) + self.increment_b_128();
        self.b1 = ((b >> 64) as u64) + self.b1 * self.multiplier_b() + self.b0;
        self.b0 = b as u64;

        // Here's the stepping code for A in 128-bit math.
        // let a = self.a_128() * self.multiplier_a_128() + self.increment_a_128();
        // self.a1 = (a >> 64) as u64;
        // self.a0 = a as u64;
    }

    /// Returns the current 64-bit output.
    #[wrappit] #[inline] fn get(&self) -> u64 {
        // Krull65 algorithm consists of two 128-bit LCGs advancing in synchrony.
        // The LCGs A and B, which are always run with the same constants, realize
        // two fixed sequences of length 2**128. The stream constant is chosen
        // by positioning B against A.

        // As our starting point, we take the XOR of some high quality bits from A and B.
        // Choose high 64 bits from B and the next to highest 64 bits from A.
        // As we're mixing different bits of the LCGs together,
        // and the rest of the pipeline is bijective, this guarantees
        // equidistribution with each 64-bit output appearing 2**64 times in each stream.
        let x = self.b1 ^ (self.a1 << 1) ^ (self.a0 >> 63);

        // We can examine our chosen worst case of the user XORing two streams X and Y.
        // At this point in the pipeline, pairwise correlations between X and Y
        // can be measured easily, as they are just autocorrelations of B: A is identical.
        // So the sequence X XOR Y is the XOR of B with a lagged copy of itself.
        // Autocorrelation of an LCG is indicated by the lowest differing bit.
        // For instance, if streams X and Y share an identical lowest 32 bits,
        // then statistical tests fail at 256 MB, but if they share 48 bits,
        // then statistical tests fail at 2 MB already.
        // Fortunately, there are only a vanishing fraction of pairwise streams
        // where the output hash has to do significant work to remove the correlations.
        // In the next table we can see how hashing improves the result
        // with some statistical failures of X XOR Y investigated with PractRand.
        // The output hash is intended to pass tests also as an indexed RNG.
        //
        // Lowest differing bit    32     64     96     127
        // ------------------------------------------------
        // No hashing            256MB    1MB    1MB    1MB
        // 1 round              >256GB    1GB    1MB    1MB
        // 2 rounds                ?      ?    >32GB    1MB
        // 3 rounds                ?      ?      ?    >64GB
        let x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9; // round 1
        let x = (x ^ (x >> 27)) * 0x94d049bb133111eb; // round 2
        let x = (x ^ (x >> 31)) * 0xd6e8feb86659fd93; // round 3
        x ^ (x >> 32)
    }

    /// Generates the next 64-bit random number.
    #[inline]
    pub fn next(&mut self) -> u64 {
        self.step();
        self.get()
    }

    /// Creates a new Krull65 RNG.
    /// Stream and position are set to 0.
    pub fn new() -> Self {
        Krull65 { a0: origin_a0(), a1: 0, b0: origin_b0(), b1: 0 }
    }

    /// Creates a new Krull65 RNG.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_seed(seed: u128) -> Self {
        let mut krull = Self::new();
        krull.set_stream(seed);
        krull
    }

    /// Jumps forward (if steps > 0) or backward (if steps < 0) or does nothing (if steps = 0).
    /// The stream wraps around, so signed steps can be interpreted as unsigned.
    pub fn jump(&mut self, steps: i128) {
        self.set_a_128(crate::lcg::get_state(self.multiplier_a_128(), self.increment_a_128(), self.a_128(), steps as u128));
        self.set_b_128(crate::lcg::get_state(self.multiplier_b_128(), self.increment_b_128(), self.b_128(), steps as u128));
    }

    /// Returns current position in stream. The full state of the generator is (stream, position).
    pub fn position(&self) -> u128 {
        // Position is encoded in A.
        super::lcg::get_iterations(self.multiplier_a_128(), self.increment_a_128(), origin_a_128(), self.a_128())
    }

    /// Sets position in stream.
    pub fn set_position(&mut self, position: u128) {
        let delta = position.wrapping_sub(self.position());
        self.jump(delta as i128);
    }

    /// Resets stream position to 0. Equivalent to set_position(0).
    #[inline]
    pub fn reset(&mut self) {
        self.a0 = origin_a0();
        self.a1 = 0;
        self.b0 = origin_b0();
        self.b1 = 0;
    }

    /// Returns current stream. The full state of the generator is (stream, position).
    #[inline]
    pub fn stream(&self) -> u128 {
        let a_n = self.position();
        let b_n = super::lcg::get_iterations(self.multiplier_b_128(), self.increment_b_128(), origin_b_128(), self.b_128());
        // The stream is encoded as the phase difference (B - A).
        b_n.wrapping_sub(a_n)
    }

    /// Sets stream and initializes position to 0.
    pub fn set_stream(&mut self, stream: u128) {
        self.reset();
        self.set_b_128(crate::lcg::get_state(self.multiplier_b_128(), self.increment_b_128(), origin_b_128(), stream));
    }
}

use super::{RngCore, Error, SeedableRng};

impl RngCore for Krull65 {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }
     
    fn next_u64(&mut self) -> u64 {
        self.next()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = dest.len();
        let mut i = 0;
        while i < bytes {
            let x = self.next();
            let j = bytes.min(i + 8);
            // Always use Little-Endian.
            dest[i .. j].copy_from_slice(&x.to_le_bytes()[0 .. (j - i)]);
            i = j;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl SeedableRng for Krull65 {
    type Seed = [u8; 16];

    /// Creates a new Krull65 RNG from a seed.
    /// All seeds work equally well.
    fn from_seed(seed: Self::Seed) -> Self {
        // Always use Little-Endian.
        Krull65::from_seed(u128::from_le_bytes(seed))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    use super::super::*;

    #[test] pub fn run_tests() {

        let mut r: u128 = 0;
        let mut rnd = || -> u128 { r = r.wrapping_mul(LCG_M128_1).wrapping_add(0xffff); r };

        for _ in 0 .. 1<<12 {
            let seed = rnd();
            let mut krull1 = Krull65::new();
            assert_eq!(0, krull1.stream());
            assert_eq!(0, krull1.position());
            krull1.set_stream(seed);
            assert_eq!(seed, krull1.stream());
            assert_eq!(0, krull1.position());
            let mut krull2 = Krull65::from_seed(seed);
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
            for _ in 0 .. n { krull1.next_u64(); }
            assert_eq!(pos1 + n, krull1.position());

            assert_eq!(seed, krull1.stream());

            let bytes = 1 + (rnd() & 0x7f);
            let mut buffer1 = [0u8; 0x80];
            let mut buffer2 = [0u8; 0x80];
            krull1.reset();
            assert_eq!(0, krull1.position());
            krull1.fill_bytes(&mut buffer1[0 .. bytes as usize]);
            krull2.reset();
            for i in 0 .. 0x10 {
                let x = krull2.next_u64();
                buffer2[(i << 3) .. ((i + 1) << 3)].copy_from_slice(&x.to_le_bytes());
            }
            assert!(buffer1[0 .. bytes as usize].iter().zip(buffer2[0 .. bytes as usize].iter()).all(|(x, y)| x == y));
        }
    }
}
