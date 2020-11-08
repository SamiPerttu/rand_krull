use wrapping_arithmetic::wrappit;
#[cfg(feature = "serde")] use serde::{Deserialize, Serialize};

// Krull65 features
// -"trivially strong" design by Sami Perttu
// -64-bit output, 256-bit state, 320-bit footprint
// -full 256-bit state space with no bad states and no bad seeds
// -2**128 pairwise independent streams of length 2**128
// -streams are equidistributed with each 64-bit number appearing 2**64 times
// -random access inside streams
// -generation takes approximately 4.6 ns (where PCG-128 is 2.4 ns and Krull64 is 3.0 ns)

/// Krull65 non-cryptographic RNG. 64-bit output, 320-bit footprint.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq)]
pub struct Krull65 {
    /// LCG A state, low 64 bits.
    a0: u64,
    /// LCG A state, high 64 bits.
    a1: u64,
    /// LCG B state, low 64 bits.
    b0: u64,
    /// LCG B state, high 64 bits.
    b1: u64,
    /// Stream number, high 64 bits.
    c1: u64,
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
        ((self.c1 as u128) << 1) ^ super::LCG_M128_1
    }

    #[inline] fn increment_b_128(&self) -> u128 {
        ((self.c1 as u128) << 1) ^ 1
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
        // 65-bit multiplies are ~0.5 ns faster here than 128-bit.
        // We also add the increment in 128-bit to get the carry for free.
        let a = (self.a0 as u128) * (self.multiplier_a() as u128) + self.increment_a_128();
        self.a1 = ((a >> 64) as u64) + self.a1 * self.multiplier_a() + self.a0;
        self.a0 = a as u64;
        let b = (self.b0 as u128) * (self.multiplier_b() as u128) + self.increment_b_128();
        self.b1 = ((b >> 64) as u64) + self.b1 * self.multiplier_b() + self.b0;
        self.b0 = b as u64;
    }

    /// Returns the current 64-bit output.
    #[wrappit] #[inline] fn get(&self) -> u64 {
        // Krull65 algorithm consists of two 128-bit LCGs advancing in synchrony.
        // The LCGs A and B realize two cycles of length 2**128,
        // with constants determined from high 64 bits of C, the stream.
        // Low 64 bits of C are chosen by positioning B against A.
        //
        // As our starting point, we take the XOR of some high quality bits from A and B.
        // Choose high 64 bits from B and A.
        // As we're mixing different bits of the LCGs together,
        // and the rest of the pipeline is bijective, this guarantees
        // equidistribution with each 64-bit output appearing 2**64 times in each stream.
        //
        let x = self.b1 ^ (self.a1 << 32) ^ (self.a1 >> 32);

        // The signal is already quite high quality here, as the minimum periodicity
        // left in the bits is 2**96 samples.
        //
        // We can examine our chosen worst case of the user XORing two streams X and Y
        // at the worst possible location with C being identical.
        // At this point in the pipeline, pairwise correlations between X and Y
        // can be measured easily, as they are just autocorrelations of B: A is identical.
        // So the sequence X XOR Y is the XOR of B with a lagged copy of itself.
        //
        // Fortunately, only in a vanishing fraction of cases does the output hash
        // have to do significant work to remove the pairwise correlations.
        // The level of correlation is indicated by the lowest differing bit in C.
        // In the next table we can see how hashing improves the result
        // with some statistical failures of X XOR Y investigated with PractRand.
        //
        // Identical bits       31     63     95     127
        // ---------------------------------------------
        // No hashing         256MB    1MB    1MB    1MB
        // 1 round             >1TB   32GB    1MB    1MB
        // 2 rounds             ?      ?    ~64TB    1MB
        // 3 rounds             ?      ?      ?     >1TB
        //
        // We have cordoned off 64 bits of the theoretical 128-bit phase difference
        // to avoid extreme correlations, leaving our worst case at 63 identical bits.
        // At that level of correlation, we need a second round of hashing
        // to purify streams pairwise. The output hash is intended to also
        // pass tests as an indexed RNG.
        //
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
        Krull65 { a0: origin_a0(), a1: 0, b0: origin_b0(), b1: 0, c1: 0 }
    }

    /// Creates a new Krull65 RNG from a 32-bit seed.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_32(seed: u32) -> Self {
        let mut krull = Self::new();
        krull.set_stream(seed as u128);
        krull
    }

    /// Creates a new Krull65 RNG from a 64-bit seed.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_64(seed: u64) -> Self {
        let mut krull = Self::new();
        krull.set_stream(seed as u128);
        krull
    }

    /// Creates a new Krull65 RNG from a 128-bit seed.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_128(seed: u128) -> Self {
        let mut krull = Self::new();
        krull.set_stream(seed);
        krull
    }

    /// Creates a new Krull65 RNG from a 192-bit seed.
    /// All seeds work equally well.
    /// Each seed accesses a unique sequence of length 2**64.
    /// Sets stream to (seed0 XOR seed1) to decorrelate nearby seeds in both arguments.
    /// High bits of position are taken from seed1.
    pub fn from_192(seed0: u128, seed1: u64) -> Self {
        let mut krull = Self::new();
        krull.set_stream(seed0 ^ (seed1 as u128));
        krull.set_position((seed1 as u128) << 64);
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
        // Low bits of stream are encoded as the phase difference (B - A).
        let delta = b_n.wrapping_sub(a_n) as u64;
        (((delta ^ self.c1) as u128) << 64) | (delta as u128)
    }

    /// Sets stream and initializes position to 0.
    pub fn set_stream(&mut self, stream: u128) {
        // This transformation enhances diversity of nearby streams.
        self.c1 = (stream ^ (stream >> 64)) as u64;
        self.reset();
        self.set_b_128(crate::lcg::get_state(self.multiplier_b_128(), self.increment_b_128(), origin_b_128(), (stream as u64) as u128));
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

use core::convert::TryInto;

impl SeedableRng for Krull65 {
    type Seed = [u8; 24];

    /// Creates a new Krull65 RNG from a seed.
    /// Each seed accesses a unique sequence of length 2**64.
    /// All seeds work equally well.
    fn from_seed(seed: Self::Seed) -> Self {
        // Always use Little-Endian.
        Krull65::from_192(u128::from_le_bytes(seed[0 .. 16].try_into().unwrap()), u64::from_le_bytes(seed[16 .. 24].try_into().unwrap()))
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
            let mut krull2 = Krull65::from_128(seed);
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
