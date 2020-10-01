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
    /// LCG B state. Phase difference (B - A) encodes high 64 bits of the stream.
    b: u64,
    /// Stream, low 64 bits.
    c: u64,
}

// As recommended, this Debug implementation does not expose internal state.
impl core::fmt::Debug for Krull65 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Krull65 {{}}")
    }
}

/// LCG origin is the state at position 0.
#[inline] fn origin_a0(c: u64) -> u64 {
    c
}

/// LCG origin is the state at position 0.
#[inline] fn origin_b(c: u64) -> u64 {
    !c
}

impl Krull65 {

    #[inline] fn multiplier_a(&self) -> u64 {
        super::LCG_M65_2 as u64
    }

    #[inline] fn multiplier_a_128(&self) -> u128 {
        super::LCG_M65_2
    }

    #[inline] fn multiplier_b(&self) -> u64 {
        super::LCG_M64_1
    }

    #[inline] fn increment_a0(&self) -> u64 {
        self.c | 1
    }

    #[inline] fn increment_a1(&self) -> u64 {
        0
    }

    #[inline] fn increment_a_128(&self) -> u128 {
        self.increment_a0() as u128 | ((self.increment_a1() as u128) << 64)
    }

    #[inline] fn increment_b(&self) -> u64 {
        (self.c << 1) | 1
    }

    #[inline] fn origin_a0(&self) -> u64 {
        origin_a0(self.c)
    }

    #[inline] fn origin_a_128(&self) -> u128 {
        origin_a0(self.c) as u128
    }

    #[inline] fn origin_b(&self) -> u64 {
        origin_b(self.c)
    }

    #[inline] fn a_128(&self) -> u128 {
        self.a0 as u128 | ((self.a1 as u128) << 64)
    }

    /// Advances to the next state.
    #[wrappit] #[inline] fn step(&mut self) {
        // We can get a widening 64-to-128-bit multiply by casting the arguments from 64 bits.
        // We also add the increment in 128-bit to get the carry for free.
        let a = (self.a0 as u128) * (self.multiplier_a() as u128) + self.increment_a_128();
        self.a1 = ((a >> 64) as u64) + self.a1 * self.multiplier_a() + self.a0;
        self.a0 = a as u64;
        self.b = self.b * self.multiplier_b() + self.increment_b();

        // Here's the equivalent stepping code in 128-bit math.
        // let a = self.a_128() * self.multiplier_a_128() + self.increment_a_128();
        // self.a1 = (a >> 64) as u64;
        // self.a0 = a as u64;
    }

    /// Returns the current 64-bit output.
    #[wrappit] #[inline] fn get(&self) -> u64 {
        // Take 64 high bits from A and 56 high bits from B.
        // As we're XORing different bits of the LCGs together,
        // and the rest of the pipeline is bijective, this guarantees
        // equidistribution with each 64-bit output appearing 2**64 times in each stream.
        // In the worst case, the lag design causes a subtle pairwise bias between sequences
        // due to collisions that starts being detectable at around 2**62 samples.
        // The (very unlikely) worst case is where A is identical and only B is different.
        let x = self.a1 ^ (self.b >> 8);
        // The output stage is built to pass tests also as an indexed RNG.
        let x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
        let x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
        let x = (x ^ (x >> 31)) * 0xd6e8feb86659fd93;
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
        Krull65 { a0: origin_a0(0), a1: 0, b: origin_b(0), c: 0 }
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
        let a = crate::lcg::get_state(self.multiplier_a_128(), self.increment_a_128(), self.a_128(), steps as u128);
        self.a1 = (a >> 64) as u64;
        self.a0 = a as u64;
        self.b = crate::lcg::get_state(self.multiplier_b(), self.increment_b(), self.b, steps as u64);
    }

    /// Returns current position in stream. The full state of the generator is (stream, position).
    pub fn position(&self) -> u128 {
        // Position is encoded wholly in LCG A.
        super::lcg::get_iterations(self.multiplier_a_128(), self.increment_a_128(), self.origin_a_128(), self.a_128())
    }

    /// Sets position in stream.
    pub fn set_position(&mut self, position: u128) {
        let delta = position.wrapping_sub(self.position());
        self.b = crate::lcg::get_state(self.multiplier_b(), self.increment_b(), self.b, delta as u64);
        let a = crate::lcg::get_state(self.multiplier_a_128(), self.increment_a_128(), self.a_128(), delta as u128);
        self.a1 = (a >> 64) as u64;
        self.a0 = a as u64;
    }

    /// Resets stream position to 0. Equivalent to set_position(0).
    #[inline]
    pub fn reset(&mut self) {
        self.set_position(0);
    }

    /// Returns current stream. The full state of the generator is (stream, position).
    #[inline]
    pub fn stream(&self) -> u128 {
        let a_n = self.position();
        let b_n = super::lcg::get_iterations(self.multiplier_b(), self.increment_b(), self.origin_b(), self.b);
        // High 64 bits of the stream are encoded in the phase difference (B - A).
        let c_2 = b_n.wrapping_sub(a_n as u64);
        self.c as u128 | ((c_2 as u128) << 64)
    }

    /// Sets stream and initializes position to 0.
    pub fn set_stream(&mut self, stream: u128) {
        self.c = stream as u64;
        self.a0 = self.origin_a0();
        self.a1 = 0;
        self.b = super::lcg::get_state(self.multiplier_b(), self.increment_b(), self.origin_b(), (stream >> 64) as u64);
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
            for i in 0 .. n { krull1.next_u64(); }
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
