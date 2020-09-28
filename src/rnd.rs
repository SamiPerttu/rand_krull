use wrapping_arithmetic::wrappit;
#[cfg(feature = "serde")] use serde::{Deserialize, Serialize};

/// Krull64 non-cryptographic RNG. 64-bit output, 256-bit state.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq)]
pub struct Krull64 {
    /// LCG state.
    lcg: u128,
    /// Stream number.
    stream: u128,
}

// As recommended, this Debug implementation does not expose internal state.
impl core::fmt::Debug for Krull64 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Krull64 {{}}")
    }
}

#[inline] fn origin(stream: u128) -> u128 {
    // Stream position is measured in relation to an origin LCG state at position 0.
    // We define the origin as equal to the stream number XOR some arbitrary constant
    // in order to desynchronize the streams. Here we invert all the bits,
    // which potentially enhances compression of RNGs at position 0 when serialized.
    !stream
}

impl Krull64 {

    #[inline]
    fn multiplier(&self) -> u128 {
        // This multiplier was recommended by Melissa O'Neill.
        // (There are 2**126 full period 128-bit LCG multipliers of varying quality.)
        super::LCG_M2
    }

    #[inline]
    fn increment(&self) -> u128 {
        // LCG increment is odd in full period sequences.
        // Unlike with LCG multipliers, any odd increment works fine.
        // Flip of increment bit B causes changes with a period of (128 - B):
        // LCG sequences that differ only in high bits of the increment are correlated.
        // The increment is a mirror image of the state in this sense,
        // as in state it is the low bits that repeat.
        (self.stream << 1) | 1
    }

    /// Origin is LCG state at position 0 in current stream.
    #[inline]
    fn origin(&self) -> u128 {
        origin(self.stream)
    }

    /// Advances to the next state.
    #[wrappit] #[inline]
    fn step(&mut self) {
        self.lcg = self.lcg * self.multiplier() + self.increment();
    }

    /// Returns the current 64-bit output.
    #[wrappit] #[inline]
    fn get(&self) -> u64 {
        // Take high 64 bits from the LCG, they are the most random.
        // The 1-to-1 mapping guarantees equidistribution
        // as the rest of the pipeline is bijective.
        // High bits of the stream are not well mixed in LCG state,
        // so we reintroduce them here.
        let x = (self.lcg >> 64) as u64 ^ (self.stream >> 79) as u64;

        // The output stage has so far been tested with PractRand to 1 TB
        // in the (extremely unlikely) worst case scenario of the user
        // XORing two maximally correlated sequences, which differ
        // in 1 fixed bit only at this point of the pipeline.
        // So the effect of the output stage is largely "vertical" in
        // dispersing the "horizontally" random streams.
        // We want the output stage to pass tests also as an indexed RNG.
        // It was tested with PractRand to 1 TB in this use.
        // The output hash is a combination of stages from SplitMix64 by Sebastiano Vigna
        // combined with a final stage from a hash by degski.
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

    /// Creates a new Krull64 RNG.
    /// Stream and position are set to 0.
    pub fn new() -> Self {
        Krull64 { lcg: origin(0), stream: 0 }
    }

    /// Creates a new Krull64 RNG.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_seed(seed: u128) -> Self {
        Krull64 { lcg: origin(seed), stream: seed }
    }

    /// Jumps forward (if steps > 0) or backward (if steps < 0) or does nothing (if steps = 0).
    /// The stream wraps around, so signed steps can be interpreted as unsigned.
    pub fn jump(&mut self, steps: i128) {
        self.lcg = crate::lcg::get_state(self.multiplier(), self.increment(), self.lcg, steps as u128);
    }

    /// Returns current position in stream. The full state of the generator is (stream, position).
    pub fn position(&self) -> u128 {
        crate::lcg::get_iterations(self.multiplier(), self.increment(), self.origin(), self.lcg)
    }

    /// Sets position in stream.
    pub fn set_position(&mut self, position: u128) {
        self.lcg = crate::lcg::get_state(self.multiplier(), self.increment(), self.origin(), position);
    }

    /// Resets stream position to 0. Equivalent to set_position(0).
    #[inline]
    pub fn reset(&mut self) {
        self.lcg = self.origin();
    }

    /// Returns current stream. The full state of the generator is (stream, position).
    #[inline]
    pub fn stream(&self) -> u128 {
        self.stream
    }

    /// Sets stream and initializes position to 0.
    pub fn set_stream(&mut self, stream: u128) {
        self.stream = stream;
        self.lcg = origin(stream);
    }
}

use super::{RngCore, Error, SeedableRng};

impl RngCore for Krull64 {
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

impl SeedableRng for Krull64 {
    type Seed = [u8; 16];

    /// Creates a new Krull64 RNG from a seed.
    /// All seeds work equally well.
    fn from_seed(seed: Self::Seed) -> Self {
        // Always use Little-Endian.
        Krull64::from_seed(u128::from_le_bytes(seed))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    use super::super::*;

    #[test] pub fn run_tests() {

        let mut r: u128 = 0;
        let mut rnd = || -> u128 { r = r.wrapping_mul(LCG_M1).wrapping_add(0xffff); r };

        for _ in 0 .. 1<<12 {
            let seed = rnd();
            let mut krull1 = Krull64::new();
            assert_eq!(0, krull1.stream());
            assert_eq!(0, krull1.position());
            krull1.set_stream(seed);
            assert_eq!(seed, krull1.stream());
            assert_eq!(0, krull1.position());
            let mut krull2 = Krull64::from_seed(seed);
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
