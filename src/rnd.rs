use wrapping_arithmetic::wrappit;

/// Krull64 RNG.
#[derive(Clone, Eq, PartialEq)]
pub struct Krull64 {
    /// LCG state.
    pub state: u128,
    /// Stream number.
    stream: u128,
}

#[inline] fn origin(stream: u128) -> u128 {
    // Stream position is measured in relation to an origin state at position 0.
    // We define the origin as equal to the stream number XOR some arbitrary constant
    // in order to desynchronize the streams.
    !stream
}

// -high quality, non-cryptographic simulation RNG
// -256-bit state with full period, 64-bit output
// -2**128 streams of length 2**128 supporting random access
// -easy to seed
// -streams are equidistributed with each 64-bit output appearing 2**64 times
// -technically this is an LCG with a strong output hash, so like an overengineered PCG.
// Why Krull64?
// -RNGs are too fast with weak streaming and seeding procedures that barely clear the bar
// -confident randomness with properly seeded streams for parallel simulations
// -every bit of the 256-bit state is sufficiently mixed in the output

impl Krull64 {

    #[inline]
    fn multiplier(&self) -> u128 {
        // There are 2**126 full period 128-bit LCG multipliers of varying quality.
        // This multiplier was recommended by Melissa McCarthy.
        super::LCG_M2
    }

    #[inline]
    fn increment(&self) -> u128 {
        // LCG increment is odd in full period sequences.
        // Unlike with LCG multipliers, any odd increment will do.
        // Flip of increment bit B causes changes with a period of (128 - B).
        // LCG sequences that differ only in high bits of the increment are correlated.
        (self.stream << 1) | 1
    }

    #[inline]
    fn origin(&self) -> u128 {
        origin(self.stream)
    }

    /// Advances to the next state.
    #[wrappit] #[inline]
    fn step(&mut self) {
        self.state = self.state * self.multiplier() + self.increment();
    }

    /// Returns the current 64-bit output.
    #[wrappit] #[inline]
    fn get(&self) -> u64 {
        // Take high 64 bits from the LCG, they are the most random.
        // High bits of the stream are not well mixed in LCG state,
        // so we remix them here. Shift amount was picked empirically.
        let x = (self.state >> 64) as u64 ^ (self.stream >> 79) as u64;

        // The output stage has so far been tested to 1 TB
        // in the (extremely unlikely) worst case scenario
        // of an XOR of two maximally correlated sequences, which differ in 1 bit only.
        // We would like streams to be diverse enough that
        // all of the nearly 2**384 pairwise combined sequences
        // from different streams pass statistical tests.
        // The output hash is a combination of stages from SplitMix64 by Sebastiano Vigna
        // combined with a final stage from a hash by degski.
        let x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
        let x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
        let x = (x ^ (x >> 31)) * 0xd6e8feb86659fd93;
        x ^ (x >> 32)
    }

    /// Generates the next 64-bit random number.
    pub fn next(&mut self) -> u64 {
        self.step();
        self.get()
    }

    /// Creates a new Krull64 RNG. Stream and position are set to 0.
    pub fn new() -> Self {
        Krull64 { state: origin(0), stream: 0 }
    }

    /// Creates a new Krull64 RNG.
    /// Stream is set to the given seed and position is set to 0.
    /// All seeds work equally well.
    pub fn from_seed(seed: u128) -> Self {
        Krull64 { state: origin(seed), stream: seed }
    }

    pub fn print(&self) {
        println!("RNG state {:32x} output {:32x} position {:x}", self.state, self.get(), self.position());
    }

    /// Jumps forward (if steps > 0) or backward (if steps < 0).
    pub fn jump(&mut self, steps: i128) {
        self.state = crate::lcg::get_state(self.multiplier(), self.increment(), self.state, steps as u128);
    }

    /// Returns current position in stream.
    pub fn position(&self) -> u128 {
        crate::lcg::get_iterations(self.multiplier(), self.increment(), self.origin(), self.state)
    }

    /// Sets position in stream.
    pub fn set_position(&mut self, position: u128) {
        self.state = crate::lcg::get_state(self.multiplier(), self.increment(), self.origin(), position);
    }

    /// Returns current stream.
    pub fn stream(&self) -> u128 {
        self.stream
    }

    /// Sets stream and initializes position to 0.
    pub fn set_stream(&mut self, stream: u128) {
        self.state = origin(stream);
        self.stream = stream;
    }

    /// Returns the next random u128.
    pub fn next_u128(&mut self) -> u128 {
        let msb = self.next() as u128;
        let lsb = self.next() as u128;
        (msb << 64) ^ lsb
    }

    /// Returns the next random f64.
    pub fn next_f64(&mut self) -> f64 {
        self.next() as f64 / 18446744073709600000.0
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
            dest[i .. j].copy_from_slice(&x.to_le_bytes());
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

#[test]
pub fn run_tests() {

    let mut r: u128 = 0;
    let mut rnd = || -> u128 { r = r.wrapping_mul(super::LCG_M1).wrapping_add(0xffff); r };

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
    }
}
