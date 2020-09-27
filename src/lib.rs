pub mod lcg;
pub mod rnd;

pub use rnd::*;
pub use rand_core::*;

// LCG multipliers.
pub const LCG_M1: u128 = 0x2360ed051fc65da44385df649fccf645;
pub const LCG_M2: u128 = 0x2d99787926d46932a4c1f32680f70c55;
pub const LCG_M3: u128 = 0x96704a6bb5d2c4fb3aa645df0540268d;
