#![no_std]

pub mod krull64;
pub mod krull65;
pub mod lcg;

pub use krull64::*;
pub use krull65::*;
pub use rand_core::*;

// LCG multipliers from Steele, G. and Vigna, S.,
// Computationally Easy, Spectrally Good Multipliers for
// Congruential Pseudorandom Number Generators (2020).

// 128-bit LCG multipliers.
pub const LCG_M128_1: u128 = 0xde92a69f6e2f9f25fd0d90f576075fbd;
pub const LCG_M128_2: u128 = 0x576bc0a2178fcf7c619f3ebc7363f7f5;
pub const LCG_M128_3: u128 = 0x87ea3de194dd2e97074f3d0c2ea63d35;
pub const LCG_M128_4: u128 = 0xf48c0745581cf801619cd45257f0ab65;

// 65-bit LCG multipliers for 128-bit LCGs.
pub const LCG_M65_1: u128 = 0x1df77a66a374e300d;
pub const LCG_M65_2: u128 = 0x1d605bbb58c8abbfd;
pub const LCG_M65_3: u128 = 0x1d7d8dd3a6a72b43d;
pub const LCG_M65_4: u128 = 0x1f20529e418340d05;

// 64-bit LCG multipliers.
pub const LCG_M64_1: u64 = 0xd1342543de82ef95;
pub const LCG_M64_2: u64 = 0xaf251af3b0f025b5;
pub const LCG_M64_3: u64 = 0xb564ef22ec7aece5;
pub const LCG_M64_4: u64 = 0xf7c2ebc08f67f2b5;
