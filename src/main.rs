use wrapping_arithmetic::wrappit;
use std::io::Write;
use rand_krull::*;

/// 64-bit hash SplitMix64 by Sebastiano Vigna. It passes PractRand to 32 TB.
#[wrappit] #[inline] 
pub fn hashr(x: u64) -> u64 {
    let x = x * 0x9e3779b97f4a7c15;
    let x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
    let x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
    x ^ (x >> 31)
}

fn main() -> std::io::Result<()> {

    let mut rnd = Krull64::from_seed(0);
    let mut rnq = Krull64::from_seed(1);
    //let mut rnq = Krull64::from_seed(0x80000000000000000000000000000000);
    let mut stdout = std::io::stdout();

    let mut v: Vec<u8> = Vec::new();
    let mut n: u64 = 0;

    //for _ in 0 .. 20 { rnd.print(); rnd.next(); }
    //for _ in 0 .. 20 { rnq.print(); rnq.next(); }

    loop {
        let x = rnd.next_u64();
        let y = rnq.next_u64();

        // Incrementing Wang hash fails very badly.
        // Incrementing hashd fails quite badly.
        // Middle LCG bits fails badly.
        //let z = (rnd.state >> 32) as u64; 
        // Incrementing FarmHash fails badly.
        // Middle-high LCG bits (48..112) fails at 4 GB.
        // let z = (rnd.state >> 48) as u64; 
        // Incrementing hashc fails at 8 GB. (SplitMix64 without initial multiplier)
        // Middle-high-high LCG bits (56..120) fails at 16 GB.
        //let z = (rnd.state >> 56) as u64; 
        // High LCG bits: 1 unusual result at 256 MB, then OK to at least 32 GB.
        //let z = (rnd.state >> 64) as u64; 
        // SplitMix64 is OK to at least 32 GB.
        let z = hashr(n);
        // Krull is OK to at least 1 TB. unusuals at 8 & 128 GB.
        //let z = hash64(n);
        // XOR of parallel streams 0 and 1<<127 has been tested to 1 TB.
        //let z = x ^ y;

        // Stream 0 64-bit output has been tested to 64 GB.
        //let z = x;
        // Stream 1 64-bit output has been tested to 0 GB.
        //let z = y;

        v.extend_from_slice(&z.to_le_bytes());

        // Stream 0 32-bit output has been tested to 0 GB.
        //v.extend_from_slice(&(x as u32).to_le_bytes());

        if v.len() >= 0x10000 {
            stdout.write_all(v.as_slice())?;
            v.clear();
        }

        n = n + 1;
    }
    
    Ok(())
}
