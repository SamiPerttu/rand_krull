use wrapping_arithmetic::wrappit;

// This module contains utility functions for working with
// LCGs (linear congruential generators).

/// LCG iteration is state <- state * m + p.
/// Returns the (m, p) pair that iterates by n steps at once.
/// Assumes (m, p) is full period.
#[wrappit]
pub fn get_jump(m: u128, p: u128, n: u128) -> (u128, u128) {
    // Algorithm from Brown, F. B., "Random Number Generation with Arbitrary Stride",
    // Transactions of the American Nuclear Society, 1994.
    let mut unit_m = m;
    let mut unit_p = p;
    let mut jump_m: u128 = 1;
    let mut jump_p: u128 = 0;
    let mut delta = n;

    while delta > 0 {
        if delta & 1 == 1 {
            jump_m = jump_m * unit_m;
            jump_p = jump_p * unit_m + unit_p;
        }
        unit_p = (unit_m + 1) * unit_p;
        unit_m *= unit_m;
        delta >>= 1;
    }
    (jump_m, jump_p)
}

/// LCG iteration is state <- state * m + p.
/// Returns the number of iterations between origin state and the given state.
/// Assumes (m, p) is full period.
#[wrappit]
pub fn get_iterations(m: u128, p: u128, origin: u128, state: u128) -> u128 {
    let mut jump_m = m;
    let mut jump_p = p;
    let mut ordinal: u128 = 0;
    let mut bit: u128 = 1;
    let mut address = origin;

    while address != state {
        if (bit & address) != (bit & state) {
            address = address * jump_m + jump_p;
            ordinal = ordinal + bit;
        }
        jump_p = (jump_m + 1) * jump_p;
        jump_m *= jump_m;
        bit <<= 1;
    }
    ordinal
}

/// LCG iteration is state <- state * m + p.
/// Returns state after the specified number of iterations from the origin state.
/// Assumes (m, p) is full period.
#[wrappit]
pub fn get_state(m: u128, p: u128, origin: u128, iterations: u128) -> u128 {
    let mut jump_m = m;
    let mut jump_p = p;
    let mut state = origin;
    let mut ordinal = iterations;

    while ordinal > 0 {
        if ordinal & 1 == 1 {
            state = state * jump_m + jump_p;
        }
        jump_p = (jump_m + 1) * jump_p;
        jump_m *= jump_m;
        ordinal >>= 1;
    }
    state
}

#[cfg(test)] mod tests {
    use super::*;
    use super::super::*;

    #[test] pub fn run_tests() {

        let mut r: u128 = 0;
        let mut rnd = || -> u128 { r = r.wrapping_mul(LCG_M1).wrapping_add(0xffff); r };

        for _ in 0 .. 1<<12 {

            let m = match rnd() % 3 { 0 => LCG_M1, 1 => LCG_M2, _ => LCG_M3 };
            let p = rnd() | 1;
            let origin = rnd();

            assert_eq!(origin.wrapping_mul(m).wrapping_add(p), get_state(m, p, origin, 1));
            assert_eq!(1, get_iterations(m, p, origin, origin.wrapping_mul(m).wrapping_add(p)));

            // Run some consistency tests.
            let state = rnd();
            let n = get_iterations(m, p, origin, state);
            assert_eq!(state, get_state(m, p, origin, n));

            let (m_total, p_total) = get_jump(m, p, n);
            assert_eq!(origin.wrapping_mul(m_total).wrapping_add(p_total), state);

            let n = rnd();
            let state = get_state(m, p, origin, n);
            assert_eq!(n, get_iterations(m, p, origin, state));

            // Get h <= n.
            let h = n & rnd();
            let state_h = get_state(m, p, origin, h);
            assert_eq!(n - h, get_iterations(m, p, state_h, state));
        }
    }
}
