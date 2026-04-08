use soroban_sdk::{contracterror, Env};

// For formal verification purposes

/// Minimal fixed-point trait kept for the 64-bit FV compatibility shim.
pub trait SorobanFixedPoint: Sized {
    fn fixed_mul_floor(&self, env: &Env, y: &Self, denominator: &Self) -> Self;

    fn fixed_mul_ceil(&self, env: &Env, y: &Self, denominator: &Self) -> Self;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SorobanFixedPointError {
    ZeroDenominator = 1500,
    ResultOverflow = 1501,
}
