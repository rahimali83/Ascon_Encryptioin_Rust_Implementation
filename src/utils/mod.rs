/// Utility Functions Module
///
/// This module provides padding and parsing functions used by Ascon algorithms.

pub mod padding;
pub mod parsing;

pub use padding::{pad, pad_u64};
pub use parsing::parse;
