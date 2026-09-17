//! Reproducible evidence, reversible cipher primitives and scoped K4 diagnostics.
//!
//! [`cipher`] and [`transforms`] encrypt and decrypt under explicitly supplied
//! keys and conventions. [`diagnosis`] checks necessary conditions against
//! published K4 anchors; passing those conditions never establishes a solution.
//! [`primers`] exhausts a fixed numeric-primer domain using necessary crib
//! constraints. No complete alphabet-key recovery or plaintext authentication is
//! provided.
//! [`statistics`] reproduces five fixed quantities under a seeded permutation
//! null; their unusualness does not establish a cipher mechanism.
//! [`statistics::width_scan`] repeats a calibrated maximum-selection procedure
//! across widths 1–48 on both the observed text and every null sample.

pub mod cipher;
pub mod diagnosis;
pub mod evidence;
pub mod feasibility;
pub mod primers;
pub mod statistics;
pub mod transforms;
