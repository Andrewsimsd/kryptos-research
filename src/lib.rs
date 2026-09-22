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
//! [`structured_alphabets`] exhaustively tests a finite set of named alphabet
//! orders against recurrence-derived crib equations.
//! [`keyword_alphabets`] constructs a provenance-bound keyword family, gates
//! K4 evaluation on deterministic planted calibration, and exhausts that
//! finite domain with complete compact certificates.

pub mod cipher;
pub mod classical_schedules;
pub mod diagnosis;
pub mod evidence;
pub mod feasibility;
pub mod keyword_alphabets;
pub mod primers;
pub mod statistics;
pub mod structured_alphabets;
pub mod transforms;
