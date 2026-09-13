//! Tree-sitter normalization bridge for `dupes-core`.
//!
//! This crate provides shared utilities for building tree-sitter-backed
//! language analyzers compatible with the `dupes-core` duplicate detection
//! pipeline. Language-specific crates supply a [`NodeMapping`] table and a
//! tree-sitter query; this crate handles normalization, fingerprinting, and
//! `CodeUnit` extraction.
//!
//! # Quick start
//!
//! For the simplest integration, construct a [`TreeSitterAnalyzer`] with your
//! grammar, extraction query, and mapping, then pass it to `dupes_core::analyze()`.
//!
//! For lower-level access, configure a [`CodeUnitExtractor`] for parsed byte
//! sources or call [`normalize_ts_node`] directly.

pub mod analyzer;
pub mod extractor;
pub mod mapping;
pub mod normalizer;

// Re-export primary types for convenience
pub use analyzer::TreeSitterAnalyzer;
// Re-export commonly needed dupes-core types
pub use dupes_core::code_unit::{
  CodeUnit,
  CodeUnitKind,
};
pub use dupes_core::config::AnalysisConfig;
pub use dupes_core::fingerprint::Fingerprint;
pub use dupes_core::node::BinOpKind;
pub use dupes_core::node::LiteralKind;
pub use dupes_core::node::NodeKind;
pub use dupes_core::node::NormalizationContext;
pub use dupes_core::node::NormalizedNode;
pub use dupes_core::node::PlaceholderKind;
pub use dupes_core::node::UnOpKind;
pub use extractor::CodeUnitExtractor;
pub use extractor::KindResolver;
pub use mapping::NodeMapping;
pub use normalizer::normalize_ts_node;
