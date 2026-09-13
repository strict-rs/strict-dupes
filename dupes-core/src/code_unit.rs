//! Shared code-unit vocabulary: detection dimensions, unit kinds, and the
//! normalized [`CodeUnit`] record every analyzer produces.

use std::fmt;
use std::path::PathBuf;

use crate::fingerprint::Fingerprint;
use crate::node::NormalizedNode;
use crate::suppression::RuleId;

/// A duplicate-detection dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum DetectionDimension {
  /// Language-aware AST comparison of top-level code units.
  Ast,
  /// Language-aware AST comparison of nested code regions.
  SubAst,
  /// Identifier/literal-normalized token-window comparison.
  TokenNormalized,
  /// Whitespace-insensitive raw token-window comparison.
  TokenRaw,
  /// Trimmed, whitespace-normalized line-window comparison.
  Line,
}

impl DetectionDimension {
  /// All supported detection dimensions.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "The dimension registry is the canonical enumeration used by configuration and external consumers"
  )]
  pub const fn all() -> &'static [Self] {
    &[Self::Ast, Self::SubAst, Self::TokenNormalized, Self::TokenRaw, Self::Line]
  }
}

impl fmt::Display for DetectionDimension {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::Ast => write!(f, "ast"),
      Self::SubAst => write!(f, "sub_ast"),
      Self::TokenNormalized => write!(f, "token_normalized"),
      Self::TokenRaw => write!(f, "token_raw"),
      Self::Line => write!(f, "line"),
    }
  }
}

/// The kind of code unit extracted from source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum CodeUnitKind {
  /// A free function.
  Function,
  /// An associated function or method.
  Method,
  /// A closure or lambda body.
  Closure,
  /// A class body (or comparable type-level container).
  Class,
  /// An inherent `impl` block.
  ImplBlock,
  /// A trait `impl` block.
  TraitImplBlock,
  // Sub-function kinds
  /// A single branch body of an `if`/`else` chain.
  IfBranch,
  /// A run of consecutive `if` statements treated as one coherent unit.
  IfChain,
  /// A single `match` arm body.
  MatchArm,
  /// A loop body.
  LoopBody,
  /// A bare nested block.
  Block,
  /// A sliding window from the token detection dimensions.
  TokenWindow,
  /// A sliding window from the line detection dimension.
  LineWindow,
}

impl fmt::Display for CodeUnitKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::Function => write!(f, "function"),
      Self::Method => write!(f, "method"),
      Self::Closure => write!(f, "closure"),
      Self::Class => write!(f, "class"),
      Self::ImplBlock => write!(f, "impl block"),
      Self::TraitImplBlock => write!(f, "trait impl block"),
      Self::IfBranch => write!(f, "if branch"),
      Self::IfChain => write!(f, "if chain"),
      Self::MatchArm => write!(f, "match arm"),
      Self::LoopBody => write!(f, "loop body"),
      Self::Block => write!(f, "block"),
      Self::TokenWindow => write!(f, "token window"),
      Self::LineWindow => write!(f, "line window"),
    }
  }
}

/// A unit of code extracted and normalized for duplication analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnit {
  /// Structural kind of the unit.
  pub kind:         CodeUnitKind,
  /// Display name (function/method path or window description).
  pub name:         String,
  /// Source file the unit was extracted from.
  pub file:         PathBuf,
  /// First source line of the unit (1-based).
  pub line_start:   usize,
  /// Last source line of the unit (1-based).
  pub line_end:     usize,
  /// Normalized signature subtree ([`NodeKind::Opaque`] leaf when the unit has none).
  ///
  /// [`NodeKind::Opaque`]: crate::node::NodeKind::Opaque
  pub signature:    NormalizedNode,
  /// Normalized body subtree compared for similarity.
  pub body:         NormalizedNode,
  /// Content fingerprint identifying the unit across moves and renames.
  pub fingerprint:  Fingerprint,
  /// Number of nodes in the normalized body, used by size floors.
  pub node_count:   usize,
  /// For sub-function units, the name of the parent function.
  pub parent_name:  Option<String>,
  /// Whether this code unit was identified as test code by the language analyzer.
  pub is_test:      bool,
  /// Suppression rule that tagged this unit as a low-signal candidate.
  pub suppressed:   Option<RuleId>,
  /// For if-branch sub-units, the fingerprint of the owning if-chain unit.
  pub parent_chain: Option<Fingerprint>,
}
