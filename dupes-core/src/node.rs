//! The language-agnostic normalized AST: [`NodeKind`] payloads, the
//! data-driven [`NormalizedNode`] tree, placeholder assignment and
//! re-indexing, and node counting.

use std::collections::HashMap;
use std::hash::Hash;

/// Kinds of literals — preserves type but erases value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LiteralKind {
  /// Integer literal.
  Int,
  /// Floating-point literal.
  Float,
  /// String literal.
  Str,
  /// Byte-string literal.
  ByteStr,
  /// C-string literal.
  CStr,
  /// Byte literal.
  Byte,
  /// Character literal.
  Char,
  /// Boolean literal.
  Bool,
  /// Null-like literal (Python `None`).
  Null,
}

/// Kinds of placeholders — what the original identifier referred to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaceholderKind {
  /// A variable or parameter name.
  Variable,
  /// A function or method name.
  Function,
  /// A type name.
  Type,
  /// A lifetime name.
  Lifetime,
  /// A loop label.
  Label,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
  /// `+`
  Add,
  /// `-`
  Sub,
  /// `*`
  Mul,
  /// `/`
  Div,
  /// `%`
  Rem,
  /// `&&` / `and`
  And,
  /// `||` / `or`
  Or,
  /// `^`
  BitXor,
  /// `&`
  BitAnd,
  /// `|`
  BitOr,
  /// `<<`
  Shl,
  /// `>>`
  Shr,
  /// `==`
  Eq,
  /// `<`
  Lt,
  /// `<=`
  Le,
  /// `!=`
  Ne,
  /// `>=`
  Ge,
  /// `>`
  Gt,
  /// `+=`
  AddAssign,
  /// `-=`
  SubAssign,
  /// `*=`
  MulAssign,
  /// `/=`
  DivAssign,
  /// `%=`
  RemAssign,
  /// `^=`
  BitXorAssign,
  /// `&=`
  BitAndAssign,
  /// `|=`
  BitOrAssign,
  /// `<<=`
  ShlAssign,
  /// `>>=`
  ShrAssign,
  /// Python `//`
  FloorDiv,
  /// Python `**`
  Pow,
  /// Python `in`
  In,
  /// Python `not in`
  NotIn,
  /// Python `is`
  Is,
  /// Python `is not`
  IsNot,
  /// Python `//=`
  FloorDivAssign,
  /// Python `**=`
  PowAssign,
  /// Any binary operator not otherwise modeled.
  Other,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOpKind {
  /// `*` dereference.
  Deref,
  /// `!` / `not` logical negation.
  Not,
  /// `-` arithmetic negation.
  Neg,
  /// Any unary operator not otherwise modeled.
  Other,
}

/// The kind of a normalized AST node. Carries only non-child data
/// (operator kinds, literal kinds, placeholder indices, mutability flags, macro names).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeKind {
  // Blocks and statements
  /// A statement block.
  Block,
  /// A `let` binding statement.
  LetBinding,
  /// An expression statement terminated by `;`.
  Semi,
  /// A parenthesized expression.
  Paren,

  // Literals and identifiers
  /// A literal, typed but value-erased.
  Literal(LiteralKind),
  /// A normalized identifier: its kind plus a per-kind placeholder index.
  Placeholder(PlaceholderKind, usize),

  // Operations
  /// A binary operation.
  BinaryOp(BinOpKind),
  /// A unary operation.
  UnaryOp(UnOpKind),
  /// A range expression.
  Range,

  // Calls and access
  /// A function call.
  Call,
  /// A method call.
  MethodCall,
  /// A field access.
  FieldAccess,
  /// An index expression.
  Index,
  /// A path expression.
  Path,

  // Closures and functions
  /// A closure expression.
  Closure,
  /// A function signature (return type plus parameters).
  FnSignature,

  // Control flow
  /// A `return` expression.
  Return,
  /// A `break` expression.
  Break,
  /// A `continue` expression.
  Continue,
  /// An assignment expression.
  Assign,

  // References and pointers
  /// A reference expression, tracking mutability.
  Reference {
    /// Whether the reference is mutable.
    mutable: bool,
  },

  // Compound types
  /// A tuple expression.
  Tuple,
  /// An array or list expression.
  Array,
  /// A set expression.
  Set,
  /// An array-repeat expression.
  Repeat,

  // Type operations
  /// A type cast.
  Cast,
  /// A struct or class initializer.
  StructInit,

  // Async/error
  /// An `await` expression.
  Await,
  /// A `yield` expression.
  Yield,
  /// A `?` try expression.
  Try,

  // Control flow structures
  /// An `if` expression.
  If,
  /// A `match` expression.
  Match,
  /// A single `match` arm.
  MatchArm,
  /// A bare `loop`.
  Loop,
  /// A `while` loop.
  While,
  /// A `for` loop.
  ForLoop,
  /// A `let` condition expression (`if let` / `while let`).
  LetExpr,

  // Patterns
  /// The wildcard pattern.
  PatWild,
  /// A normalized binding pattern (kind plus placeholder index).
  PatPlaceholder(PlaceholderKind, usize),
  /// A tuple pattern.
  PatTuple,
  /// A struct pattern.
  PatStruct,
  /// An or-pattern.
  PatOr,
  /// A literal pattern.
  PatLiteral,
  /// A reference pattern, tracking mutability.
  PatReference {
    /// Whether the pattern binds mutably.
    mutable: bool,
  },
  /// A slice pattern.
  PatSlice,
  /// A rest (`..`) pattern.
  PatRest,
  /// A range pattern.
  PatRange,

  // Types
  /// A normalized type identifier.
  TypePlaceholder(PlaceholderKind, usize),
  /// A reference type, tracking mutability.
  TypeReference {
    /// Whether the referenced type is mutable.
    mutable: bool,
  },
  /// A tuple type.
  TypeTuple,
  /// A slice type.
  TypeSlice,
  /// An array type.
  TypeArray,
  /// A path type.
  TypePath,
  /// An `impl Trait` type.
  TypeImplTrait,
  /// The inferred `_` type.
  TypeInfer,
  /// The unit type.
  TypeUnit,
  /// The never type.
  TypeNever,

  // Field initializer (name = value)
  /// A field initializer (`name: value`).
  FieldValue,

  // Macro invocations
  /// A macro invocation, keyed by the macro's name.
  MacroCall {
    /// The invoked macro's name.
    name: String,
  },

  // Generic token / line duplicate detection
  /// A source token from the generic token/line window dimensions.
  Token(String),

  /// An unsupported construct, erased to an opaque marker.
  Opaque,

  /// Sentinel for absent optional children, ensuring fixed child positions
  /// for correct zip alignment in similarity comparison.
  None,
}

/// A normalized AST node with a kind payload and ordered children.
///
/// The shared representation supports generic counting, extraction, and traversal.
///
/// ## Child ordering conventions
///
/// - **Fixed with None sentinels** (always same child count):
///   - `If` -> [condition, `then_branch`, `else_or_None`]
///   - `LetBinding` -> [pattern, `type_or_None`, `init_or_None`, `diverge_or_None`]
///   - `Range` / `PatRange` -> [`from_or_None`, `to_or_None`]
///   - `MatchArm` -> [pattern, `guard_or_None`, body]
/// - **Fixed children first, variable after** (for zip alignment):
///   - `Call` -> [func, arg0, arg1, ...]
///   - `MethodCall` -> [receiver, method, arg0, ...]
///   - `Closure` -> [body, param0, ...]
///   - `FnSignature` -> [`return_type_or_None`, param0, ...]
///   - `Match` -> [expr, arm0, arm1, ...]
///   - `StructInit` -> [`rest_or_None`, field0, field1, ...]
///   - `MacroCall` -> [arg0, arg1, ...]
/// - **Variable-length (0 or 1)**: `Return`, `Break` -> [] or [value]
/// - **Homogeneous**: `Block`, `Tuple`, `Array`, `Path`, `PatTuple`, etc. -> [elem0, ...]
/// - **All other fixed**: e.g. `BinaryOp` -> [left, right], `ForLoop` -> [pat, iter, body]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedNode {
  /// The node's kind payload (operator, literal, placeholder, ...).
  pub kind:     NodeKind,
  /// Ordered children, following the child ordering conventions above.
  pub children: Vec<Self>,
}

impl NormalizedNode {
  /// Create a leaf node (no children).
  #[must_use]
  pub const fn leaf(kind: NodeKind) -> Self {
    Self {
      kind,
      children: vec![],
    }
  }

  /// Create a node with children.
  #[must_use]
  pub const fn with_children(kind: NodeKind, children: Vec<Self>) -> Self {
    Self {
      kind,
      children,
    }
  }

  /// Create a None sentinel node.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Language normalizers share this constructor to preserve absent-child positions in the normalized tree"
  )]
  pub const fn none() -> Self {
    Self::leaf(NodeKind::None)
  }

  /// Convert an Option<NormalizedNode> to a node, using None sentinel for absent values.
  #[allow(
    clippy::single_call_fn,
    reason = "Optional AST children share this sentinel conversion across external language normalizers"
  )]
  pub fn opt(node: Option<Self>) -> Self {
    node.unwrap_or_else(Self::none)
  }

  /// Check if this is a None sentinel node.
  #[must_use]
  pub const fn is_none(&self) -> bool {
    matches!(self.kind, NodeKind::None)
  }
}

/// Tracks identifier-to-placeholder mappings during normalization.
#[derive(Debug)]
pub struct NormalizationContext {
  /// Original identifiers and their assigned indices, partitioned by kind.
  mappings: PlaceholderMappings<String>,
}

/// Original identities and assigned indices for each independent placeholder kind.
type PlaceholderMappings<Identity> = HashMap<PlaceholderKind, HashMap<Identity, usize>>;

/// Reuse an identity's index or assign the next index from its kind's existing population.
fn placeholder_index<Identity: Eq + Hash>(
  mappings: &mut PlaceholderMappings<Identity>,
  kind: PlaceholderKind,
  identity: Identity,
) -> usize {
  let identities = mappings.entry(kind).or_default();
  let next = identities.len();
  *identities.entry(identity).or_insert(next)
}

impl NormalizationContext {
  /// Create an empty context with no assigned placeholders.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Each external language normalizer starts its own placeholder context through this constructor"
  )]
  pub fn new() -> Self {
    Self {
      mappings: HashMap::new()
    }
  }

  /// Get or assign a placeholder index for the given identifier and kind.
  pub fn placeholder(&mut self, name: &str, kind: PlaceholderKind) -> usize {
    placeholder_index(&mut self.mappings, kind, name.to_owned())
  }
}

impl Default for NormalizationContext {
  fn default() -> Self {
    Self::new()
  }
}

// -- Placeholder re-indexing --------------------------------------------------

/// Assign each placeholder its per-kind index at its first depth-first occurrence.
fn apply_reindex(node: &mut NormalizedNode, mapping: &mut PlaceholderMappings<usize>) {
  if let NodeKind::Placeholder(kind, ref mut index)
  | NodeKind::PatPlaceholder(kind, ref mut index)
  | NodeKind::TypePlaceholder(kind, ref mut index) = node.kind
  {
    *index = placeholder_index(mapping, kind, *index);
  }
  for child in &mut node.children {
    apply_reindex(child, mapping);
  }
}

/// Re-index placeholders from zero in per-kind, depth-first first-occurrence order.
///
/// This makes subtrees from different function contexts directly comparable.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Subtree canonicalization is shared by the core extractor and external language analyzers"
)]
pub fn reindex_placeholders(node: &NormalizedNode) -> NormalizedNode {
  let mut reindexed = node.clone();
  apply_reindex(&mut reindexed, &mut HashMap::new());
  reindexed
}

/// Count the number of nodes in a normalized tree.
/// None sentinel nodes are not counted.
pub fn count_nodes(node: &NormalizedNode) -> usize {
  if node.is_none() {
    return 0;
  }
  node.children.iter().map(count_nodes).fold(1, usize::saturating_add)
}

#[cfg(test)]
mod tests {
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::BinOpKind;
  use super::LiteralKind;
  use super::NodeKind;
  use super::NormalizationContext;
  use super::NormalizedNode;
  use super::PlaceholderKind;
  use super::count_nodes;
  use super::reindex_placeholders;

  /// Complete trees at a rejected canonicalization expectation.
  #[derive(Debug, thiserror::Error)]
  #[error("reindexing {input:?} produced {actual:?}, expected {expected:?}: {source}")]
  struct ReindexFailure {
    /// Original tree supplied to canonicalization.
    input:    Box<NormalizedNode>,
    /// Expected complete canonical tree.
    expected: Box<NormalizedNode>,
    /// Actual complete canonical tree.
    actual:   Box<NormalizedNode>,
    /// Native assertion failure.
    source:   TestFailure,
  }

  /// Compare the complete canonical tree while retaining its original input.
  fn check_reindexing(input: NormalizedNode, expected: NormalizedNode) -> Result<(), ReindexFailure> {
    let actual = reindex_placeholders(&input);
    ensure(actual == expected, "canonicalization preserves the expected tree and identities").map_err(|source| ReindexFailure {
      input: Box::new(input),
      expected: Box::new(expected),
      actual: Box::new(actual),
      source,
    })
  }

  /// Both original and canonical trees at a rejected equivalence check.
  #[derive(Debug, thiserror::Error)]
  #[error("subtrees {inputs:?} canonicalized to {canonical:?}: {source}")]
  struct EquivalentSubtreesFailure {
    /// The two independently numbered source trees.
    inputs:    Box<[NormalizedNode; 2]>,
    /// The corresponding canonical trees in the same order.
    canonical: Box<[NormalizedNode; 2]>,
    /// Native distinct-input or equivalent-output assertion failure.
    source:    TestFailure,
  }

  /// Complete assignment requests, context, and results at a failed expectation.
  #[derive(Debug, thiserror::Error)]
  #[error("requests {requests:?} produced {actual:?}, expected {expected:?}, in {context:?}: {source}")]
  struct ContextFailure<const COUNT: usize> {
    /// Ordered original names and their placeholder kinds.
    requests: Box<[(&'static str, PlaceholderKind); COUNT]>,
    /// Expected index for each request.
    expected: Box<[usize; COUNT]>,
    /// Actual index returned for each request.
    actual:   Box<[usize; COUNT]>,
    /// The context holding every assignment made by the operation.
    context:  Box<NormalizationContext>,
    /// Native assertion failure.
    source:   TestFailure,
  }

  /// Execute one complete assignment sequence and compare every returned index.
  fn check_context<const COUNT: usize>(
    requests: [(&'static str, PlaceholderKind); COUNT],
    expected: [usize; COUNT],
  ) -> Result<(), ContextFailure<COUNT>> {
    let mut context = NormalizationContext::default();
    let actual = requests.map(|(name, kind)| context.placeholder(name, kind));
    ensure(actual == expected, "placeholder assignments match the complete request sequence").map_err(|source| ContextFailure {
      requests: Box::new(requests),
      expected: Box::new(expected),
      actual: Box::new(actual),
      context: Box::new(context),
      source,
    })
  }

  /// Complete source tree and its rejected node-count expectation.
  #[derive(Debug, thiserror::Error)]
  #[error("counting {input:?} produced {actual}, expected {expected}: {source}")]
  struct CountFailure {
    /// Original tree whose non-sentinel nodes were counted.
    input:    Box<NormalizedNode>,
    /// Expected number of syntax nodes.
    expected: usize,
    /// Actual number of syntax nodes.
    actual:   usize,
    /// Native assertion failure.
    source:   TestFailure,
  }

  /// Count a complete tree without discarding it if the expectation fails.
  fn check_count(input: NormalizedNode, expected: usize) -> Result<(), CountFailure> {
    let actual = count_nodes(&input);
    ensure_eq(&actual, &expected, "only present syntax nodes contribute to the count").map_err(|source| CountFailure {
      input: Box::new(input),
      expected,
      actual,
      source,
    })
  }

  #[test]
  fn reindex_preserves_first_occurrence_order_and_repeated_identity() -> Result<(), ReindexFailure> {
    for sequences in [[[5, 8], [0, 1]], [[8, 5], [0, 1]], [[3, 3], [0, 0]]] {
      let [input, expected] = sequences.map(|indices| {
        NormalizedNode::with_children(
          NodeKind::BinaryOp(BinOpKind::Add),
          Vec::from(indices.map(|index| NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, index)))),
        )
      });
      check_reindexing(input, expected)?;
    }
    Ok(())
  }

  #[test]
  fn reindex_makes_equivalent_subtrees_equal() -> Result<(), EquivalentSubtreesFailure> {
    let subtree1 = NormalizedNode::with_children(NodeKind::Block, vec![
      NormalizedNode::with_children(NodeKind::LetBinding, vec![
        NormalizedNode::leaf(NodeKind::PatPlaceholder(PlaceholderKind::Variable, 2)),
        NormalizedNode::none(),
        NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Add), vec![
          NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 0)),
          NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
        ]),
        NormalizedNode::none(),
      ]),
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 2)),
    ]);
    let subtree2 = NormalizedNode::with_children(NodeKind::Block, vec![
      NormalizedNode::with_children(NodeKind::LetBinding, vec![
        NormalizedNode::leaf(NodeKind::PatPlaceholder(PlaceholderKind::Variable, 7)),
        NormalizedNode::none(),
        NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Add), vec![
          NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 5)),
          NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
        ]),
        NormalizedNode::none(),
      ]),
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 7)),
    ]);

    let first = reindex_placeholders(&subtree1);
    let second = reindex_placeholders(&subtree2);
    ensure(
      subtree1 != subtree2,
      "the source subtrees begin with different placeholder identities",
    )
    .and_then(|()| ensure(first == second, "canonicalization equates structurally equivalent subtrees"))
    .map_err(|source| EquivalentSubtreesFailure {
      inputs: Box::new([subtree1, subtree2]),
      canonical: Box::new([first, second]),
      source,
    })
  }

  #[test]
  fn reindex_handles_multiple_placeholder_kinds() -> Result<(), ReindexFailure> {
    let node = NormalizedNode::with_children(NodeKind::Call, vec![
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Function, 3)),
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 5)),
      NormalizedNode::with_children(NodeKind::Cast, vec![
        NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 5)),
        NormalizedNode::leaf(NodeKind::TypePlaceholder(PlaceholderKind::Type, 2)),
      ]),
    ]);
    let expected = NormalizedNode::with_children(NodeKind::Call, vec![
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Function, 0)),
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 0)),
      NormalizedNode::with_children(NodeKind::Cast, vec![
        NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 0)),
        NormalizedNode::leaf(NodeKind::TypePlaceholder(PlaceholderKind::Type, 0)),
      ]),
    ]);
    check_reindexing(node, expected)
  }

  #[test]
  fn count_nodes_skips_none_sentinels() -> Result<(), CountFailure> {
    let node = NormalizedNode::with_children(NodeKind::If, vec![
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 0)),
      NormalizedNode::with_children(NodeKind::Block, vec![]),
      NormalizedNode::none(),
    ]);
    // If(1) + Placeholder(1) + Block(1) = 3 (None is not counted)
    check_count(node, 3)
  }

  // -- NormalizationContext tests --

  #[test]
  fn context_assigns_sequential_indices_per_kind() -> Result<(), ContextFailure<3>> {
    for (requests, expected) in [
      (
        [
          ("x", PlaceholderKind::Variable),
          ("y", PlaceholderKind::Variable),
          ("z", PlaceholderKind::Variable),
        ],
        [0, 1, 2],
      ),
      (
        [
          ("foo", PlaceholderKind::Variable),
          ("foo", PlaceholderKind::Function),
          ("foo", PlaceholderKind::Type),
        ],
        [0, 0, 0],
      ),
    ] {
      check_context(requests, expected)?;
    }
    Ok(())
  }

  #[test]
  fn context_returns_same_index_for_same_name() -> Result<(), ContextFailure<2>> {
    check_context([("x", PlaceholderKind::Variable), ("x", PlaceholderKind::Variable)], [0, 0])
  }

  #[test]
  fn context_same_name_different_kind_are_distinct() -> Result<(), ContextFailure<4>> {
    check_context(
      [
        ("x", PlaceholderKind::Variable),
        ("x", PlaceholderKind::Function),
        ("y", PlaceholderKind::Variable),
        ("y", PlaceholderKind::Function),
      ],
      [0, 0, 1, 1],
    )
  }

  // -- count_nodes tests --

  #[test]
  fn count_nodes_basic() -> Result<(), CountFailure> {
    let node = NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Add), vec![
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, 0)),
      NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
    ]);
    check_count(node, 3)
  }
}
