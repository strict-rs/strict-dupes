//! Python language analyzer for `dupes-core`.
//!
//! Provides [`PythonAnalyzer`], a thin wrapper around
//! [`dupes_treesitter::TreeSitterAnalyzer`] configured with Python-specific
//! node mappings, extraction query, and test detection.

use std::path::Path;

use dupes_core::analyzer::LanguageAnalyzer;
use dupes_core::code_unit::CodeUnit;
use dupes_core::code_unit::CodeUnitKind;
use dupes_core::config::AnalysisConfig;
use dupes_core::node::BinOpKind;
use dupes_core::node::LiteralKind;
use dupes_core::node::NodeKind;
use dupes_core::node::UnOpKind;
use dupes_treesitter::TreeSitterAnalyzer;
use dupes_treesitter::analyzer::TreeSitterParseError;
use dupes_treesitter::extractor::KindResolver;
use dupes_treesitter::mapping::NodeMapping;

/// Tree-sitter query for extracting Python functions, lambdas, and classes.
///
/// Matches `function_definition` at any depth (top-level functions and class
/// methods), `lambda` expressions, and `class_definition` bodies.
const PYTHON_QUERY: &str = "
(function_definition
    name: (identifier) @name
    parameters: (parameters) @parameters
    body: (block) @body
) @definition

(lambda
    parameters: (lambda_parameters)? @parameters
    body: (_) @body
) @definition

(class_definition
    name: (identifier) @name
    body: (block) @body
) @definition
";

/// Native failure while compiling the Python analyzer's extraction query.
#[derive(Debug, thiserror::Error)]
#[error("could not initialize the Python extraction query: {source}")]
pub struct PythonAnalyzerError {
  /// Complete built-in query supplied to tree-sitter.
  pub query:  &'static str,
  /// Original tree-sitter query-compilation failure.
  pub source: tree_sitter::QueryError,
}

/// Python language analyzer backed by tree-sitter.
///
/// Detects duplicate and near-duplicate code in Python source files (`.py`, `.pyi`).
/// Extracts functions, lambda expressions, and class definitions as code units.
/// Test code is identified by the `test_` function name prefix or `Test` class name
/// prefix (pytest conventions).
#[derive(Debug)]
pub struct PythonAnalyzer {
  /// The generic bridge configured with Python's grammar and extraction rules.
  inner: TreeSitterAnalyzer,
}

impl PythonAnalyzer {
  /// Create a new `PythonAnalyzer`.
  ///
  /// # Errors
  ///
  /// Returns the native tree-sitter failure and complete query if query
  /// compilation fails for the selected Python grammar.
  #[allow(
    clippy::single_call_fn,
    reason = "The fallible constructor owns Python grammar, query, and callback initialization for frontend consumers."
  )]
  pub fn new() -> Result<Self, PythonAnalyzerError> {
    let kind_resolver: KindResolver = |node_kind| match node_kind {
      "lambda" => CodeUnitKind::Closure,
      "class_definition" => CodeUnitKind::Class,
      _ => CodeUnitKind::Function,
    };
    let test_detector: fn(&str, tree_sitter::Node<'_>) -> bool =
      |name, node| name.starts_with("test_") || (node.kind() == "class_definition" && name.starts_with("Test"));
    let inner: TreeSitterAnalyzer =
      TreeSitterAnalyzer::new(tree_sitter_python::LANGUAGE.into(), &["py", "pyi"], PYTHON_QUERY, python_mapping())
        .map_err(|source| PythonAnalyzerError {
          query: PYTHON_QUERY,
          source,
        })?
        .with_kind_resolver(kind_resolver)
        .with_test_detector(test_detector);

    Ok(Self {
      inner,
    })
  }
}

impl LanguageAnalyzer for PythonAnalyzer {
  type Error = TreeSitterParseError;

  fn file_extensions(&self) -> &[&str] {
    self.inner.file_extensions()
  }

  fn parse_file(&self, path: &Path, source: &str, config: AnalysisConfig) -> Result<Vec<CodeUnit>, Self::Error> {
    self.inner.parse_file(path, source, config)
  }
}

/// Build the Python-specific [`NodeMapping`].
///
/// # Covered constructs
///
/// - Identifiers, literals (`int`, `float`, `str`, `bool`, `None`)
/// - Binary operators (+, -, *, /, //, **, %, ==, !=, <, >, <=, >=, and, or, in, not in, is, is
///   not, bitwise, augmented assignment)
/// - Unary operators (not, -, ~)
/// - Control flow: if, for, while, match/case, return, break, continue
/// - Calls, assignments (plain + augmented), blocks, function definitions
/// - Containers: tuple, list, set, dictionary
/// - Access: attribute (field access), subscript (index)
/// - Async: await, yield
///
/// # Normalization limits
///
/// - `with_statement` / `try_statement` / `raise_statement` / `assert_statement` — fall through to
///   generic recursion (structure is preserved, semantic kind is lost)
/// - `conditional_expression` (ternary `x if cond else y`) — falls through to `Block`
/// - List/dict/set comprehensions — children are recursively normalized
/// - `global_statement` / `nonlocal_statement` — fall through
/// - f-string interpolations — the `string` node is treated as `Literal(Str)`, so interpolated
///   expressions inside f-strings are not captured
/// - `pass_statement` / `ellipsis` — become `Opaque` leaves
/// - Decorator-based test detection (e.g., `@pytest.fixture`) — only name-based `test_`/`Test`
///   prefix
/// - Lambda test detection — lambdas inside test functions are not tagged as test code
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Python syntax mapping is the language-owned extension table consumed by the generic tree-sitter bridge."
)]
pub fn python_mapping() -> NodeMapping {
  NodeMapping::new()
    .identifiers(&["identifier"])
    .literals(&[
      ("integer", LiteralKind::Int),
      ("float", LiteralKind::Float),
      ("string", LiteralKind::Str),
      ("true", LiteralKind::Bool),
      ("false", LiteralKind::Bool),
      ("none", LiteralKind::Null),
    ])
    .binary_ops(&[
      // Arithmetic
      ("+", BinOpKind::Add),
      ("-", BinOpKind::Sub),
      ("*", BinOpKind::Mul),
      ("/", BinOpKind::Div),
      ("%", BinOpKind::Rem),
      // Comparison
      ("==", BinOpKind::Eq),
      ("!=", BinOpKind::Ne),
      ("<", BinOpKind::Lt),
      (">", BinOpKind::Gt),
      ("<=", BinOpKind::Le),
      (">=", BinOpKind::Ge),
      // Logical
      ("and", BinOpKind::And),
      ("or", BinOpKind::Or),
      // Bitwise
      ("&", BinOpKind::BitAnd),
      ("|", BinOpKind::BitOr),
      ("^", BinOpKind::BitXor),
      ("<<", BinOpKind::Shl),
      (">>", BinOpKind::Shr),
      // Augmented assignment operators
      ("+=", BinOpKind::AddAssign),
      ("-=", BinOpKind::SubAssign),
      ("*=", BinOpKind::MulAssign),
      ("/=", BinOpKind::DivAssign),
      ("%=", BinOpKind::RemAssign),
      ("&=", BinOpKind::BitAndAssign),
      ("|=", BinOpKind::BitOrAssign),
      ("^=", BinOpKind::BitXorAssign),
      ("<<=", BinOpKind::ShlAssign),
      (">>=", BinOpKind::ShrAssign),
      // Floor division and power
      ("//", BinOpKind::FloorDiv),
      ("**", BinOpKind::Pow),
      ("//=", BinOpKind::FloorDivAssign),
      ("**=", BinOpKind::PowAssign),
      // Membership and identity
      ("in", BinOpKind::In),
      ("not in", BinOpKind::NotIn),
      ("is", BinOpKind::Is),
      ("is not", BinOpKind::IsNot),
    ])
    .unary_ops(&[("not", UnOpKind::Not), ("-", UnOpKind::Neg), ("~", UnOpKind::Other)])
    .skip(&["comment", "decorator"])
    .blocks(&["block"])
    .calls(&["call"])
    .returns(&["return_statement"])
    .ifs(&["if_statement"])
    .for_loops(&["for_statement"])
    .while_loops(&["while_statement"])
    .matches(&["match_statement"])
    .assignments(&["assignment"])
    .function_defs(&["function_definition"])
    .binary_op_kinds(&[
      "binary_operator", "boolean_operator", "comparison_operator", "augmented_assignment",
    ])
    .unary_op_kinds(&["not_operator", "unary_operator"])
    .match_arms(&["case_clause"])
    .node_kinds(&[
      // Control flow leaves
      ("break_statement", NodeKind::Break),
      ("continue_statement", NodeKind::Continue),
      // Async
      ("await", NodeKind::Await),
      ("yield", NodeKind::Yield),
      // Containers
      ("tuple", NodeKind::Tuple),
      ("list", NodeKind::Array),
      ("set", NodeKind::Set),
      ("dictionary", NodeKind::StructInit),
      // Access
      ("attribute", NodeKind::FieldAccess),
      ("subscript", NodeKind::Index),
    ])
}

#[cfg(test)]
mod tests {
  use dupes_core::analyzer::LanguageAnalyzer as _;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;

  use super::PythonAnalyzer;
  use super::PythonAnalyzerError;

  /// Native construction failures and extension-contract assertion failures.
  #[derive(Debug, thiserror::Error)]
  enum AnalyzerTestFailure {
    /// The built-in extraction query could not be compiled.
    #[error(transparent)]
    Initialization(#[from] PythonAnalyzerError),
    /// The analyzer did not expose its expected file extensions.
    #[error(transparent)]
    Expectation(#[from] ConditionFailure),
  }

  /// Fallible construction preserves support for Python modules and stubs.
  #[test]
  fn file_extensions() -> Result<(), AnalyzerTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    ensure(
      analyzer.file_extensions() == ["py", "pyi"],
      "new analyzer supports Python modules and stubs",
    )
    .map(drop)?;
    Ok(())
  }
}
