//! Generic tree-sitter-backed `LanguageAnalyzer` implementation.
//!
//! Provides [`TreeSitterAnalyzer`], a ready-made adapter that implements
//! `dupes_core::analyzer::LanguageAnalyzer` using a [`NodeMapping`], a tree-sitter
//! query, and a tree-sitter [`Language`]. Language-specific crates can construct
//! one with their grammar and mapping to get full duplication analysis without
//! writing custom parsing logic.

use std::fmt;
use std::path::Path;

use dupes_core::analyzer::LanguageAnalyzer;
use dupes_core::code_unit::CodeUnit;
use dupes_core::code_unit::CodeUnitKind;
use dupes_core::config::AnalysisConfig;
use dupes_core::source::SourceFile;

use crate::extractor::CodeUnitExtractor;
use crate::extractor::ExtractionError;
use crate::extractor::KindResolver;
use crate::mapping::NodeMapping;

/// A parse or extraction failure with the input and any native tree already produced.
#[derive(Debug, thiserror::Error)]
pub enum TreeSitterParseError {
  /// The parser rejected the selected language's ABI version.
  #[error("tree-sitter language setup failed for {}: {source}", input.path.display())]
  Language {
    /// Complete source supplied to the failed parse attempt.
    input:  SourceFile,
    /// Original tree-sitter language compatibility error.
    source: tree_sitter::LanguageError,
  },
  /// Parsing returned no tree after language setup succeeded.
  #[error("tree-sitter produced no parse tree for {}", input.path.display())]
  NoTree {
    /// Complete source whose parse did not produce a tree.
    input: SourceFile,
  },
  /// Parsing completed, but a required extraction stage failed.
  #[error("tree-sitter extraction failed for {}: {source}", input.path.display())]
  Extraction {
    /// Complete source supplied to the successful parse and failed extraction.
    input:  SourceFile,
    /// Native parse tree, including any malformed-syntax observations.
    tree:   tree_sitter::Tree,
    /// Complete extracted prefix and interrupted-unit failure.
    source: Box<ExtractionError>,
  },
}

/// A tree-sitter-backed language analyzer.
///
/// Wraps a tree-sitter [`Language`](tree_sitter::Language), extraction query,
/// [`NodeMapping`], and file extensions to implement [`LanguageAnalyzer`].
///
/// # Example
///
/// ```
/// use dupes_core::analyzer::LanguageAnalyzer as _;
/// use dupes_treesitter::TreeSitterAnalyzer;
/// use dupes_treesitter::mapping::NodeMapping;
///
/// # /// Preserve the native query or example expectation failure.
/// # #[derive(Debug, thiserror::Error)]
/// # enum ExampleError {
/// #     /// The extraction query could not be compiled.
/// #     #[error(transparent)]
/// #     Query(#[from] tree_sitter::QueryError),
/// #     /// The configured extensions did not match the example contract.
/// #     #[error(transparent)]
/// #     Expectation(#[from] strict_test_support::TestFailure),
/// # }
/// # /// Construct and inspect a configured analyzer.
/// # fn main() -> Result<(), ExampleError> {
/// let analyzer = TreeSitterAnalyzer::new(
///   tree_sitter_python::LANGUAGE.into(),
///   &["py"],
///   "(function_definition name: (identifier) @name
///         parameters: (parameters) @parameters
///         body: (block) @body) @definition",
///   NodeMapping::new().identifiers(&["identifier"]).blocks(&["block"]),
/// )?;
/// strict_test_support::ensure(
///   analyzer.file_extensions() == ["py"],
///   "the configured analyzer supports Python files",
/// )?;
/// # Ok(())
/// # }
/// ```
pub struct TreeSitterAnalyzer<ResolveKind = KindResolver, DetectTest = fn(&str, tree_sitter::Node<'_>) -> bool> {
  /// Grammar used to parse each source file.
  language:      tree_sitter::Language,
  /// File extensions served by this configured analyzer.
  extensions:    Vec<&'static str>,
  /// Compiled query identifying code-unit definitions and their parts.
  query:         tree_sitter::Query,
  /// Language-owned normalization rules.
  mapping:       NodeMapping,
  /// Concrete callback resolving a captured definition's semantic kind.
  kind_resolver: ResolveKind,
  /// Concrete callback identifying captured definitions as test code.
  is_test:       DetectTest,
}

impl TreeSitterAnalyzer {
  /// Create a new tree-sitter analyzer.
  ///
  /// # Errors
  ///
  /// Returns an error if `query_source` is not a valid tree-sitter query
  /// for the given language.
  pub fn new(
    language: tree_sitter::Language,
    extensions: &[&'static str],
    query_source: &str,
    mapping: NodeMapping,
  ) -> Result<Self, tree_sitter::QueryError> {
    let query = tree_sitter::Query::new(&language, query_source)?;
    Ok(Self {
      language,
      extensions: extensions.to_vec(),
      query,
      mapping,
      kind_resolver: |_| CodeUnitKind::Function,
      is_test: |_, _| false,
    })
  }
}

impl<ResolveKind, DetectTest> TreeSitterAnalyzer<ResolveKind, DetectTest> {
  /// Set a callback to resolve `CodeUnitKind` from the tree-sitter node kind.
  ///
  /// The callback receives the `@definition` node's `kind()` string (e.g.,
  /// `"function_definition"`, `"lambda"`, `"class_definition"`) and should
  /// return the corresponding `CodeUnitKind`.
  ///
  /// Default: all nodes map to `CodeUnitKind::Function`.
  #[must_use]
  pub fn with_kind_resolver<NewResolveKind: Fn(&str) -> CodeUnitKind + Send + Sync + 'static>(
    self,
    kind_resolver: NewResolveKind,
  ) -> TreeSitterAnalyzer<NewResolveKind, DetectTest> {
    TreeSitterAnalyzer {
      language: self.language,
      extensions: self.extensions,
      query: self.query,
      mapping: self.mapping,
      kind_resolver,
      is_test: self.is_test,
    }
  }

  /// Set a callback to detect test code.
  ///
  /// The callback receives the function name and the `@definition` tree-sitter
  /// node, and should return `true` if the code unit is test code.
  #[must_use]
  pub fn with_test_detector<NewDetectTest: Fn(&str, tree_sitter::Node<'_>) -> bool + Send + Sync + 'static>(
    self,
    is_test: NewDetectTest,
  ) -> TreeSitterAnalyzer<ResolveKind, NewDetectTest> {
    TreeSitterAnalyzer {
      language: self.language,
      extensions: self.extensions,
      query: self.query,
      mapping: self.mapping,
      kind_resolver: self.kind_resolver,
      is_test,
    }
  }
}

impl<ResolveKind, DetectTest> LanguageAnalyzer for TreeSitterAnalyzer<ResolveKind, DetectTest>
where
  ResolveKind: Fn(&str) -> CodeUnitKind + Send + Sync,
  DetectTest: Fn(&str, tree_sitter::Node<'_>) -> bool + Send + Sync,
{
  type Error = TreeSitterParseError;

  fn file_extensions(&self) -> &[&str] {
    &self.extensions
  }

  fn parse_file(&self, path: &Path, source: &str, config: AnalysisConfig) -> Result<Vec<CodeUnit>, Self::Error> {
    let mut parser = tree_sitter::Parser::new();
    let input = || SourceFile {
      path:     path.to_path_buf(),
      contents: source.to_owned(),
    };
    parser
      .set_language(&self.language)
      .map_err(|failure| TreeSitterParseError::Language {
        input:  input(),
        source: failure,
      })?;
    let tree = parser.parse(source, None).ok_or_else(|| TreeSitterParseError::NoTree {
      input: input()
    })?;
    let extractor = CodeUnitExtractor::new(&self.query, &self.mapping, &self.kind_resolver, &self.is_test);
    extractor
      .extract(&tree, source.as_bytes(), path, config)
      .map_err(|failure| TreeSitterParseError::Extraction {
        input: input(),
        tree,
        source: Box::new(failure),
      })
  }
}

impl<ResolveKind, DetectTest> fmt::Debug for TreeSitterAnalyzer<ResolveKind, DetectTest> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TreeSitterAnalyzer")
      .field("extensions", &self.extensions)
      .field("kind_resolver", &"<closure>")
      .finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::collections::HashSet;
  use std::path::Path;

  use dupes_core::analyzer::LanguageAnalyzer as _;
  use dupes_core::code_unit::CodeUnit;
  use dupes_core::code_unit::CodeUnitKind;
  use dupes_core::config::AnalysisConfig;
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;

  use super::TreeSitterAnalyzer;
  use super::TreeSitterParseError;
  use crate::mapping::NodeMapping;

  /// Retain native setup and parse failures and the complete mismatching units.
  #[derive(Debug, thiserror::Error)]
  enum AnalyzerTestFailure {
    /// The fixture query could not be compiled.
    #[error(transparent)]
    Query(#[from] tree_sitter::QueryError),
    /// The analyzer could not parse a fixture.
    #[error(transparent)]
    Parse(#[from] TreeSitterParseError),
    /// The returned units did not satisfy the callback contract.
    #[error("{source}; returned units: {units:?}")]
    Units {
      /// Complete code units returned by the analyzer.
      units:  Vec<CodeUnit>,
      /// Failed semantic expectation.
      source: TestFailure,
    },
    /// Query rejection lost the native diagnostic or unexpectedly constructed an analyzer.
    #[error("{source}; query construction result: {outcome:?}")]
    QueryExpectation {
      /// Complete construction result for the invalid query.
      outcome: Box<Result<TreeSitterAnalyzer, tree_sitter::QueryError>>,
      /// Failed semantic expectation.
      source:  TestFailure,
    },
  }

  /// Custom callbacks retain captured state and preserve each other's configuration.
  #[test]
  fn callbacks_capture_state_without_changing_default_classification() -> Result<(), AnalyzerTestFailure> {
    let analyzer = TreeSitterAnalyzer::new(
      tree_sitter_python::LANGUAGE.into(),
      &["py"],
      "(function_definition name: (identifier) @name body: (block) @body) @definition",
      NodeMapping::new().identifiers(&["identifier"]).blocks(&["block"]),
    )?;
    let source = "def alpha(value):\n    return value\n\ndef beta(value):\n    return value\n";
    let config = AnalysisConfig {
      min_nodes: 1,
      min_lines: 0,
    };
    let defaults = analyzer.parse_file(Path::new("callbacks.py"), source, config)?;
    let kinds = HashMap::from([("function_definition", CodeUnitKind::Method)]);
    let test_names = HashSet::from(["alpha"]);
    let configured = analyzer
      .with_kind_resolver(move |node_kind| kinds.get(node_kind).copied().unwrap_or(CodeUnitKind::Function))
      .with_test_detector(move |name, _node| test_names.contains(name))
      .parse_file(Path::new("callbacks.py"), source, config)?;

    for (units, expected) in [
      (defaults, [
        ("alpha", CodeUnitKind::Function, false),
        ("beta", CodeUnitKind::Function, false),
      ]),
      (configured, [
        ("alpha", CodeUnitKind::Method, true),
        ("beta", CodeUnitKind::Method, false),
      ]),
    ] {
      let observed: Vec<_> = units.iter().map(|unit| (unit.name.as_str(), unit.kind, unit.is_test)).collect();
      ensure(
        observed == expected,
        "configured callbacks retain captured kinds and test membership while defaults remain unchanged",
      )
      .map_err(|failure| AnalyzerTestFailure::Units {
        units,
        source: failure,
      })?;
    }
    Ok(())
  }

  /// Invalid extraction queries return the parser's native query failure.
  #[test]
  fn invalid_query_returns_native_syntax_failure() -> Result<(), AnalyzerTestFailure> {
    let outcome = TreeSitterAnalyzer::new(tree_sitter_python::LANGUAGE.into(), &["py"], "(", NodeMapping::new());
    ensure(
      matches!(outcome, Err(ref source) if source.kind == tree_sitter::QueryErrorKind::Syntax),
      "an incomplete query returns its native syntax error without constructing an analyzer",
    )
    .map_err(|source| AnalyzerTestFailure::QueryExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }
}
