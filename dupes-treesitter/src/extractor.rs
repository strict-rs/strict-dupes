//! Query-based `CodeUnit` extraction from tree-sitter parse trees.
//!
//! Uses tree-sitter queries with named captures to identify function definitions,
//! then normalizes and fingerprints them into `CodeUnit`s for duplicate detection.

use std::fmt;
use std::path::Path;
use std::path::PathBuf;

use dupes_core::code_unit::CodeUnit;
use dupes_core::code_unit::CodeUnitKind;
use dupes_core::config::AnalysisConfig;
use dupes_core::fingerprint::Fingerprint;
use dupes_core::node::NormalizationContext;
use dupes_core::node::NormalizedNode;
use dupes_core::node::count_nodes;
use tree_sitter::StreamingIterator as _;

use crate::mapping::NodeMapping;
use crate::normalizer::NodeTextError;
use crate::normalizer::NormalizationError;
use crate::normalizer::node_bytes;
use crate::normalizer::node_text;
use crate::normalizer::normalize_ts_node;

/// Default callback signature for resolving a tree-sitter node's code-unit kind.
///
/// [`crate::TreeSitterAnalyzer::with_kind_resolver`] also accepts closures with
/// captured state, retaining their concrete types in the analyzer.
pub type KindResolver = fn(&str) -> CodeUnitKind;

/// An extraction failure with its source identity and completed code units.
#[derive(Debug, thiserror::Error)]
pub enum ExtractionError {
  /// Query evaluation cannot safely read the tree's range from the supplied bytes.
  #[error("extraction input for {} is incompatible with the tree: {source}", file.display())]
  Input {
    /// Path identifying the byte source supplied by the caller.
    file:   PathBuf,
    /// Native range and complete byte input that failed validation.
    source: Box<NodeTextError>,
  },
  /// A captured definition failed after any preceding units were extracted.
  #[error("extracting a definition at {range:?} in {} failed: {source}", file.display())]
  Unit {
    /// Path identifying this extraction attempt.
    file:      PathBuf,
    /// Native byte and point range of the interrupted definition.
    range:     tree_sitter::Range,
    /// Complete preceding units, including their fingerprints and normalized trees.
    completed: Vec<CodeUnit>,
    /// Failed stage and all completed state of the interrupted definition.
    source:    Box<UnitExtractionError>,
  },
}

/// A failed definition stage and the state established before that failure.
#[derive(Debug, thiserror::Error)]
pub enum UnitExtractionError {
  /// A captured name could not be read; the definition is not anonymous.
  #[error("reading the captured definition name failed: {0}")]
  Name(#[source] NodeTextError),
  /// Parameter normalization failed after the name was read.
  #[error("normalizing the signature of {name} failed: {source}")]
  Signature {
    /// Complete name read from the definition capture.
    name:    String,
    /// Placeholder assignments established before normalization stopped.
    context: NormalizationContext,
    /// Native failure and completed children of the interrupted signature.
    source:  NormalizationError,
  },
  /// Body normalization failed after the signature was completed.
  #[error("normalizing the body of {name} failed: {source}")]
  Body {
    /// Complete name read from the definition capture.
    name:      String,
    /// Complete normalized signature produced before the body failed.
    signature: NormalizedNode,
    /// Placeholder assignments from the signature and completed body work.
    context:   NormalizationContext,
    /// Native failure and completed children of the interrupted body.
    source:    NormalizationError,
  },
}

/// Query captures sufficient to extract one definition and its optional signature.
#[derive(Debug)]
struct DefinitionCapture<'tree> {
  /// Complete definition whose positions identify the unit.
  definition: tree_sitter::Node<'tree>,
  /// Body that will be normalized with the signature's placeholder context.
  body:       tree_sitter::Node<'tree>,
  /// Captured name; absence is the supported anonymous-definition case.
  name:       Option<tree_sitter::Node<'tree>>,
  /// Optional signature parameters.
  parameters: Option<tree_sitter::Node<'tree>>,
}

/// Locate one named capture while preserving its native tree lifetime.
fn captured_node<'tree>(captures: &[tree_sitter::QueryCapture<'tree>], index: Option<u32>) -> Option<tree_sitter::Node<'tree>> {
  captures
    .iter()
    .find(|capture| Some(capture.index) == index)
    .map(|capture| capture.node)
}

/// Extract code units using a compiled query and its language-specific mapping.
///
/// The query should use capture names to identify parts of function definitions:
/// - `@definition` — the entire function node (for line range)
/// - `@name` — the function name identifier
/// - `@body` — the function body block
/// - `@parameters` — the parameter list (optional)
///
/// Callbacks retain their concrete types and can borrow or own captured state.
pub struct CodeUnitExtractor<'query, ResolveKind, DetectTest> {
  /// Compiled capture query shared by extraction attempts.
  query:         &'query tree_sitter::Query,
  /// Language-specific normalization rules for captured syntax.
  mapping:       &'query NodeMapping,
  /// Resolve a captured definition's grammar kind to its semantic unit kind.
  kind_for_node: ResolveKind,
  /// Classify each captured definition as test or ordinary code.
  is_test:       DetectTest,
}

impl<'query, ResolveKind, DetectTest> CodeUnitExtractor<'query, ResolveKind, DetectTest>
where
  ResolveKind: Fn(&str) -> CodeUnitKind,
  DetectTest: Fn(&str, tree_sitter::Node<'_>) -> bool,
{
  /// Configure extraction with a compiled query, mapping, and callbacks.
  ///
  /// `kind_for_node` receives the captured definition's grammar kind. `is_test`
  /// receives its extracted name and native definition node.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Construct the generic extraction boundary while retaining concrete language callbacks"
  )]
  pub const fn new(
    query: &'query tree_sitter::Query,
    mapping: &'query NodeMapping,
    kind_for_node: ResolveKind,
    is_test: DetectTest,
  ) -> Self {
    Self {
      query,
      mapping,
      kind_for_node,
      is_test,
    }
  }
}

impl<ResolveKind, DetectTest> CodeUnitExtractor<'_, ResolveKind, DetectTest>
where
  ResolveKind: Fn(&str) -> CodeUnitKind,
  DetectTest: Fn(&str, tree_sitter::Node<'_>) -> bool,
{
  /// Normalize, fingerprint, and select code units from one parsed byte source.
  ///
  /// Captures lacking a definition or body do not form code units. Minimum source
  /// line counts and normalized node counts select eligible units.
  ///
  /// # Errors
  ///
  /// Returns incompatible source ranges or unreadable required text with native
  /// causes, complete preceding units, and the interrupted definition's state.
  pub fn extract(
    &self,
    tree: &tree_sitter::Tree,
    source: &[u8],
    file_path: &Path,
    config: AnalysisConfig,
  ) -> Result<Vec<CodeUnit>, ExtractionError> {
    let root = tree.root_node();
    // The native byte-slice text provider indexes captures while evaluating query
    // predicates. Validate its containing range before entering that provider.
    if let Err(failure) = node_bytes(&root, source) {
      return Err(ExtractionError::Input {
        file:   file_path.to_path_buf(),
        source: Box::new(failure),
      });
    }
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(self.query, root, source);

    // Resolve capture indices by name
    let definition_index = self.query.capture_index_for_name("definition");
    let name_index = self.query.capture_index_for_name("name");
    let body_index = self.query.capture_index_for_name("body");
    let parameters_index = self.query.capture_index_for_name("parameters");

    let mut units = Vec::new();

    while let Some(query_match) = matches.next() {
      let definition_node = captured_node(query_match.captures, definition_index);
      let name_node = captured_node(query_match.captures, name_index);
      let body_node = captured_node(query_match.captures, body_index);
      let parameters_node = captured_node(query_match.captures, parameters_index);

      // We need at least a definition and body to create a code unit
      let Some(definition) = definition_node else { continue };
      let Some(body) = body_node else { continue };

      let captured = DefinitionCapture {
        definition,
        body,
        name: name_node,
        parameters: parameters_node,
      };
      match self.extract_unit(&captured, source, file_path, config) {
        Ok(Some(unit)) => units.push(unit),
        Ok(None) => {}
        Err(failure) => {
          return Err(ExtractionError::Unit {
            file:      file_path.to_path_buf(),
            range:     definition.range(),
            completed: units,
            source:    failure,
          });
        }
      }
    }

    Ok(units)
  }

  /// Complete one captured unit or retain the stage that interrupted its construction.
  fn extract_unit(
    &self,
    captured: &DefinitionCapture<'_>,
    source: &[u8],
    file_path: &Path,
    config: AnalysisConfig,
  ) -> Result<Option<CodeUnit>, Box<UnitExtractionError>> {
    let name = captured
      .name
      .map_or_else(
        || {
          let line = captured.definition.start_position().row.saturating_add(1);
          Ok(format!("anonymous at {}:{line}", file_path.display()))
        },
        |node| node_text(&node, source).map(str::to_owned),
      )
      .map_err(|failure| Box::new(UnitExtractionError::Name(failure)))?;

    // Line numbers: tree-sitter is 0-based, dupes-core is 1-based.
    let line_start = captured.definition.start_position().row.saturating_add(1);
    let line_end = captured.definition.end_position().row.saturating_add(1);
    let line_count = line_end.saturating_sub(line_start).saturating_add(1);
    if line_count < config.min_lines {
      return Ok(None);
    }

    // Parameters and body share one fresh placeholder context per code unit.
    let mut context = NormalizationContext::new();
    let signature = match captured
      .parameters
      .map(|parameters| normalize_ts_node(&parameters, source, self.mapping, &mut context))
      .transpose()
    {
      Ok(signature) => signature.unwrap_or_else(NormalizedNode::none),
      Err(failure) => {
        return Err(Box::new(UnitExtractionError::Signature {
          name,
          context,
          source: failure,
        }));
      }
    };
    let normalized_body = match normalize_ts_node(&captured.body, source, self.mapping, &mut context) {
      Ok(body) => body,
      Err(failure) => {
        return Err(Box::new(UnitExtractionError::Body {
          name,
          signature,
          context,
          source: failure,
        }));
      }
    };

    let node_count = count_nodes(&signature).saturating_add(count_nodes(&normalized_body));
    if node_count < config.min_nodes {
      return Ok(None);
    }

    let fingerprint = Fingerprint::from_sig_and_body(&signature, &normalized_body);
    let test_code = (self.is_test)(&name, captured.definition);
    Ok(Some(CodeUnit {
      suppressed: None,
      parent_chain: None,
      kind: (self.kind_for_node)(captured.definition.kind()),
      name,
      file: file_path.to_path_buf(),
      line_start,
      line_end,
      signature,
      body: normalized_body,
      fingerprint,
      node_count,
      parent_name: None,
      is_test: test_code,
    }))
  }
}

impl<ResolveKind, DetectTest> fmt::Debug for CodeUnitExtractor<'_, ResolveKind, DetectTest> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CodeUnitExtractor")
      .field("query", &self.query)
      .field("mapping", &self.mapping)
      .finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests {
  use std::path::Path;
  use std::slice;

  use dupes_core::code_unit::CodeUnit;
  use dupes_core::code_unit::CodeUnitKind;
  use dupes_core::config::AnalysisConfig;
  use dupes_core::node::PlaceholderKind;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;

  use super::CodeUnitExtractor;
  use super::ExtractionError;
  use super::UnitExtractionError;
  use crate::mapping::NodeMapping;
  use crate::normalizer::NodeTextError;
  use crate::normalizer::NormalizationError;

  /// Keep fixture setup, native extraction failures, and complete comparison outcomes.
  #[derive(Debug, thiserror::Error)]
  enum ExtractorTestFailure {
    /// The parser rejected the fixture grammar.
    #[error(transparent)]
    Language(#[from] tree_sitter::LanguageError),
    /// The extraction query failed to compile.
    #[error(transparent)]
    Query(#[from] tree_sitter::QueryError),
    /// A valid fixture failed extraction.
    #[error(transparent)]
    Extraction(#[from] ExtractionError),
    /// The parser produced no tree.
    #[error("no tree was produced for {input:?}")]
    NoTree {
      /// Complete fixture supplied to the parser.
      input: String,
    },
    /// The fixture lacks the named definition part.
    #[error("the fixture lacks {field}: {tree:?}")]
    MissingCapture {
      /// Native tree used to locate the intended corruption.
      tree:  tree_sitter::Tree,
      /// Definition field required by the scenario.
      field: &'static str,
    },
    /// The selected fixture node is outside its source buffer.
    #[error("cannot corrupt the fixture node at {range:?}")]
    SourceRange {
      /// Complete bytes before fixture corruption.
      input: Vec<u8>,
      /// Native range selected from the fixture tree.
      range: tree_sitter::Range,
    },
    /// An extraction attempt violated its complete success or failure contract.
    #[error("{source}; baseline: {baseline:?}; attempted extraction: {outcome:?}; tree: {tree:?}")]
    Evidence {
      /// Complete successful extraction from the original source.
      baseline: Vec<CodeUnit>,
      /// Complete outcome after changing only the scenario's input bytes.
      outcome:  Box<Result<Vec<CodeUnit>, ExtractionError>>,
      /// Native tree used for both attempts.
      tree:     tree_sitter::Tree,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
  }

  /// Parse source through the same native grammar used by the bridge's consumers.
  fn parse(source: &str) -> Result<tree_sitter::Tree, ExtractorTestFailure> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_python::LANGUAGE.into())?;
    parser.parse(source, None).ok_or_else(|| ExtractorTestFailure::NoTree {
      input: source.to_owned()
    })
  }

  /// Select an identifier within a captured definition field by its native syntax kind.
  fn first_identifier<'tree>(node: &tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>> {
    if node.kind() == "identifier" {
      return Some(*node);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find_map(|child| first_identifier(&child))
  }

  /// Corrupt a required field in the second function and compare the entire completed prefix.
  fn check_interrupted_definition(
    field: &'static str,
    check: impl FnOnce(&CodeUnit, &mut UnitExtractionError, &[u8]) -> Result<(), ConditionFailure>,
  ) -> Result<(), ExtractorTestFailure> {
    let source = "def first(value):\n    return value\n\ndef second(value):\n    return value\n";
    let tree = parse(source)?;
    let definition = tree
      .root_node()
      .named_child(1)
      .ok_or_else(|| ExtractorTestFailure::MissingCapture {
        tree:  tree.clone(),
        field: "second definition",
      })?;
    let identifier = definition
      .child_by_field_name(field)
      .and_then(|child| first_identifier(&child))
      .ok_or_else(|| ExtractorTestFailure::MissingCapture {
        tree: tree.clone(),
        field,
      })?;
    let query = tree_sitter::Query::new(
      &tree_sitter_python::LANGUAGE.into(),
      "(function_definition name: (identifier) @name parameters: (parameters) @parameters body: (block) @body) @definition",
    )?;
    let mapping = NodeMapping::new()
      .identifiers(&["identifier"])
      .blocks(&["block"])
      .returns(&["return_statement"]);
    let extractor = CodeUnitExtractor::new(&query, &mapping, |_| CodeUnitKind::Function, |_, _| false);
    let config = AnalysisConfig {
      min_nodes: 1,
      min_lines: 1,
    };
    let baseline = extractor.extract(&tree, source.as_bytes(), Path::new("partial.py"), config)?;
    let mut bytes = source.as_bytes().to_vec();
    let Some(byte) = bytes.get_mut(identifier.start_byte()) else {
      return Err(ExtractorTestFailure::SourceRange {
        input: bytes,
        range: identifier.range(),
      });
    };
    *byte = 0xff;
    let mut outcome = extractor.extract(&tree, &bytes, Path::new("partial.py"), config);
    let expectation = if let [ref first, ref second] = *baseline.as_slice()
      && let Err(ExtractionError::Unit {
        ref file,
        range,
        ref completed,
        source: ref mut failure,
      }) = outcome
    {
      ensure(
        (first.name.as_str(), second.name.as_str()) == ("first", "second")
          && file.as_path() == Path::new("partial.py")
          && range == definition.range()
          && completed.as_slice() == slice::from_ref(first),
        "a failed second definition preserves the complete first unit and the interrupted definition's identity",
      )
      .map(drop)
      .and_then(|()| check(second, failure.as_mut(), &bytes))
    } else {
      ensure(
        false,
        "the original pair must parse and the second corrupted definition must fail as a unit",
      )
      .map(drop)
    };
    expectation.map_err(|failure| ExtractorTestFailure::Evidence {
      baseline,
      outcome: Box::new(outcome),
      tree,
      source: failure,
    })
  }

  /// An unreadable captured name is a typed failure rather than an anonymous definition.
  #[test]
  fn unreadable_name_retains_completed_units() -> Result<(), ExtractorTestFailure> {
    check_interrupted_definition("name", |_, failure, bytes| {
      ensure(
        matches!(*failure, UnitExtractionError::Name(NodeTextError::Utf8 { ref input, source, .. })
          if input.as_slice() == bytes && source.valid_up_to() == 0 && source.error_len() == Some(1)),
        "a captured name that cannot be decoded retains the complete input and native UTF-8 cause",
      )
      .map(drop)
    })
  }

  /// Signature failure preserves the decoded name and the interrupted normalization.
  #[test]
  fn signature_failure_retains_name_and_context() -> Result<(), ExtractorTestFailure> {
    check_interrupted_definition("parameters", |second, failure, bytes| {
      let UnitExtractionError::Signature {
        ref name,
        ref mut context,
        source: ref normalization,
      } = *failure
      else {
        return ensure(false, "corrupting a captured parameter must fail during signature normalization").map(drop);
      };
      ensure(
        *name == second.name
          && context.placeholder("value", PlaceholderKind::Variable) == 0
          && matches!(*normalization, NormalizationError::Children { ref kind, ref completed, source: ref text_error, .. }
            if kind.as_str() == "parameters" && completed.is_empty()
              && matches!(**text_error, NormalizationError::Text(NodeTextError::Utf8 { ref input, source, .. })
                if input.as_slice() == bytes && source.valid_up_to() == 0 && source.error_len() == Some(1))),
        "signature failure retains the known name, untouched placeholder context, and original text failure",
      )
      .map(drop)
    })
  }

  /// Body failure preserves the complete signature and its shared placeholder assignments.
  #[test]
  fn body_failure_retains_signature_and_context() -> Result<(), ExtractorTestFailure> {
    check_interrupted_definition("body", |second, failure, bytes| {
      let UnitExtractionError::Body {
        ref name,
        ref signature,
        ref mut context,
        source: ref normalization,
      } = *failure
      else {
        return ensure(false, "corrupting the returned identifier must fail during body normalization").map(drop);
      };
      ensure(
        *name == second.name
          && *signature == second.signature
          && context.placeholder("value", PlaceholderKind::Variable) == 0
          && context.placeholder("after", PlaceholderKind::Variable) == 1
          && matches!(*normalization, NormalizationError::Children { kind: ref block_kind, completed: ref block_completed, source: ref return_error, .. }
            if block_kind == "block" && block_completed.is_empty()
              && matches!(**return_error, NormalizationError::Children { kind: ref return_kind, completed: ref return_completed, source: ref text_error, .. }
                if return_kind == "return_statement" && return_completed.is_empty()
                  && matches!(**text_error, NormalizationError::Text(NodeTextError::Utf8 { ref input, source, .. })
                    if input.as_slice() == bytes && source.valid_up_to() == 0 && source.error_len() == Some(1)))),
        "body failure retains the completed signature, its placeholders, and the nested native text failure",
      ).map(drop)
    })
  }

  /// Source validation precedes native predicates that index captured text directly.
  #[test]
  fn query_predicates_reject_out_of_bounds_input_without_indexing() -> Result<(), ExtractorTestFailure> {
    let source = "def first():\n    pass\n";
    let tree = parse(source)?;
    let query = tree_sitter::Query::new(
      &tree_sitter_python::LANGUAGE.into(),
      r#"((function_definition name: (identifier) @name body: (block) @body) @definition (#eq? @name "first"))"#,
    )?;
    let mapping = NodeMapping::new().blocks(&["block"]);
    let extractor = CodeUnitExtractor::new(&query, &mapping, |_| CodeUnitKind::Function, |_, _| false);
    let config = AnalysisConfig {
      min_nodes: 1,
      min_lines: 1,
    };
    let baseline = extractor.extract(&tree, source.as_bytes(), Path::new("predicate.py"), config)?;
    let outcome = extractor.extract(&tree, b"def", Path::new("predicate.py"), config);
    ensure(
      matches!(*baseline.as_slice(), [ref unit] if unit.name == "first")
        && matches!(outcome, Err(ExtractionError::Input { ref file, source: ref failure })
          if file == Path::new("predicate.py")
            && matches!(**failure, NodeTextError::OutOfBounds { ref input, range }
              if input == b"def" && range == tree.root_node().range())),
      "a valid predicate query succeeds, while a truncated input retains its full bytes and native containing range",
    )
    .map(drop)
    .map_err(|failure| ExtractorTestFailure::Evidence {
      baseline,
      outcome: Box::new(outcome),
      tree,
      source: failure,
    })
  }
}
