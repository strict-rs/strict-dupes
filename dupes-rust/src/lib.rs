//! Rust language analyzer for the `dupes-core` duplicate detection framework.
//!
//! This crate provides [`RustAnalyzer`], which implements the
//! [`dupes_core::analyzer::LanguageAnalyzer`] trait using `syn` for AST parsing
//! and normalization.

pub mod normalizer;
pub mod parser;

use std::path::Path;

use dupes_core::analyzer::LanguageAnalyzer;
use dupes_core::code_unit::CodeUnit;
use dupes_core::config::AnalysisConfig;
use parser::RustParseError;

/// Rust language analyzer using `syn` for AST parsing.
#[derive(Clone, Copy, Debug)]
pub struct RustAnalyzer;

impl RustAnalyzer {
  /// Create the analyzer.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Keep the explicit analyzer constructor as the frontend construction boundary"
  )]
  pub const fn new() -> Self {
    Self
  }
}

impl Default for RustAnalyzer {
  fn default() -> Self {
    Self::new()
  }
}

impl LanguageAnalyzer for RustAnalyzer {
  type Error = RustParseError;

  fn file_extensions(&self) -> &[&str] {
    &["rs"]
  }

  fn parse_file(&self, path: &Path, source: &str, config: AnalysisConfig) -> Result<Vec<CodeUnit>, Self::Error> {
    parser::parse_source(path, source, config.min_nodes, config.min_lines)
  }

  fn parse_sub_units(&self, path: &Path, source: &str, _config: AnalysisConfig, min_nodes: usize) -> Result<Vec<CodeUnit>, Self::Error> {
    parser::parse_sub_units(path, source, min_nodes)
  }
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::io;
  use std::path::Path;

  use dupes_core::AnalysisResult;
  use dupes_core::SourceAnalysis;
  use dupes_core::analyze_with_generic;
  use dupes_core::analyzer::LanguageAnalyzer as _;
  use dupes_core::code_unit::CodeUnit;
  use dupes_core::code_unit::DetectionDimension;
  use dupes_core::config::AnalysisConfig;
  use dupes_core::config::Config;
  use dupes_core::error::AnalysisError;
  use dupes_core::error::AnalysisFailure;
  use dupes_core::ignore::IgnoreFileError;
  use dupes_core::ignore::ignore_file_path;
  use dupes_core::source::SourceReadError;
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;

  use super::RustAnalyzer;
  use crate::parser::RustParseError;

  /// Complete Rust pipeline success or partial failure.
  type PipelineOutcome = Result<AnalysisResult<RustParseError>, AnalysisError<RustParseError>>;
  /// Valid source retains both production and test definitions before filtering.
  const VALID_SOURCE: &str = "fn production() { let count = 1; }\n#[test]\nfn checked_example() { let total = 2; }\n";
  /// Invalid Rust fixture retained in its native parse error.
  const REJECTED_SOURCE: &str = "fn rejected( {";
  /// Undecodable source fixture retained in the native UTF-8 error.
  const INVALID_BYTES: [u8; 3] = [b'f', b'n', 0xff];
  /// Malformed ignore document used to fail after source analysis.
  const INVALID_REGISTRY: &str = "[[ignore]\n";

  /// A failed assertion retaining every native analyzer outcome.
  #[derive(Debug, thiserror::Error)]
  #[error("analyzer contract failed: {source}; outcomes: {outcomes:?}")]
  struct AnalyzerTestFailure {
    /// Complete native parse results observed by the test.
    outcomes: Vec<Result<Vec<CodeUnit>, RustParseError>>,
    /// Behavioral expectation that failed.
    source:   TestFailure,
  }

  /// Native fixture failures or a full pipeline result that violated its contract.
  #[derive(Debug, thiserror::Error)]
  enum PipelineTestFailure {
    /// Creating or writing a fixture failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// An expectation failed with the full analysis or partial failure retained.
    #[error("pipeline contract failed: {source}; outcome: {outcome:?}")]
    Expectation {
      /// Complete native pipeline result.
      outcome: Box<PipelineOutcome>,
      /// Failed behavioral expectation.
      source:  TestFailure,
    },
  }

  /// Preserve native parse results across a failed behavioral assertion.
  fn check_results(
    outcomes: Vec<Result<Vec<CodeUnit>, RustParseError>>,
    check: impl FnOnce(&[Result<Vec<CodeUnit>, RustParseError>]) -> Result<(), TestFailure>,
  ) -> Result<(), AnalyzerTestFailure> {
    check(&outcomes).map_err(|source| AnalyzerTestFailure {
      outcomes,
      source,
    })
  }

  #[test]
  fn rust_analyzer_through_trait() -> Result<(), AnalyzerTestFailure> {
    let analyzer = RustAnalyzer::new();
    let config = AnalysisConfig {
      min_nodes: 1,
      min_lines: 0,
    };
    let source = "
            fn foo(x: i32) -> i32 {
                let y = x + 1;
                y * 2
            }
            #[test]
            fn test_foo() {
                let z = 1;
                let w = z + 1;
                assert_eq!(w, 2);
            }
        ";
    let path = Path::new("test.rs");
    check_results(vec![analyzer.parse_file(path, source, config)], |outcomes| {
      let [Ok(ref units)] = *outcomes else {
        return ensure(false, "valid source must parse through the analyzer trait");
      };
      ensure(
        units
          .iter()
          .map(|unit| (unit.name.as_str(), unit.is_test, analyzer.is_test_code(unit)))
          .collect::<Vec<_>>()
          == [("foo", false, false), ("test_foo", true, true)],
        "retain production and test functions with consistent native and trait-level test classification",
      )
    })
  }

  #[test]
  fn parse_failures_remain_native_through_the_trait() -> Result<(), AnalyzerTestFailure> {
    let analyzer = RustAnalyzer::new();
    let path = Path::new("rejected.rs");
    let source = "fn broken( {";
    let config = AnalysisConfig {
      min_nodes: 1,
      min_lines: 0,
    };
    check_results(
      vec![
        analyzer.parse_file(path, source, config),
        analyzer.parse_sub_units(path, source, config, 1),
      ],
      |outcomes| {
        ensure(
          outcomes.iter().all(|outcome| {
            matches!(outcome.as_ref(), Err(failure) if failure.input.path == path && failure.input.contents == source && failure.source.span().start().line == 1)
          }),
          "both parse entry points retain the original source and typed syn diagnostic",
        )
      },
    )
  }

  /// Check every original source outcome across successful and failed registry handling.
  #[allow(
    clippy::single_call_fn,
    reason = "The joint source contract stays readable separately from filesystem fixture preparation and repeated registry states."
  )]
  fn check_pipeline_sources(outcome: &PipelineOutcome, root: &Path, registry_is_invalid: bool) -> Result<(), TestFailure> {
    let (sources, stats) = match outcome.as_ref() {
      Ok(analysis) => {
        ensure(!registry_is_invalid, "a malformed registry must return a typed analysis failure")?;
        (&analysis.sources, Some(&analysis.stats))
      }
      Err(failure) => {
        ensure(registry_is_invalid, "source failures remain nonfatal when the registry is readable")?;
        ensure(
          matches!(*failure.source, AnalysisFailure::Ignore(IgnoreFileError::Decode { ref path, ref contents, .. })
                if *path == ignore_file_path(root) && contents == INVALID_REGISTRY),
          "retain the native registry decoding failure and its exact input",
        )?;
        (&failure.analysis.sources, failure.analysis.stats.as_ref())
      }
    };
    let [
      SourceAnalysis::Ast(Ok(ref valid)),
      SourceAnalysis::Ast(Ok(ref rejected)),
      SourceAnalysis::Ast(Err(SourceReadError::Utf8 {
        path: ref decoded_path,
        source: ref utf8,
      })),
      SourceAnalysis::Ast(Err(SourceReadError::Read {
        path: ref unread_path,
        source: ref read,
      })),
    ] = *sources.as_slice()
    else {
      return ensure(false, "retain all four native file outcomes in request order");
    };
    ensure(
      valid.file.path == root.join("valid.rs")
        && valid.file.contents == VALID_SOURCE
        && rejected.file.path == root.join("rejected.rs")
        && rejected.file.contents == REJECTED_SOURCE,
      "retain complete successful source reads even when parsing or later registry loading fails",
    )?;
    let Ok(parsed) = valid.parsed.as_ref() else {
      return ensure(false, "the valid source must retain its extracted units");
    };
    ensure(
      parsed
        .top_level
        .iter()
        .map(|unit| (unit.name.as_str(), unit.is_test))
        .collect::<Vec<_>>()
        == [("production", false), ("checked_example", true)]
        && matches!(parsed.sub_units.as_ref().map(Result::as_ref), Some(Ok(sub_units)) if sub_units.is_empty())
        && stats.is_some_and(|completed| completed.total_code_units == 1),
      "test exclusion changes the analyzed population while retaining both original units and the completed empty sub-unit parse",
    )?;
    ensure(
      matches!(rejected.parsed.as_ref(), Err(failure)
            if failure.input == rejected.file && failure.source.span().start().line == 1),
      "retain the typed Rust diagnostic and rejected source without running sub-unit parsing",
    )?;
    ensure(
      *decoded_path == root.join("bytes.rs")
        && utf8.as_bytes() == INVALID_BYTES
        && *unread_path == root.join("missing.rs")
        && read.kind() == io::ErrorKind::NotFound
        && read.raw_os_error().is_some(),
      "retain undecodable bytes and the original operating-system read failure",
    )
  }

  #[test]
  fn pipeline_preserves_file_outcomes_before_and_after_registry_failure() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let files = ["valid.rs", "rejected.rs", "bytes.rs", "missing.rs"].map(|name| workspace.path().join(name));
    for (name, contents) in [
      ("valid.rs", VALID_SOURCE.as_bytes()),
      ("rejected.rs", REJECTED_SOURCE.as_bytes()),
      ("bytes.rs", INVALID_BYTES.as_slice()),
    ] {
      fs::write(workspace.path().join(name), contents)?;
    }
    let mut config = Config {
      root: workspace.path().to_path_buf(),
      min_nodes: 1,
      min_lines: 0,
      exclude_tests: true,
      sub_function: true,
      min_sub_nodes: 1,
      ..Config::default()
    };
    config.enable_only_dimensions([DetectionDimension::Ast, DetectionDimension::SubAst]);
    let registry_path = ignore_file_path(workspace.path());
    for registry_is_invalid in [false, true] {
      if registry_is_invalid {
        fs::write(&registry_path, INVALID_REGISTRY)?;
      }
      let outcome = analyze_with_generic(&RustAnalyzer::new(), &files, &[], &config);
      check_pipeline_sources(&outcome, workspace.path(), registry_is_invalid).map_err(|source| PipelineTestFailure::Expectation {
        outcome: Box::new(outcome),
        source,
      })?;
    }
    Ok(())
  }
}
