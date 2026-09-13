//! Language-agnostic core of the `cargo-dupes` / `code-dupes` duplicate
//! detection pipeline.
//!
//! Language analyzers implement [`analyzer::LanguageAnalyzer`] and feed
//! [`analyze`] / [`analyze_with_generic`], which normalize, fingerprint,
//! group, suppression-tag, ignore-filter, and aggregate findings into an
//! [`AnalysisResult`] rendered by the [`output`] reporters.

pub mod analysis;
pub mod analyzer;
pub mod calculation;
pub mod cli;
pub mod code_unit;
pub mod config;
pub mod error;
pub mod extractor;
pub mod fingerprint;
pub mod grouper;
pub mod ignore;
pub mod node;
pub mod output;
pub mod scanner;
pub mod similarity;
pub mod source;
pub mod suppression;
pub mod text_units;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::Debug;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
#[cfg(test)]
use std::string::FromUtf8Error;

use analyzer::LanguageAnalyzer;
use code_unit::CodeUnit;
use code_unit::CodeUnitKind;
use code_unit::DetectionDimension;
use config::Config;
use error::AnalysisError;
use error::AnalysisFailure;
use error::CoverageFailure;
use error::CoverageFailureCause;
use error::SuppressionCountFailure;
use error::SuppressionPopulation;
use error::UnitSpanFailure;
use fingerprint::Fingerprint;
use grouper::DuplicateGroup;
use grouper::DuplicationStats;
use grouper::MatchKind;
use ignore::IgnoreFileLoad;
use node::NodeKind;
use node::NormalizedNode;
#[cfg(test)]
use output::ReportError;
#[cfg(test)]
use serde_json::Value;
use source::SourceFile;
use source::SourceReadError;
#[cfg(test)]
use strict_test_support::ComparisonFailure;
#[cfg(test)]
use strict_test_support::ConditionFailure;
use suppression::RuleId;
use suppression::SuppressionWarning;
use text_units::TextUnits;

/// Minimum fraction explained by one precise AST group before a window is tagged.
const PRECISE_COVERAGE_SUPPRESSION_RATIO: f64 = 0.8;
/// Minimum fraction explained by one wider group in the same detection dimension.
const SAME_DIMENSION_OVERLAP_SUPPRESSION_RATIO: f64 = 0.8;

/// Split a borrowed sequence into maximal adjacent runs using the supplied boundary rule.
fn split_runs_by<T>(items: &[T], same_run: impl FnMut(&T, &T) -> bool) -> Vec<&[T]> {
  items.chunk_by(same_run).collect()
}

/// Typed output and expectation failures from reporter behavior tests.
#[cfg(test)]
#[derive(Debug, thiserror::Error)]
enum ReportTestFailure {
  /// Complete observed and expected JSON reports differed.
  #[error(transparent)]
  JsonComparison(#[from] ComparisonFailure<Value, Value>),
  /// Complete observed and expected text reports differed.
  #[error(transparent)]
  TextComparison(#[from] ComparisonFailure<String, String>),
  /// Rendering failed after producing the retained output prefix.
  #[error("report rendering failed")]
  Render {
    /// Bytes successfully written before the failure.
    output: Vec<u8>,
    /// Native rendering failure.
    source: ReportError,
  },
  /// A renderer's outcome differed from the expected output contract.
  #[error("report outcome expectation failed: {source}")]
  RenderExpectation {
    /// Complete rendering outcome, including native encoding or writer errors.
    outcome: Box<Result<(), ReportError>>,
    /// Bytes present after rendering stopped.
    output:  Vec<u8>,
    /// Original assertion failure.
    source:  ConditionFailure,
  },
  /// Text decoding failed, retaining the complete byte buffer.
  #[error(transparent)]
  Utf8(#[from] FromUtf8Error),
  /// A rendered JSON document could not be decoded.
  #[error("rendered report is not valid JSON")]
  Json {
    /// Complete bytes supplied to the decoder.
    output: Vec<u8>,
    /// Native JSON decoding failure.
    source: serde_json::Error,
  },
  /// A JSON report violated an expectation.
  #[error("JSON report expectation failed: {source}")]
  JsonExpectation {
    /// Complete parsed document observed by the test.
    document: Value,
    /// Original assertion failure.
    source:   ConditionFailure,
  },
  /// A text report violated an expectation.
  #[error("text report expectation failed: {source}")]
  TextExpectation {
    /// Complete rendered text observed by the test.
    output: String,
    /// Original assertion failure.
    source: ConditionFailure,
  },
}

/// Check rendering while preserving its complete native outcome and output bytes on mismatch.
#[cfg(test)]
fn check_render(
  outcome: Result<(), ReportError>,
  output: Vec<u8>,
  check: impl FnOnce(&Result<(), ReportError>, &[u8]) -> Result<(), ConditionFailure>,
) -> Result<(), ReportTestFailure> {
  check(&outcome, &output).map_err(|source| ReportTestFailure::RenderExpectation {
    outcome: Box::new(outcome),
    output,
    source,
  })
}

/// Capture a renderer's complete output or its prefix and native failure.
#[cfg(test)]
fn render_bytes(render: impl FnOnce(&mut Vec<u8>) -> Result<(), ReportError>) -> Result<Vec<u8>, ReportTestFailure> {
  let mut output = Vec::new();
  match render(&mut output) {
    Ok(()) => Ok(output),
    Err(source) => Err(ReportTestFailure::Render {
      output,
      source,
    }),
  }
}

/// Render and decode JSON without dropping bytes on decoder failure.
#[cfg(test)]
fn render_json(render: impl FnOnce(&mut Vec<u8>) -> Result<(), ReportError>) -> Result<Value, ReportTestFailure> {
  let output = render_bytes(render)?;
  serde_json::from_slice(&output).map_err(|source| ReportTestFailure::Json {
    output,
    source,
  })
}

/// Retain the complete JSON document when a report assertion fails.
#[cfg(test)]
fn check_json(document: Value, check: impl FnOnce(&Value) -> Result<(), ConditionFailure>) -> Result<(), ReportTestFailure> {
  check(&document).map_err(|source| ReportTestFailure::JsonExpectation {
    document,
    source,
  })
}

/// Render text and preserve its decoded content or native decoding failure.
#[cfg(test)]
fn render_text(render: impl FnOnce(&mut Vec<u8>) -> Result<(), ReportError>) -> Result<String, ReportTestFailure> {
  Ok(String::from_utf8(render_bytes(render)?)?)
}

/// Retain the complete text report when an assertion fails.
#[cfg(test)]
fn check_text(output: String, check: impl FnOnce(&str) -> Result<(), ConditionFailure>) -> Result<(), ReportTestFailure> {
  check(&output).map_err(|source| ReportTestFailure::TextExpectation {
    output,
    source,
  })
}

/// Identity used by the shared opaque-signature fixture.
#[cfg(test)]
fn opaque_fingerprint() -> Fingerprint {
  Fingerprint::from_node(&NormalizedNode::leaf(NodeKind::Opaque))
}

/// Identity of an empty normalized block.
#[cfg(test)]
fn block_fingerprint() -> Fingerprint {
  Fingerprint::from_node(&NormalizedNode::with_children(NodeKind::Block, vec![]))
}

/// Build a complete source member with the requested identity and location.
#[cfg(test)]
fn make_unit(name: &str, file: &str, line_start: usize, line_end: usize) -> CodeUnit {
  CodeUnit {
    suppressed: None,
    parent_chain: None,
    kind: CodeUnitKind::Function,
    name: name.to_owned(),
    file: PathBuf::from(file),
    line_start,
    line_end,
    signature: NormalizedNode::leaf(NodeKind::Opaque),
    body: NormalizedNode::with_children(NodeKind::Block, vec![]),
    fingerprint: opaque_fingerprint(),
    node_count: 10,
    parent_name: None,
    is_test: false,
  }
}

/// Build a group in the requested dimension without invented suppression metadata.
#[cfg(test)]
const fn duplicate_group(
  dimension: DetectionDimension,
  match_kind: MatchKind,
  fingerprint: Fingerprint,
  similarity: f64,
  members: Vec<CodeUnit>,
) -> DuplicateGroup {
  DuplicateGroup {
    suppressed: None,
    also_seen: Vec::new(),
    dimension,
    match_kind,
    fingerprint,
    members,
    similarity,
  }
}

/// Build an exact AST group using the shared opaque identity.
#[cfg(test)]
fn exact_group(members: Vec<CodeUnit>) -> DuplicateGroup {
  duplicate_group(DetectionDimension::Ast, MatchKind::Exact, opaque_fingerprint(), 1.0, members)
}

/// Build a near AST group with the supplied identity and score.
#[cfg(test)]
const fn near_group(fingerprint: Fingerprint, similarity: f64, members: Vec<CodeUnit>) -> DuplicateGroup {
  duplicate_group(DetectionDimension::Ast, MatchKind::Near, fingerprint, similarity, members)
}

/// Build AST statistics with other dimensions and accounting fields empty.
#[cfg(test)]
fn stats(
  total_code_units: usize,
  total_lines: usize,
  exact_duplicate_groups: usize,
  exact_duplicate_units: usize,
  near_duplicate_groups: usize,
  near_duplicate_units: usize,
) -> DuplicationStats {
  DuplicationStats {
    total_code_units,
    total_lines,
    exact_duplicate_groups,
    exact_duplicate_units,
    near_duplicate_groups,
    near_duplicate_units,
    ..Default::default()
  }
}

/// Add exact and near source-line counts to fixture statistics.
#[cfg(test)]
const fn with_duplicate_lines(mut stats: DuplicationStats, exact_duplicate_lines: usize, near_duplicate_lines: usize) -> DuplicationStats {
  stats.exact_duplicate_lines = exact_duplicate_lines;
  stats.near_duplicate_lines = near_duplicate_lines;
  stats
}

/// Build a complete analysis with empty optional dimensions and liveness sets.
#[cfg(test)]
fn analysis_result(
  stats: DuplicationStats,
  exact_groups: Vec<DuplicateGroup>,
  near_groups: Vec<DuplicateGroup>,
  warnings: Vec<SuppressionWarning>,
) -> AnalysisResult {
  AnalysisResult {
    suppressed_groups: Vec::new(),
    ignored_groups: Vec::new(),
    ignore_file: None,
    stats,
    exact_groups,
    near_groups,
    sub_exact_groups: Vec::new(),
    sub_near_groups: Vec::new(),
    token_normalized_exact_groups: Vec::new(),
    token_normalized_near_groups: Vec::new(),
    token_raw_exact_groups: Vec::new(),
    line_exact_groups: Vec::new(),
    warnings,
    sources: Vec::new(),
    all_fingerprints: HashSet::new(),
    all_member_fingerprint_sets: Vec::new(),
  }
}

/// The result of a full analysis run.
#[derive(Debug)]
pub struct AnalysisResult<ParseError = Infallible> {
  /// Aggregated duplication statistics.
  pub stats: DuplicationStats,
  /// Visible AST exact-duplicate groups.
  pub exact_groups: Vec<DuplicateGroup>,
  /// Visible AST near-duplicate groups.
  pub near_groups: Vec<DuplicateGroup>,
  /// Visible sub-function exact groups.
  pub sub_exact_groups: Vec<DuplicateGroup>,
  /// Visible sub-function near groups.
  pub sub_near_groups: Vec<DuplicateGroup>,
  /// Visible normalized token-window exact groups.
  pub token_normalized_exact_groups: Vec<DuplicateGroup>,
  /// Visible normalized token-window near groups.
  pub token_normalized_near_groups: Vec<DuplicateGroup>,
  /// Visible raw token-window exact groups.
  pub token_raw_exact_groups: Vec<DuplicateGroup>,
  /// Visible line-window exact groups.
  pub line_exact_groups: Vec<DuplicateGroup>,
  /// Groups hidden from the default report by suppression rules
  /// (post-ignore, all dimensions). Each carries its rule in `suppressed`.
  pub suppressed_groups: Vec<DuplicateGroup>,
  /// Complete groups hidden by registry policy, retained separately from the
  /// visible and rule-suppressed presentation populations.
  pub ignored_groups: Vec<DuplicateGroup>,
  /// Registry model and native read observation used for ignore filtering.
  /// `None` means registry loading did not complete for these findings.
  pub ignore_file: Option<IgnoreFileLoad>,
  /// Complete nonfatal configuration warnings, including each requested rule action.
  pub warnings: Vec<SuppressionWarning>,
  /// Every source read and language or text extraction outcome in operation order.
  pub sources: Vec<SourceAnalysis<ParseError>>,
  /// All group fingerprints (exact + near) before ignore filtering.
  /// Used by the cleanup command to identify stale ignore entries.
  pub all_fingerprints: HashSet<Fingerprint>,
  /// Member content fingerprints of every group before ignore filtering,
  /// one set per group. Used for member-based ignore-entry liveness: an
  /// entry whose recorded members all appear together in one of these sets
  /// still matches the analysis even if its group fingerprint drifted.
  pub all_member_fingerprint_sets: Vec<HashSet<Fingerprint>>,
}

/// Complete analysis findings or the typed failure retaining the reached analysis state.
pub type AnalysisOutcome<ParseError = Infallible> = Result<AnalysisResult<ParseError>, AnalysisError<ParseError>>;

/// A source-file operation retained alongside the findings derived from it.
#[derive(Debug)]
pub enum SourceAnalysis<ParseError> {
  /// A language-specific read and parse attempt.
  Ast(Result<AstSource<ParseError>, SourceReadError>),
  /// A generic token and line extraction attempt.
  Text(Result<TextSource, SourceReadError>),
}

/// A successfully read source with its native language parse outcome.
#[derive(Debug)]
pub struct AstSource<ParseError> {
  /// Complete source file supplied to the language analyzer.
  pub file:   SourceFile,
  /// Top-level parsing failure or the complete top-level and requested sub-unit outcomes.
  pub parsed: Result<AstUnits<ParseError>, ParseError>,
}

/// Units produced before application of test exclusion and grouping policy.
#[derive(Debug)]
pub struct AstUnits<ParseError> {
  /// Every top-level unit, including test code and ungrouped units.
  pub top_level: Vec<CodeUnit>,
  /// Requested sub-unit parse result; absent when sub-unit detection was not requested.
  pub sub_units: Option<Result<Vec<CodeUnit>, ParseError>>,
}

/// Generic extraction before test exclusion or grouping policy.
#[derive(Debug)]
pub struct TextSource {
  /// Complete source file supplied to generic extraction.
  pub file:  SourceFile,
  /// Every extracted normalized-token, raw-token, and line unit.
  pub units: TextUnits,
}

impl<ParseError> AnalysisResult<ParseError> {
  /// Iterate over all filtered duplicate groups.
  pub fn groups(&self) -> impl Iterator<Item = &DuplicateGroup> {
    self
      .exact_groups
      .iter()
      .chain(self.near_groups.iter())
      .chain(self.sub_exact_groups.iter())
      .chain(self.sub_near_groups.iter())
      .chain(self.token_normalized_exact_groups.iter())
      .chain(self.token_normalized_near_groups.iter())
      .chain(self.token_raw_exact_groups.iter())
      .chain(self.line_exact_groups.iter())
  }

  /// Iterate over all filtered groups including rule-suppressed ones.
  pub fn groups_with_suppressed(&self) -> impl Iterator<Item = &DuplicateGroup> {
    self.groups().chain(self.suppressed_groups.iter())
  }
}

/// Run the full analysis pipeline using a language analyzer.
///
/// Reads each file, parses it via the analyzer, optionally filters test code,
/// then delegates to [`analyze_units`] for grouping, similarity, and stats.
///
/// # Errors
///
/// Returns registry-loading failures together with the findings already computed.
pub fn analyze<Analyzer: LanguageAnalyzer>(analyzer: &Analyzer, files: &[PathBuf], config: &Config) -> AnalysisOutcome<Analyzer::Error> {
  analyze_with_generic(analyzer, files, files, config)
}

/// Run the full analysis pipeline with separate AST and generic text inputs.
///
/// # Errors
///
/// Returns registry-loading failures together with the findings already computed.
pub fn analyze_with_generic<Analyzer: LanguageAnalyzer>(
  analyzer: &Analyzer,
  ast_files: &[PathBuf],
  generic_files: &[PathBuf],
  config: &Config,
) -> AnalysisOutcome<Analyzer::Error> {
  let mut units = Vec::new();
  let mut explicit_sub_units = Vec::new();
  let mut sources = Vec::new();
  let mut test_ranges = TestRanges::default();

  for path in ast_files {
    let observed = read_ast_source(analyzer, path, config);
    if let Ok(ref source) = observed
      && let Ok(ref parsed) = source.parsed
    {
      let mut file_units = parsed.top_level.clone();
      retain_non_test_units(analyzer, config.exclude_tests, &mut test_ranges, &mut file_units);
      units.extend(file_units);
      if let Some(Ok(ref sub_units)) = parsed.sub_units {
        let mut selected = sub_units.clone();
        retain_non_test_units(analyzer, config.exclude_tests, &mut test_ranges, &mut selected);
        explicit_sub_units.extend(selected);
      }
    }
    sources.push(SourceAnalysis::Ast(observed));
  }

  let mut token_normalized_units = Vec::new();
  let mut token_raw_units = Vec::new();
  let mut line_units = Vec::new();

  for path in generic_files {
    let observed = SourceFile::read(path).map(|file| {
      let extracted = text_units::extract(path, &file.contents, config);
      TextSource {
        file,
        units: extracted,
      }
    });
    if let Ok(ref source) = observed {
      let mut generic = source.units.clone();
      if config.exclude_tests {
        test_ranges.retain_non_test(&mut generic.normalized_tokens);
        test_ranges.retain_non_test(&mut generic.raw_tokens);
        test_ranges.retain_non_test(&mut generic.lines);
      }
      token_normalized_units.extend(generic.normalized_tokens);
      token_raw_units.extend(generic.raw_tokens);
      line_units.extend(generic.lines);
    }
    sources.push(SourceAnalysis::Text(observed));
  }

  let mut outcome = analyze_units_with_generic(
    &units,
    &explicit_sub_units,
    &token_normalized_units,
    &token_raw_units,
    &line_units,
    config.load_warnings.clone(),
    config,
  );
  match outcome {
    Ok(ref mut analysis) => analysis.sources = sources,
    Err(ref mut failure) => failure.analysis.sources = sources,
  }
  outcome
}

/// Retain the native read and each requested parse outcome before report selection.
#[allow(
  clippy::single_call_fn,
  reason = "A file's top-level parse determines whether sub-unit parsing may run, while both native outcomes remain attached to the \
            source."
)]
fn read_ast_source<Analyzer: LanguageAnalyzer>(
  analyzer: &Analyzer,
  path: &Path,
  config: &Config,
) -> Result<AstSource<Analyzer::Error>, SourceReadError> {
  let file = SourceFile::read(path)?;
  let analysis_config = config.analysis_config();
  let parsed = analyzer.parse_file(path, &file.contents, analysis_config).map(|top_level| {
    let sub_units = (config.sub_function && config.dimension_enabled(DetectionDimension::SubAst))
      .then(|| analyzer.parse_sub_units(path, &file.contents, analysis_config, config.min_sub_nodes));
    AstUnits {
      top_level,
      sub_units,
    }
  });
  Ok(AstSource {
    file,
    parsed,
  })
}

/// Record test units in `test_ranges` and drop them when exclusion is on.
fn retain_non_test_units(analyzer: &impl LanguageAnalyzer, exclude_tests: bool, test_ranges: &mut TestRanges, units: &mut Vec<CodeUnit>) {
  if exclude_tests {
    test_ranges.add_units(analyzer, units);
    units.retain(|unit| !analyzer.is_test_code(unit));
  }
}

/// Append a unit's line range to its file's range list.
fn push_unit_range(map: &mut HashMap<PathBuf, Vec<LineRange>>, unit: &CodeUnit) {
  map.entry(unit.file.clone()).or_default().push(LineRange {
    start: unit.line_start,
    end:   unit.line_end,
  });
}

/// Source regions classified as tests by the selected language analyzer.
#[derive(Default)]
struct TestRanges {
  /// Test regions grouped by their original source-file identity.
  by_file: HashMap<PathBuf, Vec<LineRange>>,
}

/// Inclusive source-line interval used by test exclusion and duplicate coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRange {
  /// First line belonging to the interval.
  pub start: usize,
  /// Last line belonging to the interval.
  pub end:   usize,
}

impl LineRange {
  /// Number of source lines represented by the inclusive interval.
  fn len(self) -> Result<usize, calculation::LineRangeFailure> {
    calculation::inclusive_line_count(self.start, self.end)
  }

  /// Shared source interval, or no interval when the inputs are disjoint.
  const fn intersection(self, other: Self) -> Option<Self> {
    let start = if self.start > other.start {
      self.start
    } else {
      other.start
    };
    let end = if self.end < other.end { self.end } else { other.end };
    if start <= end {
      Some(Self {
        start,
        end,
      })
    } else {
      None
    }
  }
}

impl TestRanges {
  /// Record the source intervals of units that the analyzer classifies as tests.
  fn add_units(&mut self, analyzer: &impl LanguageAnalyzer, units: &[CodeUnit]) {
    for unit in units {
      if analyzer.is_test_code(unit) {
        push_unit_range(&mut self.by_file, unit);
      }
    }
  }

  /// Retain generic windows that are not wholly inside known test intervals.
  fn retain_non_test(&self, units: &mut Vec<CodeUnit>) {
    units.retain(|unit| !self.contains(unit));
  }

  /// Whether a unit is wholly contained in a test interval from the same file.
  fn contains(&self, unit: &CodeUnit) -> bool {
    self.by_file.get(&unit.file).is_some_and(|ranges| {
      ranges
        .iter()
        .any(|range| unit.line_start >= range.start && unit.line_end <= range.end)
    })
  }
}

/// Run the analysis pipeline on pre-parsed code units.
///
/// The caller is responsible for scanning files and parsing them into `CodeUnit`s.
/// This function handles suppression tagging, grouping, similarity detection,
/// ignore filtering, and stats.
///
/// # Errors
///
/// Returns registry-loading failures together with the findings already computed.
pub fn analyze_units(units: &[CodeUnit], warnings: Vec<SuppressionWarning>, config: &Config) -> Result<AnalysisResult, AnalysisError> {
  analyze_units_with_generic(units, &[], &[], &[], &[], warnings, config)
}

/// Run the analysis pipeline on pre-parsed AST and generic units.
///
/// # Errors
///
/// Returns the native registry-loading failure and the complete pre-ignore findings.
pub fn analyze_units_with_generic<ParseError: Debug>(
  units: &[CodeUnit],
  explicit_sub_units: &[CodeUnit],
  token_normalized_units: &[CodeUnit],
  token_raw_units: &[CodeUnit],
  line_units: &[CodeUnit],
  warnings: Vec<SuppressionWarning>,
  config: &Config,
) -> Result<AnalysisResult<ParseError>, AnalysisError<ParseError>> {
  analysis::AnalysisProgress::new(
    analysis::AnalysisUnits {
      ast:               units.to_vec(),
      sub_ast:           explicit_sub_units.to_vec(),
      normalized_tokens: token_normalized_units.to_vec(),
      raw_tokens:        token_raw_units.to_vec(),
      lines:             line_units.to_vec(),
    },
    warnings,
  )
  .run(config)
}

/// Exact and near groups for a dimension.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchedGroups {
  /// Exact duplicate groups.
  pub exact: Vec<DuplicateGroup>,
  /// Near duplicate groups.
  pub near:  Vec<DuplicateGroup>,
}

/// Apply aggregated `also seen as` notes to the covering AST/sub groups.
///
/// `notes` reference groups by [`DuplicateCoverage`] construction order:
/// ast exact, ast near, then (when precise spans exist) sub exact, sub near.
#[allow(
  clippy::single_call_fn,
  reason = "Coverage annotation must follow the same precise-group order used by the coverage index"
)]
fn apply_coverage_notes(ast_groups: &mut MatchedGroups, sub_groups: Option<&mut MatchedGroups>, mut notes: Vec<CoverageNoteSource>) {
  if notes.is_empty() {
    return;
  }
  let mut coverers: Vec<&mut DuplicateGroup> = ast_groups.exact.iter_mut().chain(ast_groups.near.iter_mut()).collect();
  if let Some(precise_sub_groups) = sub_groups {
    coverers.extend(precise_sub_groups.exact.iter_mut().chain(precise_sub_groups.near.iter_mut()));
  }
  notes.sort_by_key(|note| (note.coverer, note.dimension, note.match_kind));
  for matching in notes.chunk_by(PartialEq::eq) {
    if let Some(first) = matching.first()
      && let Some(group) = coverers.get_mut(first.coverer)
    {
      group.also_seen.push(grouper::CoverageNote {
        dimension:   first.dimension,
        match_kind:  first.match_kind,
        group_count: matching.len(),
      });
    }
  }
}

/// Generic token and line duplicate groups.
#[derive(Debug, Default)]
pub struct GenericGroups {
  /// Normalized token exact and near groups.
  pub token_normalized: MatchedGroups,
  /// Raw-token exact groups.
  pub token_raw_exact:  Vec<DuplicateGroup>,
  /// Normalized-line exact groups.
  pub line_exact:       Vec<DuplicateGroup>,
  /// Window groups hidden by suppression rules (all generic dimensions).
  pub suppressed:       Vec<DuplicateGroup>,
}

/// Split off groups whose members are all rule-suppressed.
///
/// A group stays visible while any member is unsuppressed (mixed groups carry
/// their tagged members); a fully suppressed group takes its first member's
/// rule as the group tag. Member order is the deterministic unit scan order,
/// so the tag choice is stable.
fn partition_suppressed(groups: Vec<DuplicateGroup>, suppressed: &mut Vec<DuplicateGroup>) -> Vec<DuplicateGroup> {
  let (hidden, visible): (Vec<_>, Vec<_>) = groups
    .into_iter()
    .partition(|group| group.members.iter().all(|member| member.suppressed.is_some()));
  suppressed.extend(hidden.into_iter().map(|mut group| {
    group.suppressed = group.members.first().and_then(|member| member.suppressed);
    group
  }));
  visible
}

/// Tag top-level units with the trivial-shape suppression rules.
///
/// Tagging is centralized here so every language analyzer's units get the
/// same treatment; analyzers emit unconditionally.
#[allow(
  clippy::single_call_fn,
  reason = "Central top-level tagging enforces the same suppression policy for every language analyzer"
)]
fn tag_top_level_units(units: &mut [CodeUnit], policy: &suppression::SuppressionPolicy) {
  for unit in units {
    if unit.suppressed.is_some() {
      continue;
    }
    unit.suppressed = match unit.kind {
      CodeUnitKind::Closure => {
        let body = unit.body.children.first().unwrap_or(&unit.body);
        extractor::classify_closure_body(body, policy)
      }
      CodeUnitKind::Function | CodeUnitKind::Method | CodeUnitKind::TraitImplBlock => {
        extractor::classify_top_level_body(&unit.body, policy)
      }
      CodeUnitKind::Class
      | CodeUnitKind::ImplBlock
      | CodeUnitKind::IfBranch
      | CodeUnitKind::IfChain
      | CodeUnitKind::MatchArm
      | CodeUnitKind::LoopBody
      | CodeUnitKind::Block
      | CodeUnitKind::TokenWindow
      | CodeUnitKind::LineWindow => None,
    };
  }
}

/// Add one unit contribution while retaining the original map on overflow.
fn bump(counts: &mut BTreeMap<RuleId, usize>, rule: RuleId, incoming: usize) -> Result<(), SuppressionCountFailure> {
  let completed = counts.get(&rule).copied().unwrap_or(0);
  let total = completed.checked_add(incoming).ok_or_else(|| SuppressionCountFailure {
    unit_counts: counts.clone(),
    group_counts: BTreeMap::new(),
    population: SuppressionPopulation::Units,
    rule,
    completed,
    incoming,
  })?;
  *counts.entry(rule).or_default() = total;
  Ok(())
}

/// Fill the suppression accounting fields of the stats.
///
/// Unit-level rules count tagged units across the top-level and window
/// populations plus the sub-unit tallies collected at classification time;
/// chain-covered members are counted from their suppressed groups (they are
/// tagged at the group stage). Group-level rules count suppressed groups.
#[allow(
  clippy::single_call_fn,
  reason = "Suppression accounting must distinguish unit-level tags from group-level coverage rules"
)]
fn apply_suppression_stats(
  stats: &mut DuplicationStats,
  initial_unit_counts: &BTreeMap<RuleId, usize>,
  unit_populations: &[&[CodeUnit]],
  suppressed_groups: &[DuplicateGroup],
) -> Result<(), AnalysisFailure> {
  let mut rule_unit_counts = initial_unit_counts.clone();
  for units in unit_populations {
    for rule in units.iter().filter_map(|unit| unit.suppressed) {
      bump(&mut rule_unit_counts, rule, 1)?;
    }
  }
  let mut rule_group_counts: BTreeMap<RuleId, usize> = BTreeMap::new();
  for group in suppressed_groups {
    match group.suppressed {
      Some(rule @ (RuleId::GroupCoveredByAst | RuleId::GroupOverlapContained)) => {
        bump(&mut rule_group_counts, rule, 1).map_err(|mut failure| {
          failure.group_counts = failure.unit_counts;
          failure.unit_counts = rule_unit_counts.clone();
          failure.population = SuppressionPopulation::Groups;
          failure
        })?;
      }
      Some(rule @ RuleId::SubCoveredByChain) => {
        bump(&mut rule_unit_counts, rule, group.members.len()).map_err(|mut failure| {
          failure.group_counts = rule_group_counts.clone();
          failure
        })?;
      }
      _ => {}
    }
  }
  stats.suppressed_unit_count = rule_unit_counts.iter().try_fold(0_usize, |completed, (&rule, &incoming)| {
    completed.checked_add(incoming).ok_or_else(|| SuppressionCountFailure {
      unit_counts: rule_unit_counts.clone(),
      group_counts: rule_group_counts.clone(),
      population: SuppressionPopulation::TotalUnits,
      rule,
      completed,
      incoming,
    })
  })?;
  stats.suppressed_group_count = suppressed_groups.len();
  stats.suppressed_by_rule = rule_unit_counts
    .into_iter()
    .chain(rule_group_counts)
    .map(|(rule, count)| (rule.as_str().to_owned(), count))
    .collect();
  Ok(())
}

/// Partition both match kinds of a dimension into visible and suppressed.
fn partition_matched(groups: &mut MatchedGroups, suppressed: &mut Vec<DuplicateGroup>) {
  groups.exact = partition_suppressed(mem::take(&mut groups.exact), suppressed);
  groups.near = partition_suppressed(mem::take(&mut groups.near), suppressed);
}

/// Compute top-level AST duplicate groups when enabled.
#[allow(
  clippy::single_call_fn,
  reason = "The AST stage owns whether parsed units participate in duplicate grouping"
)]
fn compute_ast_groups(units: &[CodeUnit], config: &Config, groups: &mut MatchedGroups) -> Result<(), AnalysisFailure> {
  if config.dimension_enabled(DetectionDimension::Ast) {
    compute_matched_groups(units, config.similarity_threshold, DetectionDimension::Ast, groups)?;
  }
  Ok(())
}

/// Compute nested AST duplicate groups when enabled.
#[allow(
  clippy::single_call_fn,
  reason = "The sub-AST stage owns fallback extraction, region deduplication, and chain coverage ordering"
)]
fn compute_sub_ast_groups(
  units: &[CodeUnit],
  sub_units: &mut Vec<CodeUnit>,
  config: &Config,
  groups: &mut MatchedGroups,
  suppressed: &mut Vec<DuplicateGroup>,
  rule_unit_counts: &mut BTreeMap<RuleId, usize>,
) -> Result<(), AnalysisFailure> {
  if !(config.sub_function && config.dimension_enabled(DetectionDimension::SubAst)) {
    return Ok(());
  }

  if sub_units.is_empty() {
    *sub_units = fallback_sub_units(units, config.min_sub_nodes);
  }
  for unit in sub_units.iter_mut() {
    if unit.suppressed.is_none() {
      unit.suppressed = extractor::classify_sub_unit(&unit.body, &config.suppression);
    }
    if let Some(rule) = unit.suppressed {
      bump(rule_unit_counts, rule, 1)?;
    }
  }
  let distinct_sub_units = dedupe_same_region_sub_units(sub_units.clone());
  compute_matched_groups(&distinct_sub_units, config.similarity_threshold, DetectionDimension::SubAst, groups)?;
  apply_chain_coverage(groups, &config.suppression);
  partition_matched(groups, suppressed);
  Ok(())
}

/// Tag branch groups whose members all belong to duplicated if-chains.
///
/// Coverage requires the owning chain to have actually grouped: branches of
/// chains with no duplicate partner are released to full visibility, so
/// cross-file branch-shape repetition (option-override clusters) stays
/// detectable even when the chains differ as wholes.
#[allow(
  clippy::single_call_fn,
  reason = "Branch suppression requires every owning chain to occur in an exact duplicate group"
)]
fn apply_chain_coverage(groups: &mut MatchedGroups, policy: &suppression::SuppressionPolicy) {
  if !policy.is_enabled(RuleId::SubCoveredByChain) {
    return;
  }
  let duplicated_chains: HashSet<Fingerprint> = grouper::member_fingerprints_iter(
    groups
      .exact
      .iter()
      .filter(|group| group.members.first().is_some_and(|member| member.kind == CodeUnitKind::IfChain)),
  )
  .collect();
  for group in groups.exact.iter_mut().chain(groups.near.iter_mut()) {
    let chain_covered = !group.members.is_empty()
      && group
        .members
        .iter()
        .all(|member| member.parent_chain.is_some_and(|chain| duplicated_chains.contains(&chain)));
    if chain_covered {
      for member in &mut group.members {
        member.suppressed = policy.allow(RuleId::SubCoveredByChain);
      }
    }
  }
}

/// Remove redundant same-region representations of identical content.
///
/// A match arm or if branch whose body is exactly an if-chain produces two
/// sub-units with the same fingerprint over essentially the same lines; only
/// the widest one may represent the region, otherwise the pair forms a
/// self-referential "duplicate group" at a single source location.
#[allow(
  clippy::single_call_fn,
  reason = "One source region must not form a duplicate group with another representation of itself"
)]
fn dedupe_same_region_sub_units(mut units: Vec<CodeUnit>) -> Vec<CodeUnit> {
  units.sort_by(|first, second| {
    first
      .file
      .cmp(&second.file)
      .then_with(|| first.fingerprint.cmp(&second.fingerprint))
      .then_with(|| {
        second
          .line_end
          .saturating_sub(second.line_start)
          .cmp(&first.line_end.saturating_sub(first.line_start))
      })
      .then_with(|| first.line_start.cmp(&second.line_start))
      .then_with(|| first.name.cmp(&second.name))
  });
  let mut kept: Vec<CodeUnit> = Vec::new();
  for unit in units {
    let redundant = kept
      .iter()
      .any(|existing| existing.file == unit.file && existing.fingerprint == unit.fingerprint && unit_ranges_overlap(existing, &unit));
    if !redundant {
      kept.push(unit);
    }
  }
  kept
}

/// Return true when two units' line ranges intersect.
#[allow(
  clippy::single_call_fn,
  reason = "Source overlap decides whether identical sub-units are redundant representations of the same region"
)]
fn unit_ranges_overlap(first: &CodeUnit, second: &CodeUnit) -> bool {
  first.line_start.max(second.line_start) <= first.line_end.min(second.line_end)
}

/// Compute token and line duplicate groups when their dimensions are enabled.
///
/// Cross-dimension coverage events are appended to `notes` so the covering
/// AST/sub groups can carry `also seen as` annotations.
#[allow(
  clippy::single_call_fn,
  reason = "The generic stage preserves the ordered partition, merge, containment, and precise-coverage steps"
)]
fn compute_generic_groups(
  units: &analysis::AnalysisUnits,
  config: &Config,
  duplicate_coverage: &DuplicateCoverage,
  notes: &mut Vec<CoverageNoteSource>,
  groups: &mut GenericGroups,
  phase: &mut analysis::AnalysisPhase,
) -> Result<(), AnalysisFailure> {
  let policy = &config.suppression;
  *phase = analysis::AnalysisPhase::NormalizedTokens;
  if config.dimension_enabled(DetectionDimension::TokenNormalized) {
    compute_matched_groups(
      &units.normalized_tokens,
      config.token_similarity_threshold,
      DetectionDimension::TokenNormalized,
      &mut groups.token_normalized,
    )?;
  }
  partition_matched(&mut groups.token_normalized, &mut groups.suppressed);
  suppress_overlapping_groups(&mut groups.token_normalized.exact, policy, &mut groups.suppressed)?;
  suppress_overlapping_groups(&mut groups.token_normalized.near, policy, &mut groups.suppressed)?;
  duplicate_coverage.split_substantially_covered(&mut groups.token_normalized.exact, policy, &mut groups.suppressed, notes)?;
  duplicate_coverage.split_substantially_covered(&mut groups.token_normalized.near, policy, &mut groups.suppressed, notes)?;

  *phase = analysis::AnalysisPhase::RawTokens;
  if config.dimension_enabled(DetectionDimension::TokenRaw) {
    groups.token_raw_exact = grouper::group_exact_duplicates_for(&units.raw_tokens, DetectionDimension::TokenRaw);
  }
  groups.token_raw_exact = partition_suppressed(mem::take(&mut groups.token_raw_exact), &mut groups.suppressed);
  suppress_overlapping_groups(&mut groups.token_raw_exact, policy, &mut groups.suppressed)?;
  duplicate_coverage.split_substantially_covered(&mut groups.token_raw_exact, policy, &mut groups.suppressed, notes)?;

  *phase = analysis::AnalysisPhase::Lines;
  if config.dimension_enabled(DetectionDimension::Line) {
    groups.line_exact = grouper::group_exact_duplicates_for(&units.lines, DetectionDimension::Line);
  }
  // Partition before merging so the visible merge sees exactly the groups
  // the pre-tagging pipeline saw; the suppressed population is merged too so
  // `--show-suppressed` reads as concept regions instead of window chains.
  let mut line_suppressed = Vec::new();
  groups.line_exact = partition_suppressed(mem::take(&mut groups.line_exact), &mut line_suppressed);
  let merged = merge_shifted_window_groups(&mut groups.line_exact).and_then(|()| merge_shifted_window_groups(&mut line_suppressed));
  groups.suppressed.append(&mut line_suppressed);
  merged?;
  suppress_overlapping_groups(&mut groups.line_exact, policy, &mut groups.suppressed)?;
  duplicate_coverage.split_substantially_covered(&mut groups.line_exact, policy, &mut groups.suppressed, notes)?;
  Ok(())
}

/// Merge exact window groups that are shifted continuations of one another.
///
/// Sliding extraction reports a duplicated region longer than one window as a
/// chain of overlapping groups, each shifted by a few lines. When two groups
/// pair member-for-member in the same files with one uniform shift and
/// compatible window content, they describe the same duplicated region, so
/// they are merged into a single concept-level group whose members span the
/// union range. Merged units are rebuilt from the union content, keeping the
/// group fingerprint identical to what a directly extracted window of that
/// span would produce.
fn merge_shifted_window_groups(groups: &mut Vec<DuplicateGroup>) -> Result<(), UnitSpanFailure> {
  let mut merged: Vec<DuplicateGroup> = Vec::new();
  for group in groups.iter_mut() {
    group
      .members
      .sort_by(|first, second| first.file.cmp(&second.file).then(first.line_start.cmp(&second.line_start)));
  }
  groups.sort_by(|first, second| {
    member_signature(first)
      .cmp(&member_signature(second))
      .then_with(|| group_start_key(first).cmp(&group_start_key(second)))
  });

  let mut pending = mem::take(groups).into_iter();
  while let Some(group) = pending.next() {
    if let Some(last) = merged.last_mut() {
      match merge_window_group_pair(last, &group) {
        Ok(Some(combined)) => {
          *last = combined;
          continue;
        }
        Ok(None) => {}
        Err(source) => {
          merged.push(group);
          merged.extend(pending);
          *groups = merged;
          return Err(source);
        }
      }
    }
    merged.push(group);
  }

  merged.sort_by(grouper::compare_group_size_desc_then_fingerprint);
  *groups = merged;
  Ok(())
}

/// Files of each member, used to bucket groups that could pair up.
fn member_signature(group: &DuplicateGroup) -> Vec<&PathBuf> {
  group.members.iter().map(|member| &member.file).collect()
}

/// Earliest member position, used to order shifted groups along a region.
fn group_start_key(group: &DuplicateGroup) -> Option<(&PathBuf, usize)> {
  group.members.first().map(|member| (&member.file, member.line_start))
}

/// Try to merge `next` into `current` as a shifted continuation.
#[allow(
  clippy::single_call_fn,
  reason = "A merged concept requires compatible membership, one uniform source shift, and equal overlapping content"
)]
fn merge_window_group_pair(current: &DuplicateGroup, next: &DuplicateGroup) -> Result<Option<DuplicateGroup>, UnitSpanFailure> {
  if current.dimension != next.dimension
    || current.match_kind != MatchKind::Exact
    || next.match_kind != MatchKind::Exact
    || current.members.len() != next.members.len()
  {
    return Ok(None);
  }

  let (Some(first_current), Some(first_next)) = (current.members.first(), next.members.first()) else {
    return Ok(None);
  };
  let Some(current_values) = contiguous_window_values(first_current)? else {
    return Ok(None);
  };
  let Some(next_values) = contiguous_window_values(first_next)? else {
    return Ok(None);
  };
  if first_next.line_start <= first_current.line_start {
    return Ok(None);
  }
  let Some(shift) = first_next.line_start.checked_sub(first_current.line_start) else {
    return Ok(None);
  };
  if shift > current_values.len() || first_next.line_end <= first_current.line_end {
    return Ok(None);
  }

  for (member, next_member) in current.members.iter().zip(&next.members) {
    if member.file != next_member.file
      || next_member.line_start.checked_sub(member.line_start) != Some(shift)
      || contiguous_window_values(member)?.is_none()
      || contiguous_window_values(next_member)?.is_none()
    {
      return Ok(None);
    }
  }

  // The retained suffix of the current window must equal the overlapping
  // prefix of the next window for the union to be one duplicated region.
  let Some((_, current_overlap)) = current_values.split_at_checked(shift) else {
    return Ok(None);
  };
  let Some((next_overlap, next_suffix)) = next_values.split_at_checked(current_overlap.len()) else {
    return Ok(None);
  };
  if current_overlap != next_overlap {
    return Ok(None);
  }

  let union_values: Vec<String> = current_values
    .iter()
    .chain(next_suffix)
    .map(|text| (*text).to_owned())
    .collect();

  let members: Vec<CodeUnit> = current
    .members
    .iter()
    .zip(&next.members)
    .map(|(member, next_member)| {
      let mut combined = text_units::window_unit(
        &member.file, &member.name, member.kind, member.line_start, next_member.line_end, &union_values,
      );
      combined.suppressed = current.suppressed;
      combined
    })
    .collect();

  let Some(content_fingerprint) = members.first().map(|member| member.fingerprint) else {
    return Ok(None);
  };
  Ok(Some(DuplicateGroup {
    // Merging happens within one population, so a suppressed chain keeps
    // its group tag (and member tags) through the rebuilt union members.
    suppressed: current.suppressed,
    also_seen: Vec::new(),
    dimension: current.dimension,
    match_kind: MatchKind::Exact,
    fingerprint: grouper::exact_group_fingerprint(current.dimension, content_fingerprint),
    members,
    similarity: 1.0,
  }))
}

/// Window values when the unit's content lines map one-to-one to source lines.
fn contiguous_window_values(unit: &CodeUnit) -> Result<Option<Vec<&str>>, UnitSpanFailure> {
  let Some(values) = text_units::window_values(unit) else {
    return Ok(None);
  };
  let lines = grouper::unit_line_count(unit).map_err(|source| UnitSpanFailure {
    unit: Box::new(unit.clone()),
    source,
  })?;
  Ok((values.len() == lines).then_some(values))
}

/// Source ranges already explained by AST/sub-AST duplicate groups.
///
/// Coverage is tracked per duplicate group: a generic token/line group is
/// redundant only when one single stronger group covers all of its members,
/// meaning both describe the same duplicate concept. Members that merely fall
/// inside unrelated duplicate ranges scattered across different groups do not
/// suppress a generic family (deliberate fixture regions spanning test
/// files and fixture crates must stay visible).
#[derive(Default)]
struct DuplicateCoverage {
  /// Precise groups in the same stable order used by coverage annotations.
  groups: Vec<GroupCoverage>,
}

/// The source ranges of one AST/sub-AST duplicate group.
#[derive(Default)]
struct GroupCoverage {
  /// Source intervals occupied by members of this one duplicate group.
  by_file: HashMap<PathBuf, Vec<LineRange>>,
}

impl DuplicateCoverage {
  /// Index precise AST groups and the optional precise sub-AST population.
  #[allow(
    clippy::single_call_fn,
    reason = "The precise coverage index establishes the stable group order used by coverage annotations"
  )]
  fn from_matched_groups(ast_groups: &MatchedGroups, precise_sub_groups: Option<&MatchedGroups>) -> Self {
    let mut coverage = Self::default();
    for group in ast_groups.exact.iter().chain(ast_groups.near.iter()) {
      coverage.add_group(group);
    }
    if let Some(sub_groups) = precise_sub_groups {
      for group in sub_groups.exact.iter().chain(sub_groups.near.iter()) {
        coverage.add_group(group);
      }
    }
    coverage
  }

  /// Add one group without combining its members with unrelated groups.
  fn add_group(&mut self, group: &DuplicateGroup) {
    let mut group_coverage = GroupCoverage::default();
    for member in &group.members {
      push_unit_range(&mut group_coverage.by_file, member);
    }
    self.groups.push(group_coverage);
  }

  /// Split groups into uncovered (kept) and covered; covered groups are
  /// tagged `group.covered-by-ast` and their covering group index is
  /// recorded so the survivor can carry an `also seen as` note.
  fn split_substantially_covered(
    &self,
    groups: &mut Vec<DuplicateGroup>,
    policy: &suppression::SuppressionPolicy,
    suppressed: &mut Vec<DuplicateGroup>,
    notes: &mut Vec<CoverageNoteSource>,
  ) -> Result<(), CoverageFailure> {
    if self.groups.is_empty() || !policy.is_enabled(RuleId::GroupCoveredByAst) {
      return Ok(());
    }
    suppress_selected_groups(groups, suppressed, |group, _kept| {
      Ok(self.covering_group_index(group)?.and_then(|coverer| {
        notes.push(CoverageNoteSource {
          coverer,
          dimension: group.dimension,
          match_kind: group.match_kind,
        });
        policy.allow(RuleId::GroupCoveredByAst)
      }))
    })
  }

  /// Find one precise group that covers every member of the candidate group.
  fn covering_group_index(&self, group: &DuplicateGroup) -> Result<Option<usize>, CoverageFailure> {
    self.groups.iter().enumerate().try_fold(None, |found, (index, coverage)| {
      if found.is_some() {
        return Ok(found);
      }
      let covered = group
        .members
        .iter()
        .try_fold(true, |all, member| if all { coverage.covers_unit(member) } else { Ok(false) })?;
      Ok(covered.then_some(index))
    })
  }
}

/// One cross-dimension coverage event: the AST/sub group at `coverer` (in
/// [`DuplicateCoverage`] construction order) covered a generic group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageNoteSource {
  /// Position of the precise group in the coverage index.
  pub coverer:    usize,
  /// Detection dimension of the covered group.
  pub dimension:  DetectionDimension,
  /// Exact or near classification of the covered group.
  pub match_kind: MatchKind,
}

impl GroupCoverage {
  /// Whether the precise group covers the required fraction of a valid source span.
  fn covers_unit(&self, unit: &CodeUnit) -> Result<bool, CoverageFailure> {
    self
      .covered_ratio(unit)
      .map(|ratio| ratio >= PRECISE_COVERAGE_SUPPRESSION_RATIO)
  }

  /// Fraction of the candidate span explained by this group's union of intervals.
  fn covered_ratio(&self, unit: &CodeUnit) -> Result<f64, CoverageFailure> {
    let Some(ranges) = self.by_file.get(&unit.file) else {
      return Ok(0.0);
    };
    let unit_range = LineRange {
      start: unit.line_start,
      end:   unit.line_end,
    };
    let mut covered = 0_usize;
    union_coverage_ratio(unit_range, ranges, &mut covered).map_err(|source| CoverageFailure {
      candidate: Box::new(unit.clone()),
      ranges: ranges.clone(),
      completed: covered,
      source,
    })
  }
}

/// Measure a union of intersections, retaining the completed integer total on failure.
#[allow(
  clippy::single_call_fn,
  reason = "Interval union measurement owns overlap coalescing separately from attaching the candidate's complete source evidence"
)]
fn union_coverage_ratio(candidate: LineRange, ranges: &[LineRange], covered: &mut usize) -> Result<f64, CoverageFailureCause> {
  let span = candidate.len()?;
  let mut intersections: Vec<LineRange> = ranges.iter().filter_map(|range| range.intersection(candidate)).collect();
  intersections.sort_by_key(|range| (range.start, range.end));
  let mut ordered_intersections = intersections.into_iter();
  let Some(mut current) = ordered_intersections.next() else {
    return Ok(0.0);
  };
  for range in ordered_intersections {
    if range.start <= current.end.saturating_add(1) {
      current.end = current.end.max(range.end);
    } else {
      add_covered_interval(covered, current)?;
      current = range;
    }
  }
  add_covered_interval(covered, current)?;
  calculation::ratio(*covered, span).map_err(CoverageFailureCause::from)
}

/// Accumulate one disjoint intersection without replacing an overflowing total.
fn add_covered_interval(completed: &mut usize, range: LineRange) -> Result<(), CoverageFailureCause> {
  let incoming = range.len()?;
  *completed = completed.checked_add(incoming).ok_or(CoverageFailureCause::TotalOverflow {
    incoming,
  })?;
  Ok(())
}

/// Move selected groups into suppression, restoring all remaining work on failure.
fn suppress_selected_groups(
  groups: &mut Vec<DuplicateGroup>,
  suppressed: &mut Vec<DuplicateGroup>,
  mut select: impl FnMut(&DuplicateGroup, &[DuplicateGroup]) -> Result<Option<RuleId>, CoverageFailure>,
) -> Result<(), CoverageFailure> {
  let mut kept = Vec::new();
  let mut pending = mem::take(groups).into_iter();
  while let Some(mut group) = pending.next() {
    match select(&group, &kept) {
      Ok(Some(rule)) => {
        group.suppressed = Some(rule);
        suppressed.push(group);
      }
      Ok(None) => kept.push(group),
      Err(source) => {
        kept.push(group);
        kept.extend(pending);
        *groups = kept;
        return Err(source);
      }
    }
  }
  *groups = kept;
  Ok(())
}

/// Tag generic token/line groups contained within already-kept neighbors.
///
/// Candidates are ranked concept-first: a group whose members span the
/// longest coherent region wins over fragment groups that overlap it, so a
/// compact intentional shape is never replaced by a shifted or stitched
/// fragment that happens to repeat in more places. Contained groups move to
/// the suppressed population tagged `group.overlap-contained`.
fn suppress_overlapping_groups(
  groups: &mut Vec<DuplicateGroup>,
  policy: &suppression::SuppressionPolicy,
  suppressed: &mut Vec<DuplicateGroup>,
) -> Result<(), CoverageFailure> {
  if !policy.is_enabled(RuleId::GroupOverlapContained) {
    return Ok(());
  }
  groups.sort_by(|first, second| {
    group_widest_interval(second)
      .cmp(&group_widest_interval(first))
      .then_with(|| second.members.len().cmp(&first.members.len()))
      .then(grouper::compare_similarity_desc(first.similarity, second.similarity))
      .then_with(|| group_start_key(first).cmp(&group_start_key(second)))
      .then_with(|| first.fingerprint.cmp(&second.fingerprint))
  });

  suppress_selected_groups(groups, suppressed, |group, kept| {
    is_covered_by_kept(group, kept, SAME_DIMENSION_OVERLAP_SUPPRESSION_RATIO)
      .map(|covered| covered.then_some(RuleId::GroupOverlapContained))
  })
}

/// Widest endpoint difference; omitting the common inclusive increment preserves order.
fn group_widest_interval(group: &DuplicateGroup) -> Option<usize> {
  group
    .members
    .iter()
    .map(|unit| unit.line_end.saturating_sub(unit.line_start))
    .max()
}

/// Whether one retained group explains the candidate's complete membership.
#[allow(
  clippy::single_call_fn,
  reason = "Same-dimension containment requires one retained group to cover every candidate member"
)]
fn is_covered_by_kept(group: &DuplicateGroup, kept: &[DuplicateGroup], min_overlap_ratio: f64) -> Result<bool, CoverageFailure> {
  for kept_group in kept.iter().filter(|retained| retained.dimension == group.dimension) {
    let all_covered = group.members.iter().try_fold(true, |all, member| {
      if all {
        member_has_coverer(member, &kept_group.members, min_overlap_ratio)
      } else {
        Ok(false)
      }
    })?;
    if all_covered {
      return Ok(true);
    }
  }
  Ok(false)
}

/// Whether one same-file representative explains enough of the candidate span.
#[allow(
  clippy::single_call_fn,
  reason = "A candidate member requires one qualifying representative; combining separate representatives would change containment \
            semantics"
)]
fn member_has_coverer(candidate: &CodeUnit, representatives: &[CodeUnit], min_overlap_ratio: f64) -> Result<bool, CoverageFailure> {
  for representative in representatives.iter().filter(|member| member.file == candidate.file) {
    if line_overlap_ratio(candidate, representative)? >= min_overlap_ratio {
      return Ok(true);
    }
  }
  Ok(false)
}

/// Fraction of a candidate's lines occupied by a representative source interval.
#[allow(
  clippy::single_call_fn,
  reason = "Containment measures overlap against the candidate span rather than the representative span"
)]
fn line_overlap_ratio(candidate: &CodeUnit, representative: &CodeUnit) -> Result<f64, CoverageFailure> {
  let mut coverage = GroupCoverage::default();
  push_unit_range(&mut coverage.by_file, representative);
  coverage.covered_ratio(candidate)
}

/// Compute exact and near groups for one unit set.
fn compute_matched_groups(
  units: &[CodeUnit],
  similarity_threshold: f64,
  dimension: DetectionDimension,
  groups: &mut MatchedGroups,
) -> Result<(), AnalysisFailure> {
  groups.exact = grouper::group_exact_duplicates_for(units, dimension);
  let exact_fingerprints = grouper::member_fingerprints(&groups.exact);
  groups.near = grouper::find_near_duplicates_for(units, similarity_threshold, &exact_fingerprints, dimension)?;
  Ok(())
}

/// Extract fallback sub-units from top-level normalized AST bodies.
#[allow(
  clippy::single_call_fn,
  reason = "Fallback extraction deliberately retains parent spans and cannot establish precise cross-dimension coverage"
)]
fn fallback_sub_units(units: &[CodeUnit], min_sub_nodes: usize) -> Vec<CodeUnit> {
  units
    .iter()
    .flat_map(|unit| {
      extractor::extract_sub_units(&unit.body, min_sub_nodes)
        .into_iter()
        .map(|sub_unit| {
          let fingerprint = Fingerprint::from_node(&sub_unit.node);
          CodeUnit {
            suppressed: sub_unit.suppressed,
            parent_chain: sub_unit.parent_chain,
            kind: sub_unit.kind,
            name: sub_unit.description,
            file: unit.file.clone(),
            line_start: unit.line_start,
            line_end: unit.line_end,
            signature: NormalizedNode::leaf(NodeKind::Opaque),
            body: sub_unit.node,
            fingerprint,
            node_count: sub_unit.node_count,
            parent_name: Some(unit.name.clone()),
            is_test: unit.is_test,
          }
        })
    })
    .collect()
}

/// Iterate every group of every dimension before ignore filtering.
fn all_unfiltered_groups<'a>(
  ast_groups: &'a MatchedGroups,
  sub_groups: &'a MatchedGroups,
  generic_groups: &'a GenericGroups,
) -> impl Iterator<Item = &'a DuplicateGroup> {
  ast_groups
    .exact
    .iter()
    .chain(ast_groups.near.iter())
    .chain(sub_groups.exact.iter())
    .chain(sub_groups.near.iter())
    .chain(generic_groups.token_normalized.exact.iter())
    .chain(generic_groups.token_normalized.near.iter())
    .chain(generic_groups.token_raw_exact.iter())
    .chain(generic_groups.line_exact.iter())
    .chain(generic_groups.suppressed.iter())
}

/// Apply ignore filtering to exact and near groups.
fn filter_matched_groups(groups: MatchedGroups, ignore_file: &ignore::IgnoreFile, ignored: &mut Vec<DuplicateGroup>) -> MatchedGroups {
  MatchedGroups {
    exact: ignore::filter_ignored(groups.exact, ignore_file, ignored),
    near:  ignore::filter_ignored(groups.near, ignore_file, ignored),
  }
}

/// Apply ignore filtering to generic groups.
///
/// The suppressed population is filtered too: the registry is authoritative,
/// so an ignored group never reappears even under `--show-suppressed`.
#[allow(
  clippy::single_call_fn,
  reason = "Registry filtering applies uniformly to visible and suppressed generic groups while retaining removed groups"
)]
fn filter_generic_groups(groups: GenericGroups, ignore_file: &ignore::IgnoreFile, ignored: &mut Vec<DuplicateGroup>) -> GenericGroups {
  GenericGroups {
    token_normalized: filter_matched_groups(groups.token_normalized, ignore_file, ignored),
    token_raw_exact:  ignore::filter_ignored(groups.token_raw_exact, ignore_file, ignored),
    line_exact:       ignore::filter_ignored(groups.line_exact, ignore_file, ignored),
    suppressed:       ignore::filter_ignored(groups.suppressed, ignore_file, ignored),
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;
  use std::collections::HashSet;
  use std::convert::Infallible;
  use std::fs;
  use std::io;
  use std::path::Path;
  use std::path::PathBuf;

  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;
  use thiserror::Error;

  use super::AnalysisResult;
  use super::CoverageNoteSource;
  use super::MatchedGroups;
  use super::ReportTestFailure;
  use super::SAME_DIMENSION_OVERLAP_SUPPRESSION_RATIO;
  use super::analyze_units;
  use super::analyze_units_with_generic;
  use super::analyze_with_generic;
  use super::apply_coverage_notes;
  use super::check_json;
  use super::check_render;
  use super::check_text;
  use super::is_covered_by_kept;
  use super::split_runs_by;
  use super::suppress_overlapping_groups;
  use crate::analysis::AnalysisPhase;
  use crate::analyzer::LanguageAnalyzer;
  use crate::calculation::LineRangeFailure;
  use crate::code_unit::CodeUnit;
  use crate::code_unit::CodeUnitKind;
  use crate::code_unit::DetectionDimension;
  use crate::config::AnalysisConfig;
  use crate::config::Config;
  use crate::duplicate_group;
  use crate::error::AnalysisError;
  use crate::error::AnalysisFailure;
  use crate::error::CoverageFailure;
  use crate::fingerprint::Fingerprint;
  use crate::grouper;
  use crate::grouper::DuplicateGroup;
  use crate::grouper::MatchKind;
  use crate::ignore;
  use crate::ignore::IgnoreFileError;
  use crate::ignore::IgnoreFileObservation;
  use crate::ignore::IgnoreFileWrite;
  use crate::make_unit;
  use crate::node::BinOpKind;
  use crate::node::LiteralKind;
  use crate::node::NodeKind;
  use crate::node::NormalizedNode;
  use crate::node::PlaceholderKind;
  use crate::node::count_nodes;
  use crate::output::ReportError;
  use crate::suppression::RuleId;
  use crate::suppression::SuppressionPolicy;
  use crate::text_units;

  /// Match adjacent integer values without overflowing at the integer limit.
  fn consecutive(previous: usize, current: usize) -> bool {
    previous.checked_add(1) == Some(current)
  }

  /// An empty slice has no adjacent runs.
  #[test]
  fn empty_input_yields_no_runs() -> Result<(), ConditionFailure> {
    let items: [usize; 0] = [];
    ensure(
      split_runs_by(&items, |previous, current| consecutive(*previous, *current)).is_empty(),
      "empty input must not produce a run",
    )
    .map(drop)
  }

  /// A consecutive slice stays one complete borrowed run.
  #[test]
  fn single_run_stays_whole() -> Result<(), ConditionFailure> {
    let items = [3, 4, 5, 6];
    let runs = split_runs_by(&items, |previous, current| consecutive(*previous, *current));
    ensure(runs == [items.as_slice()], "adjacent input must remain one complete borrowed run").map(drop)
  }

  /// Each gap starts a new run without losing an input element.
  #[test]
  fn gaps_split_into_multiple_runs() -> Result<(), ConditionFailure> {
    let items = [1, 2, 5, 6, 9];
    let runs = split_runs_by(&items, |previous, current| consecutive(*previous, *current));
    ensure(
      runs == [[1, 2].as_slice(), [5, 6].as_slice(), [9].as_slice()],
      "each gap must split the input while preserving every element in order",
    )
    .map(drop)
  }

  /// Failed report checks keep their full rendered subject and original rendering failure.
  #[test]
  fn report_assertion_failures_preserve_their_subjects() -> Result<(), ConditionFailure> {
    let text = "complete rendered report\n";
    let text_failure = check_text(text.to_owned(), |output| {
      ensure(output.is_empty(), "expected an empty report").map(drop)
    });
    ensure(
      matches!(text_failure, Err(ReportTestFailure::TextExpectation { output, .. }) if output == text),
      "a failed text expectation retains every rendered character",
    )
    .map(drop)?;
    let document = serde_json::Value::from("complete JSON subject");
    let json_failure = check_json(document.clone(), |output| ensure(output.is_null(), "expected null").map(drop));
    ensure(
      matches!(json_failure, Err(ReportTestFailure::JsonExpectation { document: retained, .. }) if retained == document),
      "a failed JSON expectation retains the complete original value",
    )
    .map(drop)?;
    let render_failure = check_render(
      Err(ReportError::Write(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "closed report stream",
      ))),
      b"written prefix".to_vec(),
      |outcome, _output| ensure(outcome.is_ok(), "expected successful rendering").map(drop),
    );
    ensure(
      matches!(render_failure, Err(ReportTestFailure::RenderExpectation { outcome, output, .. })
        if output == b"written prefix"
          && matches!(*outcome, Err(ReportError::Write(ref native))
            if native.kind() == io::ErrorKind::BrokenPipe && native.to_string() == "closed report stream")),
      "a failed rendering expectation retains both the output prefix and complete native writer failure",
    )
    .map(drop)
  }

  /// Native setup and analysis failures from pipeline behavior tests.
  #[derive(Debug, Error)]
  enum PipelineTestFailure {
    /// A coverage calculation rejected the original source interval or counts.
    #[error(transparent)]
    Calculation(#[from] CoverageFailure),
    /// A direct grouping or coverage expectation failed.
    #[error(transparent)]
    Assertion(#[from] ConditionFailure),
    /// A fixture filesystem operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Analysis returned a typed failure and any completed findings.
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    /// Line-window assertions failed after measuring the complete finding population.
    #[error("line-window measurements violate the fixture contract: {source}")]
    LineMeasurements {
      /// Complete analysis owning every measured member.
      analysis:     Box<AnalysisResult>,
      /// Native lengths or typed interval failures in member order.
      measurements: Vec<Result<usize, LineRangeFailure>>,
      /// Failed behavioral expectation.
      source:       ConditionFailure,
    },
    /// Preparing the registry fixture failed with its original typed evidence.
    #[error(transparent)]
    Registry(#[from] IgnoreFileError),
    /// Analysis after a successful registry write failed or violated its contract.
    #[error("persisted registry analysis failed: {source}; write: {write:?}")]
    RegistryAnalysis {
      /// Complete successful write that preceded the analysis.
      write:  Box<IgnoreFileWrite>,
      /// Complete analysis failure or failed behavioral expectation.
      source: Box<Self>,
    },
    /// The pipeline returned an unexpected partial result or failure.
    #[error("pipeline outcome expectation failed: {source}")]
    Expectation {
      /// Complete native pipeline result, retained for inspection.
      outcome: Box<Result<AnalysisResult, AnalysisError>>,
      /// Assertion explaining the violated contract.
      source:  ConditionFailure,
    },
    /// A later outcome failed to preserve the findings and warnings from its baseline.
    #[error("pipeline preservation comparison failed: {source}")]
    Comparison {
      /// Complete successful baseline for the unchanged source corpus.
      baseline: Box<AnalysisResult>,
      /// Complete later pipeline result, including native failure evidence.
      outcome:  Box<Result<AnalysisResult, AnalysisError>>,
      /// Failed preservation expectation.
      source:   ConditionFailure,
    },
    /// Coverage annotations differ from the expected complete AST and sub-AST groups.
    #[error("coverage annotation expectation failed: {source}")]
    Coverage {
      /// Complete annotated groups in AST then sub-AST order.
      outcome:  Box<(MatchedGroups, MatchedGroups)>,
      /// Complete expected groups in the same order.
      expected: Box<(MatchedGroups, MatchedGroups)>,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
  }

  /// Keep the complete analysis available when one of its behavioral assertions fails.
  fn check_analysis<Observed>(
    analysis: AnalysisResult,
    check: impl FnOnce(&AnalysisResult) -> Result<Observed, ConditionFailure>,
  ) -> Result<Observed, PipelineTestFailure> {
    check(&analysis).map_err(|source| PipelineTestFailure::Expectation {
      outcome: Box::new(Ok(analysis)),
      source,
    })
  }

  /// Preserve the registry write and require analysis to retain its complete loaded document.
  fn check_registry_analysis(
    outcome: Result<AnalysisResult, AnalysisError>,
    write: IgnoreFileWrite,
    check: impl FnOnce(&AnalysisResult) -> Result<(), ConditionFailure>,
  ) -> Result<(), PipelineTestFailure> {
    outcome
      .map_err(PipelineTestFailure::Analysis)
      .and_then(|analysis| {
        check_analysis(analysis, |completed| {
          ensure(
            matches!(completed.ignore_file, Some(ref loaded)
              if loaded.path == write.path
                && loaded.registry == write.registry
                && matches!(loaded.observation, IgnoreFileObservation::Read { ref contents }
                  if *contents == write.contents)),
            "analysis retains the exact registry path, complete model, and document from the successful write",
          )
          .map(drop)?;
          check(completed)
        })
      })
      .map_err(|source| PipelineTestFailure::RegistryAnalysis {
        write:  Box::new(write),
        source: Box::new(source),
      })
  }

  /// Distinguishable normalized content used to control exact group membership.
  fn test_body(contents: &str) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::leaf(NodeKind::Token(contents.to_owned()))])
  }

  /// Build a complete unit whose source identity and normalized content are explicit.
  fn test_unit(kind: CodeUnitKind, name: &str, file: &Path, line_start: usize, line_end: usize, body: NormalizedNode) -> CodeUnit {
    CodeUnit {
      suppressed: None,
      parent_chain: None,
      kind,
      name: name.to_owned(),
      file: file.to_path_buf(),
      line_start,
      line_end,
      signature: NormalizedNode::leaf(NodeKind::Opaque),
      fingerprint: Fingerprint::from_node(&body),
      node_count: count_nodes(&body),
      body,
      parent_name: None,
      is_test: false,
    }
  }

  /// Construct independent group identities for overlap-policy scenarios.
  fn test_group(dimension: DetectionDimension, fingerprint_seed: &str, members: Vec<CodeUnit>) -> DuplicateGroup {
    duplicate_group(
      dimension,
      MatchKind::Exact,
      Fingerprint::from_bytes(fingerprint_seed.as_bytes()),
      1.0,
      members,
    )
  }

  /// Enable line detection with a scenario-specific window size and registry root.
  fn line_only_config(root: &Path, min_lines: usize) -> Config {
    Config {
      root: root.to_path_buf(),
      line_min_lines: min_lines,
      enabled_dimensions: BTreeSet::from([DetectionDimension::Line]),
      ..Config::default()
    }
  }

  /// Enable AST grouping with the comparison threshold required by the scenario.
  fn ast_only_config(root: &Path, similarity_threshold: f64) -> Config {
    Config {
      root: root.to_path_buf(),
      similarity_threshold,
      enabled_dimensions: BTreeSet::from([DetectionDimension::Ast]),
      ..Config::default()
    }
  }

  /// Exercise fallback extraction without top-level grouping or a restrictive node floor.
  fn sub_ast_only_config(root: &Path) -> Config {
    Config {
      root: root.to_path_buf(),
      sub_function: true,
      min_sub_nodes: 1,
      enabled_dimensions: BTreeSet::from([DetectionDimension::SubAst]),
      ..Config::default()
    }
  }

  /// Put two independently supplied function bodies at fixed, distinct source locations.
  fn paired_function_units(root: &Path, first_body: NormalizedNode, second_body: NormalizedNode) -> Vec<CodeUnit> {
    vec![
      test_unit(CodeUnitKind::Function, "first", &root.join("first.rs"), 10, 20, first_body),
      test_unit(CodeUnitKind::Function, "second", &root.join("second.rs"), 30, 40, second_body),
    ]
  }

  /// Build an identifier placeholder with its declared normalization index.
  fn variable(index: usize) -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, index))
  }

  /// Build an integer-literal node without introducing an incidental literal value.
  fn literal_int() -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int))
  }

  /// Preserve the ordered children of a normalized statement block.
  fn block(children: Vec<NormalizedNode>) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::Block, children)
  }

  /// Build a binary operation whose operator and operands define its behavior.
  fn binary(op: BinOpKind, left: NormalizedNode, right: NormalizedNode) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::BinaryOp(op), vec![left, right])
  }

  /// Retain the absent-else sentinel while varying the behavior of the then branch.
  fn if_with_then_branch(then_branch: NormalizedNode) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::If, vec![
      binary(BinOpKind::Gt, variable(0), literal_int()),
      then_branch,
      NormalizedNode::none(),
    ])
  }

  /// Mark every parsed source unit as a test while leaving generic text unclassified.
  struct TestAnalyzer;

  impl LanguageAnalyzer for TestAnalyzer {
    type Error = Infallible;

    fn file_extensions(&self) -> &[&str] {
      &["rs"]
    }

    fn parse_file(&self, path: &Path, source: &str, _config: AnalysisConfig) -> Result<Vec<CodeUnit>, Self::Error> {
      let body = NormalizedNode::leaf(NodeKind::Opaque);
      Ok(vec![CodeUnit {
        suppressed: None,
        parent_chain: None,
        kind: CodeUnitKind::Function,
        name: "test_unit".to_owned(),
        file: path.to_path_buf(),
        line_start: 1,
        line_end: source.lines().count().max(1),
        signature: NormalizedNode::leaf(NodeKind::Opaque),
        fingerprint: Fingerprint::from_node(&body),
        node_count: 1,
        body,
        parent_name: None,
        is_test: true,
      }])
    }
  }

  /// Test exclusion removes language-classified source while retaining independent document
  /// duplicates.
  #[test]
  fn exclude_tests_keeps_non_test_generic_text() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first_test = workspace.path().join("first.rs");
    let second_test = workspace.path().join("second.rs");
    let first_doc = workspace.path().join("first.md");
    let second_doc = workspace.path().join("second.md");
    for path in [&first_test, &second_test] {
      fs::write(path, "test duplicated\nbody\n")?;
    }
    for path in [&first_doc, &second_doc] {
      fs::write(path, "if docs match {\nlet value = 1;\nreturn value;\n}\n")?;
    }

    let config = Config {
      root: workspace.path().to_path_buf(),
      exclude_tests: true,
      line_min_lines: 3,
      enabled_dimensions: BTreeSet::from([DetectionDimension::Line]),
      ..Config::default()
    };

    let result = analyze_with_generic(
      &TestAnalyzer,
      &[first_test.clone(), second_test.clone()],
      &[first_test, second_test, first_doc.clone(), second_doc.clone()],
      &config,
    )?;

    check_analysis(result, |analysis| {
      ensure(
        matches!(analysis.line_exact_groups.as_slice(), [group]
          if group.members.iter().map(|member| &member.file).eq([&first_doc, &second_doc])),
        "generic text from both documents survives while language-classified test files are excluded",
      )
      .map(drop)
    })
  }

  /// Analyze a line pair against one precise AST group with independently chosen spans.
  #[allow(
    clippy::single_call_fn,
    reason = "The fixture separates complete source-unit construction from the coverage policy matrix"
  )]
  fn analyze_coverage_fixture(
    first_span: (usize, usize),
    second_span: (usize, usize),
    dimensions: &[DetectionDimension],
  ) -> Result<(AnalysisResult, Vec<CodeUnit>), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let ast_body = test_body("same ast body");
    let line_body = test_body("same line window");
    let units = paired_function_units(workspace.path(), ast_body.clone(), ast_body);
    let line_units = vec![
      test_unit(
        CodeUnitKind::LineWindow,
        "line",
        &first,
        first_span.0,
        first_span.1,
        line_body.clone(),
      ),
      test_unit(CodeUnitKind::LineWindow, "line", &second, second_span.0, second_span.1, line_body),
    ];
    let config = Config {
      root: workspace.path().to_path_buf(),
      enabled_dimensions: dimensions.iter().copied().collect(),
      ..Config::default()
    };

    let analysis = analyze_units_with_generic(&units, &[], &[], &[], &line_units, Vec::new(), &config)?;
    Ok((analysis, line_units))
  }

  /// Coverage uses one precise group and respects the configured detection dimensions.
  #[test]
  fn precise_ast_coverage_respects_overlap_and_enabled_dimensions() -> Result<(), PipelineTestFailure> {
    let scenarios = [
      (
        (12, 16),
        (32, 36),
        vec![DetectionDimension::Ast, DetectionDimension::Line],
        (1, 0),
        vec![Some(RuleId::GroupCoveredByAst)],
        "complete coverage retains the line pair under its precise AST coverer",
      ),
      (
        (8, 17),
        (28, 37),
        vec![DetectionDimension::Ast, DetectionDimension::Line],
        (1, 0),
        vec![Some(RuleId::GroupCoveredByAst)],
        "the substantial-coverage boundary retains the line pair under its precise AST coverer",
      ),
      (
        (7, 14),
        (27, 34),
        vec![DetectionDimension::Ast, DetectionDimension::Line],
        (1, 1),
        Vec::new(),
        "edge overlap leaves both duplicate concepts visible",
      ),
      (
        (50, 54),
        (60, 64),
        vec![DetectionDimension::Ast, DetectionDimension::Line],
        (1, 1),
        Vec::new(),
        "disjoint source intervals leave both duplicate concepts visible",
      ),
      (
        (12, 16),
        (32, 36),
        vec![DetectionDimension::Line],
        (0, 1),
        Vec::new(),
        "disabled AST detection supplies no coverer for the line pair",
      ),
    ];
    for (first_span, second_span, dimensions, expected_counts, expected_rules, context) in scenarios {
      let (result, expected_members) = analyze_coverage_fixture(first_span, second_span, &dimensions)?;
      check_analysis(result, |analysis| {
        ensure(
          (analysis.exact_groups.len(), analysis.line_exact_groups.len()) == expected_counts
            && analysis
              .suppressed_groups
              .iter()
              .map(|group| group.suppressed)
              .collect::<Vec<_>>()
              == expected_rules,
          context,
        )
        .map(drop)?;
        ensure(
          analysis
            .groups_with_suppressed()
            .filter(|group| group.dimension == DetectionDimension::Line)
            .flat_map(|group| &group.members)
            .cloned()
            .collect::<Vec<_>>()
            == expected_members,
          "coverage classification retains every field of the original line members",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// Repeated occurrences in one file contribute their clipped union, without counting overlap
  /// twice.
  #[test]
  fn precise_coverage_unions_unsorted_overlapping_occurrences() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let ast_body = test_body("repeated occurrence");
    let line_body = test_body("candidate line window");
    let line_units = vec![
      test_unit(CodeUnitKind::LineWindow, "line", &first, 10, 19, line_body.clone()),
      test_unit(CodeUnitKind::LineWindow, "line", &second, 30, 39, line_body),
    ];
    let config = Config {
      root: workspace.path().to_path_buf(),
      enabled_dimensions: [DetectionDimension::Ast, DetectionDimension::Line].into_iter().collect(),
      ..Config::default()
    };
    for (spans, rule) in [
      ([(16, 18), (9, 12), (12, 14)], Some(RuleId::GroupCoveredByAst)),
      ([(16, 17), (9, 12), (11, 13)], None),
    ] {
      let mut units: Vec<_> = spans
        .into_iter()
        .map(|(start, end)| test_unit(CodeUnitKind::Function, "occurrence", &first, start, end, ast_body.clone()))
        .collect();
      units.push(test_unit(CodeUnitKind::Function, "peer", &second, 30, 39, ast_body.clone()));
      let result = analyze_units_with_generic(&units, &[], &[], &[], &line_units, Vec::new(), &config)?;
      check_analysis(result, |analysis| {
        let groups: Vec<_> = analysis
          .groups_with_suppressed()
          .filter(|group| group.dimension == DetectionDimension::Line)
          .collect();
        ensure(
          matches!(groups.as_slice(), [group]
            if group.members == line_units && group.suppressed == rule)
            && analysis.line_exact_groups.is_empty() == rule.is_some(),
          "one group's clipped union covers eight of ten lines in the first case and only six in the second; overlap cannot count twice",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// A failed registry load retains every completed finding and typed configuration warning.
  #[test]
  fn invalid_registry_preserves_findings_before_ignore_filtering() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let body = test_body("shared body");
    let units = paired_function_units(workspace.path(), body.clone(), body);
    let mut config = ast_only_config(workspace.path(), Config::default().similarity_threshold);
    let (policy, warnings) = SuppressionPolicy::resolve(&["no.such-rule".to_owned()], &["also.unknown".to_owned()]);
    config.suppression = policy;
    let baseline = analyze_units(&units, warnings.clone(), &config)?;
    let path = ignore::ignore_file_path(workspace.path());
    let contents = "[[ignore]\n";
    fs::write(&path, contents)?;
    let outcome = analyze_units(&units, warnings.clone(), &config);
    ensure(
      matches!(outcome, Err(AnalysisError {
        ref source,
        ref analysis,
      }) if matches!(**source, AnalysisFailure::Ignore(IgnoreFileError::Decode { path: ref observed_path, contents: ref observed_contents, .. })
          if *observed_path == path && observed_contents == contents)
        && baseline.warnings == warnings
        && analysis.warnings == warnings
        && analysis.stats.as_ref() == Some(&baseline.stats)
        && super::all_unfiltered_groups(&analysis.ast_groups, &analysis.sub_groups, &analysis.generic_groups).collect::<Vec<_>>()
          == baseline.groups_with_suppressed().collect::<Vec<_>>()
        && analysis.phase == AnalysisPhase::Complete
        && analysis.all_fingerprints == baseline.all_fingerprints
        && analysis.all_member_fingerprint_sets == baseline.all_member_fingerprint_sets
        && analysis.ignored_groups.is_empty()
        && analysis.ignore_file.is_none()),
      "registry failure retains complete pre-ignore findings, typed warnings, statistics, and liveness with the native decoding failure",
    ).map(drop)
    .map_err(|source| PipelineTestFailure::Comparison {
      baseline: Box::new(baseline),
      outcome: Box::new(outcome),
      source,
    })
  }

  /// A calculation failure preserves an earlier registry failure and leaves statistics unfinished.
  #[test]
  fn statistics_failure_retains_prior_registry_failure_and_inputs() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let units = vec![
      test_unit(CodeUnitKind::Function, "largest", &first, 1, usize::MAX, test_body("largest")),
      test_unit(CodeUnitKind::Function, "final", &second, 1, 1, test_body("final")),
    ];
    let path = ignore::ignore_file_path(workspace.path());
    let contents = "[[ignore]\n";
    fs::write(&path, contents)?;
    let config = ast_only_config(workspace.path(), 0.9);
    let outcome = analyze_units(&units, Vec::new(), &config);
    ensure(matches!(&outcome, Err(failure)
      if failure.analysis.phase == AnalysisPhase::Statistics
        && failure.analysis.stats.is_none()
        && failure.analysis.units.ast == units
        && matches!(failure.analysis.ignore_failure, Some(IgnoreFileError::Decode { path: ref observed_path, contents: ref observed_contents, .. })
          if *observed_path == path && observed_contents == contents)
        && matches!(*failure.source, AnalysisFailure::Statistics(ref statistics)
          if statistics.completed.is_empty() && statistics.population == grouper::LinePopulation::Corpus
            && statistics.source.completed == usize::MAX
            && units.last() == Some(statistics.source.unit.as_ref())
            && statistics.source.source == grouper::LineSumFailureCause::Overflow { incoming: 1 })),
      "failed line accumulation retains the original corpus and earlier native registry failure without fabricated statistics").map(drop)
      .map_err(|source| PipelineTestFailure::Expectation { outcome: Box::new(outcome), source })
  }

  /// Fingerprint-based registry policy preserves complete hidden findings and their liveness.
  #[test]
  fn ignore_filtering_keeps_group_fingerprints_live_pre_policy() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let body = test_body("same ast body");
    let units = paired_function_units(workspace.path(), body.clone(), body);
    let config = ast_only_config(workspace.path(), Config::default().similarity_threshold);
    let baseline = analyze_units(&units, Vec::new(), &config)?;
    let expected_groups = check_analysis(baseline, |analysis| {
      ensure(
        analysis.exact_groups.len() == 1,
        "the unfiltered function pair forms one exact group",
      )
      .map(drop)?;
      Ok(analysis.exact_groups.clone())
    })?;
    let expected_fingerprints = expected_groups.iter().map(|group| group.fingerprint).collect::<HashSet<_>>();
    let ignore_file = ignore::IgnoreFile {
      ignore: expected_groups
        .iter()
        .map(|group| ignore::IgnoreEntry {
          fingerprint:         group.fingerprint.into(),
          reason:              Some("intentional duplicate".to_owned()),
          members:             Vec::new(),
          member_fingerprints: Vec::new(),
        })
        .collect(),
    };
    let write = ignore::save_ignore_file(workspace.path(), &ignore_file)?;

    let result = analyze_units(&units, Vec::new(), &config);
    check_registry_analysis(result, write, |analysis| {
      ensure(
        analysis.exact_groups.is_empty()
          && analysis.ignored_groups == expected_groups
          && analysis.all_fingerprints == expected_fingerprints,
        "registry policy retains the complete ignored group and its pre-filter fingerprint liveness",
      )
      .map(drop)
    })
  }

  /// Member-based registry policy preserves near-group evidence across fingerprint drift.
  #[test]
  fn member_fingerprint_ignores_keep_member_sets_live_pre_policy() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let units = paired_function_units(workspace.path(), test_body("first near body"), test_body("second near body"));
    let config = ast_only_config(workspace.path(), 0.0);
    let baseline = analyze_units(&units, Vec::new(), &config)?;
    let expected_groups = check_analysis(baseline, |analysis| {
      ensure(
        analysis.near_groups.len() == 1,
        "the distinct bodies form one near group at the configured threshold",
      )
      .map(drop)?;
      Ok(analysis.near_groups.clone())
    })?;
    let expected_fingerprints = expected_groups.iter().map(|group| group.fingerprint).collect::<HashSet<_>>();
    let expected_member_sets: Vec<HashSet<_>> = expected_groups
      .iter()
      .map(|group| group.members.iter().map(|member| member.fingerprint).collect())
      .collect();
    let ignore_file = ignore::IgnoreFile {
      ignore: expected_groups
        .iter()
        .map(|group| ignore::IgnoreEntry {
          fingerprint:         Fingerprint::from_bytes(b"old near group fingerprint").into(),
          reason:              Some("membership-stable near duplicate".to_owned()),
          members:             Vec::new(),
          member_fingerprints: group.members.iter().map(|member| member.fingerprint.into()).collect(),
        })
        .collect(),
    };
    let write = ignore::save_ignore_file(workspace.path(), &ignore_file)?;

    let result = analyze_units(&units, Vec::new(), &config);
    check_registry_analysis(result, write, |analysis| {
      ensure(
        analysis.near_groups.is_empty()
          && analysis.ignored_groups == expected_groups
          && analysis.all_fingerprints == expected_fingerprints
          && analysis.all_member_fingerprint_sets == expected_member_sets,
        "member-based registry matching preserves the complete near group, current identity, and pre-filter member sets",
      )
      .map(drop)
    })
  }

  /// Separate covering groups cannot pool their members to hide an unrelated candidate family.
  #[test]
  fn same_dimension_overlap_requires_one_kept_group_to_cover_all_members() -> Result<(), PipelineTestFailure> {
    let first = PathBuf::from("first.rs");
    let second = PathBuf::from("second.rs");
    let third = PathBuf::from("third.rs");
    let fourth = PathBuf::from("fourth.rs");
    let body = test_body("same line window");
    let candidate = test_group(DetectionDimension::Line, "candidate", vec![
      test_unit(CodeUnitKind::LineWindow, "candidate", &first, 11, 15, body.clone()),
      test_unit(CodeUnitKind::LineWindow, "candidate", &third, 31, 35, body.clone()),
    ]);
    let first_kept = test_group(DetectionDimension::Line, "first_kept", vec![
      test_unit(CodeUnitKind::LineWindow, "kept", &first, 10, 14, body.clone()),
      test_unit(CodeUnitKind::LineWindow, "kept", &second, 20, 24, body.clone()),
    ]);
    let second_kept = test_group(DetectionDimension::Line, "second_kept", vec![
      test_unit(CodeUnitKind::LineWindow, "kept", &third, 30, 34, body.clone()),
      test_unit(CodeUnitKind::LineWindow, "kept", &fourth, 40, 44, body),
    ]);

    ensure(
      !is_covered_by_kept(&candidate, &[first_kept, second_kept], SAME_DIMENSION_OVERLAP_SUPPRESSION_RATIO)?,
      "unrelated retained groups cannot combine their coverage to suppress one candidate family",
    )
    .map(drop)
    .map_err(PipelineTestFailure::from)
  }

  /// Eight-line duplicated computation whose overlapping five-line windows must merge.
  const COMPUTATION: &str = "\
let total = alpha + beta;
let scaled = total * gamma;
let checked = scaled - delta;
let rounded = checked + epsilon;
let bounded = rounded * zeta;
let shifted = bounded - eta;
let summed = shifted + theta;
return summed * iota;
";

  /// Compatible shifted windows merge into complete source regions with their original content.
  #[test]
  fn shifted_line_window_groups_merge_into_concept_level_group() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    for path in [&first, &second] {
      fs::write(path, COMPUTATION)?;
    }
    let config = line_only_config(workspace.path(), 5);
    let result = analyze_with_generic(&TestAnalyzer, &[], &[first.clone(), second.clone()], &config)?;

    check_analysis(result, |analysis| {
      ensure(
        matches!(analysis.line_exact_groups.as_slice(), [group]
        if group.members.iter()
        .map(|member| (&member.file, member.line_start, member.line_end, text_units::window_values(member)))
        .collect::<Vec<_>>()
        == [
          (&first, 1, 8, Some(COMPUTATION.lines().collect())),
          (&second, 1, 8, Some(COMPUTATION.lines().collect())),
        ]),
        "both merged members preserve the complete computation and its source span",
      )
      .map(drop)
    })
  }

  /// Field assignment followed by the receiver, the supported setter suppression shape.
  fn setter_body() -> NormalizedNode {
    let field = NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]);
    let assign = NormalizedNode::with_children(NodeKind::Assign, vec![field, variable(2)]);
    block(vec![assign, variable(0)])
  }

  /// Place a suppression fixture at a shared source location with consistent node counts.
  fn unit_with_body(name: &str, kind: CodeUnitKind, body: NormalizedNode) -> CodeUnit {
    test_unit(kind, name, Path::new("src/sample.rs"), 1, 4, body)
  }

  /// Trivial setter duplicates remain inspectable under their shared suppression rule.
  #[test]
  fn trivial_setter_pairs_group_as_suppressed_with_their_rule() -> Result<(), PipelineTestFailure> {
    let units = vec![
      unit_with_body("Gauge::with_a", CodeUnitKind::Method, setter_body()),
      unit_with_body("Gauge::with_b", CodeUnitKind::Method, setter_body()),
    ];
    let result = analyze_units(&units, Vec::new(), &Config::default())?;

    check_analysis(result, |analysis| {
      ensure(
        analysis.exact_groups.is_empty()
          && matches!(analysis.suppressed_groups.as_slice(), [group]
            if group.suppressed == Some(RuleId::AstSetterReturningSelf)
              && analysis.all_fingerprints.contains(&group.fingerprint)),
        "the setter pair remains detectable under its suppression rule and retains pre-ignore liveness",
      )
      .map(drop)
    })
  }

  /// A group containing an unsuppressed member remains visible with every member's tag.
  #[test]
  fn mixed_groups_stay_visible_with_tagged_members() -> Result<(), PipelineTestFailure> {
    // An impl-block unit shares the setter's content but is not a
    // taggable kind, so the group stays visible and only the method
    // member carries the rule.
    let units = vec![
      unit_with_body("Gauge::with_a", CodeUnitKind::Method, setter_body()),
      unit_with_body("twin impl", CodeUnitKind::ImplBlock, setter_body()),
    ];
    let result = analyze_units(&units, Vec::new(), &Config::default())?;

    check_analysis(result, |analysis| {
      ensure(
        analysis.exact_groups.iter().map(|group| group.suppressed).collect::<Vec<_>>() == [None] && analysis.suppressed_groups.is_empty(),
        "a mixed group remains visible without a group-level suppression tag",
      )
      .map(drop)?;
      ensure(
        analysis
          .exact_groups
          .iter()
          .flat_map(|group| &group.members)
          .map(|member| (member.name.as_str(), member.suppressed))
          .collect::<Vec<_>>()
          == [("Gauge::with_a", Some(RuleId::AstSetterReturningSelf)), ("twin impl", None)],
        "only the method member receives the setter rule while the implementation member remains untagged",
      )
      .map(drop)
    })
  }

  /// Registry policy takes precedence over rule-suppressed presentation without losing findings.
  #[test]
  fn ignore_entries_hide_suppressed_groups_and_count_as_ignored() -> Result<(), PipelineTestFailure> {
    // The registry is authoritative even over rule-suppressed findings:
    // an ignored suppressed group leaves `suppressed_groups`, increments
    // the ignored count, and stays live for cleanup accounting.
    let workspace = TempDir::new()?;
    let units = vec![
      unit_with_body("Gauge::with_a", CodeUnitKind::Method, setter_body()),
      unit_with_body("Gauge::with_b", CodeUnitKind::Method, setter_body()),
    ];
    let config = Config {
      root: workspace.path().to_path_buf(),
      ..Config::default()
    };
    let unfiltered = analyze_units(&units, Vec::new(), &config)?;
    let expected_groups = check_analysis(unfiltered, |analysis| {
      ensure(
        analysis.suppressed_groups.len() == 1,
        "the setter pair initially forms one rule-suppressed group",
      )
      .map(drop)?;
      Ok(analysis.suppressed_groups.clone())
    })?;
    let expected_fingerprints = expected_groups.iter().map(|group| group.fingerprint).collect::<HashSet<_>>();

    let ignore_file = ignore::IgnoreFile {
      ignore: expected_groups
        .iter()
        .map(|group| ignore::IgnoreEntry {
          fingerprint:         group.fingerprint.into(),
          reason:              None,
          members:             Vec::new(),
          member_fingerprints: Vec::new(),
        })
        .collect(),
    };
    let write = ignore::save_ignore_file(workspace.path(), &ignore_file)?;

    let result = analyze_units(&units, Vec::new(), &config);
    check_registry_analysis(result, write, |analysis| {
      ensure(
        analysis.suppressed_groups.is_empty()
          && analysis.stats.ignored_group_count == 1
          && analysis.ignored_groups == expected_groups
          && analysis.all_fingerprints == expected_fingerprints,
        "registry policy retains the complete suppressed group as ignored and preserves its liveness",
      )
      .map(drop)
    })
  }

  /// Precise covering groups report the dimension and match kind of retained shadow groups.
  #[test]
  fn covering_groups_carry_also_seen_notes() -> Result<(), PipelineTestFailure> {
    // A line window fully covered by one AST group is tagged
    // group.covered-by-ast and the covering group records the shadow.
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let body = "\
let weight = mass * pull;
let drag = weight / spread;
let lift = drag - offset;
let glide = lift * trim;
let sink = glide + ballast;
";
    for path in [&first, &second] {
      fs::write(path, body)?;
    }

    let mut units = vec![
      make_unit("alpha_calc", "first.rs", 1, 5),
      make_unit("beta_calc", "second.rs", 1, 5),
    ];
    for (unit, file) in units.iter_mut().zip([&first, &second]) {
      unit.file = file.clone();
    }

    let config = Config {
      root: workspace.path().to_path_buf(),
      enabled_dimensions: BTreeSet::from([DetectionDimension::Ast, DetectionDimension::Line]),
      ..Config::default()
    };
    let mut all_line_units = text_units::extract(&first, body, &config).lines;
    all_line_units.append(&mut text_units::extract(&second, body, &config).lines);

    let result = analyze_units_with_generic(&units, &[], &[], &[], &all_line_units, Vec::new(), &config)?;

    check_analysis(result, |analysis| {
      ensure(
        analysis.exact_groups.len() == 1
          && analysis.line_exact_groups.is_empty()
          && analysis
            .suppressed_groups
            .iter()
            .map(|group| group.suppressed)
            .collect::<Vec<_>>()
            == [Some(RuleId::GroupCoveredByAst)],
        "the AST pair stays visible and retains the covered line group under its rule",
      )
      .map(drop)?;
      ensure(
        analysis
          .exact_groups
          .iter()
          .flat_map(|group| &group.also_seen)
          .collect::<Vec<_>>()
          == [&grouper::CoverageNote {
            dimension:   DetectionDimension::Line,
            match_kind:  MatchKind::Exact,
            group_count: 1,
          }],
        "the precise group records the covered dimension, match kind, and group count together",
      )
      .map(drop)
    })
  }

  /// Annotation counts remain separate by covering group, dimension, and match kind.
  #[test]
  fn coverage_notes_count_matching_events_in_canonical_order() -> Result<(), PipelineTestFailure> {
    let ast_group = test_group(DetectionDimension::Ast, "ast", vec![
      make_unit("first", "first.rs", 1, 5),
      make_unit("second", "second.rs", 1, 5),
    ]);
    let sub_group = test_group(DetectionDimension::SubAst, "sub", vec![
      make_unit("nested_first", "first.rs", 2, 4),
      make_unit("nested_second", "second.rs", 2, 4),
    ]);
    let mut ast = MatchedGroups {
      exact: vec![ast_group],
      near:  Vec::new(),
    };
    let mut sub = MatchedGroups {
      exact: vec![sub_group],
      near:  Vec::new(),
    };
    let mut expected = (ast.clone(), sub.clone());
    let expected_notes = [
      vec![
        grouper::CoverageNote {
          dimension:   DetectionDimension::TokenNormalized,
          match_kind:  MatchKind::Near,
          group_count: 1,
        },
        grouper::CoverageNote {
          dimension:   DetectionDimension::Line,
          match_kind:  MatchKind::Exact,
          group_count: 2,
        },
      ],
      vec![grouper::CoverageNote {
        dimension:   DetectionDimension::Line,
        match_kind:  MatchKind::Near,
        group_count: 1,
      }],
    ];
    for (group, annotations) in expected.0.exact.iter_mut().chain(&mut expected.1.exact).zip(expected_notes) {
      group.also_seen = annotations;
    }
    let notes = [
      (1, DetectionDimension::Line, MatchKind::Near),
      (0, DetectionDimension::Line, MatchKind::Exact),
      (0, DetectionDimension::TokenNormalized, MatchKind::Near),
      (0, DetectionDimension::Line, MatchKind::Exact),
    ]
    .into_iter()
    .map(|(coverer, dimension, match_kind)| CoverageNoteSource {
      coverer,
      dimension,
      match_kind,
    })
    .collect();
    apply_coverage_notes(&mut ast, Some(&mut sub), notes);
    apply_coverage_notes(&mut ast, Some(&mut sub), Vec::new());
    let outcome = (ast, sub);
    ensure(
      outcome == expected,
      "coverage events retain their independent owners and stable annotation order; an empty batch preserves existing notes",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::Coverage {
      outcome: Box::new(outcome),
      expected: Box::new(expected),
      source,
    })
  }

  /// Fully tagged windows remain available with their rule, members, and pre-ignore identities.
  #[test]
  fn fully_suppressed_window_groups_move_to_suppressed_groups() -> Result<(), PipelineTestFailure> {
    // A duplicated chain-tail fragment groups, but every member carries
    // the chain-tail tag, so the group lands in `suppressed_groups` with
    // the rule while staying out of the visible line groups. Its
    // fingerprint stays live for ignore-entry accounting.
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let tail = "\
builder()
    .alpha(one)
    .bravo(two)
    .charlie(three)
    .delta(four);
";
    for path in [&first, &second] {
      fs::write(path, tail)?;
    }

    let config = line_only_config(workspace.path(), 5);
    let result = analyze_with_generic(&TestAnalyzer, &[], &[first.clone(), second.clone()], &config)?;

    check_analysis(result, |analysis| {
      ensure(
        analysis.line_exact_groups.is_empty()
          && matches!(analysis.suppressed_groups.as_slice(), [group]
            if group.suppressed == Some(RuleId::LineChainTail)
              && group.members.iter().map(|member| &member.file).eq([&first, &second])
              && analysis.all_fingerprints.contains(&group.fingerprint)),
        "the complete chain-tail pair remains available with its rule, source identities, and pre-ignore liveness",
      )
      .map(drop)
    })
  }

  /// Unrelated prefixes cannot change a merged region's content-derived identity.
  #[test]
  fn merged_line_window_groups_keep_location_independent_fingerprints() -> Result<(), PipelineTestFailure> {
    let run = |prefix: &str| -> Result<AnalysisResult, PipelineTestFailure> {
      let workspace = TempDir::new()?;
      let first = workspace.path().join("first.rs");
      let second = workspace.path().join("second.rs");
      fs::write(&first, format!("{prefix}{COMPUTATION}"))?;
      fs::write(&second, COMPUTATION)?;
      let config = line_only_config(workspace.path(), 5);
      Ok(analyze_with_generic(&TestAnalyzer, &[], &[first, second], &config)?)
    };

    let plain = run("")?;
    let expected_fingerprints = check_analysis(plain, |analysis| {
      ensure(
        analysis.line_exact_groups.len() == 1,
        "the original computation forms one merged group",
      )
      .map(drop)?;
      Ok(
        analysis
          .line_exact_groups
          .iter()
          .map(|group| group.fingerprint)
          .collect::<Vec<_>>(),
      )
    })?;
    let shifted = run("alpha computes unrelated prefix totals here\n\n")?;
    check_analysis(shifted, |analysis| {
      ensure(
        analysis
          .line_exact_groups
          .iter()
          .map(|group| group.fingerprint)
          .collect::<Vec<_>>()
          == expected_fingerprints,
        "moving one computation below unrelated source preserves the complete merged group identity",
      )
      .map(drop)
    })
  }

  /// A coherent wide region outranks fragments while an outside member prevents suppression.
  #[test]
  fn concept_level_line_group_wins_over_fragment_with_more_members() -> Result<(), PipelineTestFailure> {
    let body = test_body("same line window");
    let make_unit =
      |file: &Path, start: usize, end: usize| test_unit(CodeUnitKind::LineWindow, "line window", file, start, end, body.clone());
    let first = PathBuf::from("first.rs");
    let second = PathBuf::from("second.rs");
    let third = PathBuf::from("third.rs");
    let concept = test_group(DetectionDimension::Line, "concept", vec![
      make_unit(&first, 10, 21),
      make_unit(&second, 30, 41),
    ]);
    let fragment = test_group(DetectionDimension::Line, "fragment", vec![
      make_unit(&first, 12, 16),
      make_unit(&second, 32, 36),
      make_unit(&third, 50, 54),
    ]);

    let expected_uncovered = [concept.clone(), fragment.clone()];
    let mut uncovered_suppressed = Vec::new();
    let mut uncovered_kept = vec![fragment, concept.clone()];
    suppress_overlapping_groups(&mut uncovered_kept, &SuppressionPolicy::default(), &mut uncovered_suppressed)?;
    ensure(
      uncovered_kept == expected_uncovered && uncovered_suppressed.is_empty(),
      "the wider concept ranks first while a fragment with an outside member remains fully visible",
    )
    .map(drop)?;

    let covered_fragment = test_group(DetectionDimension::Line, "covered", vec![
      make_unit(&first, 12, 16),
      make_unit(&second, 32, 36),
    ]);
    let mut expected_suppressed = covered_fragment.clone();
    expected_suppressed.suppressed = Some(RuleId::GroupOverlapContained);
    let mut covered_suppressed = Vec::new();
    let mut covered_kept = vec![covered_fragment, concept.clone()];
    suppress_overlapping_groups(&mut covered_kept, &SuppressionPolicy::default(), &mut covered_suppressed)?;
    ensure(
      covered_kept == [concept] && covered_suppressed == [expected_suppressed],
      "one concept covering every fragment member retains that complete fragment under the overlap rule",
    )
    .map(drop)
    .map_err(PipelineTestFailure::from)
  }

  /// Real fixture loop bodies remain detectable despite distinct enclosing function names.
  #[test]
  fn fixture_loop_bodies_remain_detected_in_line_dimension() -> Result<(), PipelineTestFailure> {
    // The intentional fixture loop bodies in the exact_dupes and
    // near_dupes test crates must stay discoverable by line detection.
    let workspace = TempDir::new()?;
    let first = workspace.path().join("exact_fixture.rs");
    let second = workspace.path().join("near_fixture.rs");
    for (path, function_name) in [(&first, "process_data"), (&second, "process_positive")] {
      fs::write(
        path,
        format!(
          "\
pub fn {function_name}(input: Vec<i32>) -> i32 {{
    let mut sum = 0;
    for item in input.iter() {{
        if *item > 0 {{
            sum += *item;
        }}
    }}
    sum
}}
"
        ),
      )?;
    }

    let config = line_only_config(workspace.path(), 5);
    let result = analyze_with_generic(&TestAnalyzer, &[], &[first.clone(), second.clone()], &config)?;
    let measurements: Vec<_> = result
      .line_exact_groups
      .iter()
      .flat_map(|group| &group.members)
      .map(grouper::unit_line_count)
      .collect();
    ensure(
      measurements.iter().all(|length| length.as_ref().is_ok_and(|&lines| lines >= 5))
        && result.line_exact_groups.len() == 1
        && result
          .line_exact_groups
          .iter()
          .flat_map(|group| &group.members)
          .map(|member| &member.file)
          .collect::<Vec<_>>()
          == [&first, &second]
        && result
          .line_exact_groups
          .iter()
          .flat_map(|group| &group.members)
          .all(|member| member.line_start >= 2 && member.line_end <= 9),
      "both fixture loop bodies retain at least five lines in one visible group without absorbing their distinct function names",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::LineMeasurements {
      analysis: Box::new(result),
      measurements,
      source,
    })
  }

  /// Fallback extraction preserves both suppressed trivial branches and visible computation.
  #[test]
  fn fallback_sub_ast_branch_visibility_follows_its_structure() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let config = sub_ast_only_config(workspace.path());
    for (branch, rule) in [
      (block(vec![variable(0)]), Some(RuleId::SubNoStructure)),
      (block(vec![binary(BinOpKind::Add, variable(0), literal_int())]), None),
    ] {
      let body = if_with_then_branch(branch);
      let units = vec![
        test_unit(CodeUnitKind::Function, "first", &first, 1, 3, body.clone()),
        test_unit(CodeUnitKind::Function, "second", &second, 5, 7, body),
      ];
      let result = analyze_units(&units, Vec::new(), &config)?;
      check_analysis(result, |analysis| {
        let groups: Vec<_> = analysis
          .groups_with_suppressed()
          .filter(|group| group.dimension == DetectionDimension::SubAst)
          .collect();
        ensure(
          analysis.sub_exact_groups.is_empty() == rule.is_some()
            && matches!(groups.as_slice(), [group]
              if group.match_kind == MatchKind::Exact && group.suppressed == rule
                && group.members.iter().map(|member| (&member.file, member.suppressed)).eq([(&first, rule), (&second, rule)])),
          "fallback extraction retains the complete branch pair, suppressing only the trivial shape with its rule",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// Branch ownership survives fallback conversion, and coverage requires a duplicated chain.
  #[test]
  fn fallback_sub_ast_chain_ownership_requires_matching_enclosing_chains() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let config = sub_ast_only_config(workspace.path());
    let conditional = if_with_then_branch(block(vec![binary(BinOpKind::Add, variable(0), literal_int())]));
    for (second_count, rule) in [(2, Some(RuleId::SubCoveredByChain)), (3, None)] {
      let first_body = block(vec![conditional.clone(); 2]);
      let second_body = block(vec![conditional.clone(); second_count]);
      let expected_owners = [
        Some(Fingerprint::from_node(&first_body)),
        Some(Fingerprint::from_node(&second_body)),
      ];
      let units = paired_function_units(workspace.path(), first_body, second_body);
      let result = analyze_units(&units, Vec::new(), &config)?;
      check_analysis(result, |analysis| {
        let branches: Vec<_> = analysis
          .groups_with_suppressed()
          .filter(|group| group.dimension == DetectionDimension::SubAst)
          .filter(|group| matches!(group.members.first(), Some(unit) if unit.kind == CodeUnitKind::IfBranch))
          .collect();
        ensure(
          matches!(branches.as_slice(), [group]
            if group.match_kind == MatchKind::Exact && group.suppressed == rule
              && group.members.iter().map(|member| member.parent_chain).eq(expected_owners))
            && analysis
              .sub_exact_groups
              .iter()
              .any(|group| group.members.first().is_some_and(|member| member.kind == CodeUnitKind::IfChain))
              == rule.is_some(),
          "each branch retains its actual chain identity; only an exact duplicate enclosing chain covers the branch group",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// Inherited parent spans cannot act as precise evidence for hiding generic duplicates.
  #[test]
  fn fallback_sub_ast_parent_spans_do_not_suppress_generic_groups() -> Result<(), PipelineTestFailure> {
    let workspace = TempDir::new()?;
    let first = workspace.path().join("first.rs");
    let second = workspace.path().join("second.rs");
    let branch = block(vec![binary(BinOpKind::Add, variable(0), literal_int())]);
    let body = if_with_then_branch(branch);
    let line_body = test_body("same line window");
    let units = vec![
      test_unit(CodeUnitKind::Function, "first", &first, 1, 20, body.clone()),
      test_unit(CodeUnitKind::Function, "second", &second, 30, 49, body),
    ];
    let line_units = vec![
      test_unit(CodeUnitKind::LineWindow, "line", &first, 10, 14, line_body.clone()),
      test_unit(CodeUnitKind::LineWindow, "line", &second, 40, 44, line_body),
    ];
    let mut config = sub_ast_only_config(workspace.path());
    config.enabled_dimensions.extend([DetectionDimension::Line]);

    let result = analyze_units_with_generic(&units, &[], &[], &[], &line_units, Vec::new(), &config)?;
    check_analysis(result, |analysis| {
      ensure(
        (analysis.sub_exact_groups.len(), analysis.line_exact_groups.len()) == (1, 1)
          && !analysis
            .suppressed_groups
            .iter()
            .any(|group| group.suppressed == Some(RuleId::GroupCoveredByAst)),
        "fallback parent spans are not precise coverage evidence and cannot hide the line pair",
      )
      .map(drop)
    })
  }
}
