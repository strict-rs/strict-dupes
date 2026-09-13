//! Operation-owned progress for grouping, filtering, and statistics.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::mem;

use crate::AnalysisResult;
use crate::CoverageNoteSource;
use crate::DuplicateCoverage;
use crate::GenericGroups;
use crate::MatchedGroups;
use crate::SourceAnalysis;
use crate::code_unit::CodeUnit;
use crate::config::Config;
use crate::error::AnalysisError;
use crate::error::AnalysisFailure;
use crate::fingerprint::Fingerprint;
use crate::grouper;
use crate::grouper::DuplicateGroup;
use crate::grouper::DuplicationStats;
use crate::ignore;
use crate::ignore::IgnoreFileError;
use crate::ignore::IgnoreFileLoad;
use crate::suppression::RuleId;
use crate::suppression::SuppressionWarning;

/// The ordered analysis stage currently executing or reached before failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisPhase {
  /// Group top-level language units.
  Ast,
  /// Extract, classify, and group nested language units.
  SubAst,
  /// Group and suppress normalized token windows.
  NormalizedTokens,
  /// Group and suppress raw token windows.
  RawTokens,
  /// Merge and suppress normalized line windows.
  Lines,
  /// Load the registry and filter completed findings.
  Ignore,
  /// Measure corpus and duplicate line populations.
  Statistics,
  /// Account for suppression decisions after line statistics complete.
  SuppressionStatistics,
  /// Every calculation completed; a registry failure may still be returned.
  Complete,
}

/// Actual unit populations used by the analysis operation.
#[derive(Debug, Default)]
pub struct AnalysisUnits {
  /// Top-level units, including centrally applied suppression tags.
  pub ast:               Vec<CodeUnit>,
  /// Explicit nested units or the fallback population extracted by this operation.
  pub sub_ast:           Vec<CodeUnit>,
  /// Normalized token windows.
  pub normalized_tokens: Vec<CodeUnit>,
  /// Raw token windows.
  pub raw_tokens:        Vec<CodeUnit>,
  /// Normalized line windows.
  pub lines:             Vec<CodeUnit>,
}

/// Live analysis state, retained in full when a later calculation fails.
///
/// A population in a phase later than `phase` has not been processed. Statistics
/// are absent until line measurement succeeds. Liveness sets are populated only
/// after every grouping phase succeeds and before registry policy is applied.
#[derive(Debug)]
pub struct AnalysisProgress<ParseError> {
  /// Current stage in the declared operation order.
  pub phase: AnalysisPhase,
  /// Actual input and fallback populations used by the operation.
  pub units: AnalysisUnits,
  /// Top-level findings completed so far.
  pub ast_groups: MatchedGroups,
  /// Nested findings completed so far.
  pub sub_groups: MatchedGroups,
  /// AST and sub-AST groups awaiting the final suppression-population append.
  pub language_suppressed: Vec<DuplicateGroup>,
  /// Generic findings, including every group moved into suppression.
  pub generic_groups: GenericGroups,
  /// Completed sub-unit suppression tallies.
  pub rule_unit_counts: BTreeMap<RuleId, usize>,
  /// Cross-dimension annotations awaiting attachment to precise groups.
  pub coverage_notes: Vec<CoverageNoteSource>,
  /// Completed base statistics, including any subsequent accounting updates.
  pub stats: Option<DuplicationStats>,
  /// Registry model and native read observation, when loading succeeded.
  pub ignore_file: Option<IgnoreFileLoad>,
  /// Earlier registry failure retained if a subsequent calculation also fails.
  pub ignore_failure: Option<IgnoreFileError>,
  /// Findings hidden by registry policy.
  pub ignored_groups: Vec<DuplicateGroup>,
  /// Complete configuration warnings.
  pub warnings: Vec<SuppressionWarning>,
  /// Native source reads and extraction outcomes in operation order.
  pub sources: Vec<SourceAnalysis<ParseError>>,
  /// Group identities captured before ignore filtering.
  pub all_fingerprints: HashSet<Fingerprint>,
  /// Member identities captured before ignore filtering.
  pub all_member_fingerprint_sets: Vec<HashSet<Fingerprint>>,
}

impl<ParseError: Debug> AnalysisProgress<ParseError> {
  /// Initialize the operation before any grouping or measurement.
  #[allow(
    clippy::single_call_fn,
    reason = "The constructor establishes unreached phases without fabricating completed statistics or registry observations"
  )]
  pub(crate) fn new(units: AnalysisUnits, warnings: Vec<SuppressionWarning>) -> Self {
    Self {
      phase: AnalysisPhase::Ast,
      units,
      ast_groups: MatchedGroups::default(),
      sub_groups: MatchedGroups::default(),
      language_suppressed: Vec::new(),
      generic_groups: GenericGroups::default(),
      rule_unit_counts: BTreeMap::new(),
      coverage_notes: Vec::new(),
      stats: None,
      ignore_file: None,
      ignore_failure: None,
      ignored_groups: Vec::new(),
      warnings,
      sources: Vec::new(),
      all_fingerprints: HashSet::new(),
      all_member_fingerprint_sets: Vec::new(),
    }
  }

  /// Execute the contract and retain this same state on every failure path.
  pub(crate) fn run(mut self, config: &Config) -> Result<AnalysisResult<ParseError>, AnalysisError<ParseError>> {
    match self.calculate(config) {
      Ok(stats) => Ok(self.into_result(stats)),
      Err(source) => Err(AnalysisError {
        source:   Box::new(source),
        analysis: Box::new(self),
      }),
    }
  }

  /// Group all dimensions before collecting liveness and applying registry policy.
  #[allow(
    clippy::single_call_fn,
    reason = "This sequence owns the ignore-blind grouping barrier and retains each completed stage in the operation state"
  )]
  fn calculate(&mut self, config: &Config) -> Result<DuplicationStats, AnalysisFailure> {
    crate::tag_top_level_units(&mut self.units.ast, &config.suppression);
    crate::compute_ast_groups(&self.units.ast, config, &mut self.ast_groups)?;
    crate::partition_matched(&mut self.ast_groups, &mut self.language_suppressed);
    let precise_sub_spans = !self.units.sub_ast.is_empty();
    self.phase = AnalysisPhase::SubAst;
    crate::compute_sub_ast_groups(
      &self.units.ast, &mut self.units.sub_ast, config, &mut self.sub_groups, &mut self.language_suppressed, &mut self.rule_unit_counts,
    )?;
    let coverage = DuplicateCoverage::from_matched_groups(&self.ast_groups, precise_sub_spans.then_some(&self.sub_groups));
    crate::compute_generic_groups(
      &self.units, config, &coverage, &mut self.coverage_notes, &mut self.generic_groups, &mut self.phase,
    )?;
    self.generic_groups.suppressed.append(&mut self.language_suppressed);
    crate::apply_coverage_notes(
      &mut self.ast_groups,
      precise_sub_spans.then_some(&mut self.sub_groups),
      mem::take(&mut self.coverage_notes),
    );
    self.all_fingerprints = crate::all_unfiltered_groups(&self.ast_groups, &self.sub_groups, &self.generic_groups)
      .map(|group| group.fingerprint)
      .collect();
    self.all_member_fingerprint_sets = crate::all_unfiltered_groups(&self.ast_groups, &self.sub_groups, &self.generic_groups)
      .map(|group| group.members.iter().map(|member| member.fingerprint).collect())
      .collect();
    self.phase = AnalysisPhase::Ignore;
    match ignore::load_ignore_file(&config.root) {
      Ok(loaded) => {
        self.ast_groups = crate::filter_matched_groups(mem::take(&mut self.ast_groups), &loaded.registry, &mut self.ignored_groups);
        self.sub_groups = crate::filter_matched_groups(mem::take(&mut self.sub_groups), &loaded.registry, &mut self.ignored_groups);
        self.generic_groups = crate::filter_generic_groups(mem::take(&mut self.generic_groups), &loaded.registry, &mut self.ignored_groups);
        self.ignore_file = Some(loaded);
      }
      Err(source) => self.ignore_failure = Some(source),
    }
    self.phase = AnalysisPhase::Statistics;
    let mut stats = grouper::with_generic_stats(
      grouper::compute_stats_with_sub(
        &self.units.ast, &self.ast_groups.exact, &self.ast_groups.near, &self.sub_groups.exact, &self.sub_groups.near,
      )?,
      &self.generic_groups.token_normalized.exact,
      &self.generic_groups.token_normalized.near,
      &self.generic_groups.token_raw_exact,
      &self.generic_groups.line_exact,
    );
    stats.ignored_group_count = self.ignored_groups.len();
    self.phase = AnalysisPhase::SuppressionStatistics;
    let accounting = crate::apply_suppression_stats(
      &mut stats,
      &self.rule_unit_counts,
      &[
        &self.units.ast, &self.units.normalized_tokens, &self.units.raw_tokens, &self.units.lines,
      ],
      &self.generic_groups.suppressed,
    );
    if let Err(source) = accounting {
      self.stats = Some(stats);
      return Err(source);
    }
    self.phase = AnalysisPhase::Complete;
    if let Some(source) = self.ignore_failure.take() {
      self.stats = Some(stats);
      return Err(AnalysisFailure::Ignore(source));
    }
    Ok(stats)
  }

  /// Consume completed operation state into the established public report.
  #[allow(
    clippy::single_call_fn,
    reason = "Only a fully completed calculation may publish mandatory statistics in AnalysisResult"
  )]
  fn into_result(self, stats: DuplicationStats) -> AnalysisResult<ParseError> {
    AnalysisResult {
      stats,
      exact_groups: self.ast_groups.exact,
      near_groups: self.ast_groups.near,
      sub_exact_groups: self.sub_groups.exact,
      sub_near_groups: self.sub_groups.near,
      token_normalized_exact_groups: self.generic_groups.token_normalized.exact,
      token_normalized_near_groups: self.generic_groups.token_normalized.near,
      token_raw_exact_groups: self.generic_groups.token_raw_exact,
      line_exact_groups: self.generic_groups.line_exact,
      suppressed_groups: self.generic_groups.suppressed,
      ignored_groups: self.ignored_groups,
      ignore_file: self.ignore_file,
      warnings: self.warnings,
      sources: self.sources,
      all_fingerprints: self.all_fingerprints,
      all_member_fingerprint_sets: self.all_member_fingerprint_sets,
    }
  }
}
