//! Duplicate grouping: exact fingerprint groups, similarity-based near
//! groups (bucketed pairwise comparison plus union-find closure), stable
//! group fingerprints, and duplication statistics.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use crate::calculation;
use crate::calculation::LineRangeFailure;
use crate::calculation::RatioFailure;
use crate::calculation::ScalingFailure;
use crate::code_unit::CodeUnit;
use crate::code_unit::CodeUnitKind;
use crate::code_unit::DetectionDimension;
use crate::fingerprint::Fingerprint;
use crate::similarity;
use crate::similarity::SimilarityFailure;
use crate::similarity::SimilarityScore;
use crate::suppression::RuleId;

/// Whether a group was found by exact equality or similarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
  /// Every compared signature is exactly equal.
  Exact,
  /// Similarity score is at or above the configured threshold.
  Near,
}

impl fmt::Display for MatchKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::Exact => write!(f, "exact"),
      Self::Near => write!(f, "near"),
    }
  }
}

/// A group of duplicate code units.
#[derive(Debug, Clone, PartialEq)]
pub struct DuplicateGroup {
  /// Detection dimension that produced this group.
  pub dimension:   DetectionDimension,
  /// Exact or near-duplicate match.
  pub match_kind:  MatchKind,
  /// Stable group fingerprint derived from the dimension, the match kind,
  /// and a content fingerprint: the shared member fingerprint for exact
  /// groups, a composite of sorted member fingerprints for near groups.
  pub fingerprint: Fingerprint,
  /// The code units in this group.
  pub members:     Vec<CodeUnit>,
  /// Similarity score (1.0 for exact duplicates).
  pub similarity:  f64,
  /// Suppression rule that hid this group from the default report.
  pub suppressed:  Option<RuleId>,
  /// Redundant shadows of this group in other dimensions, aggregated per
  /// (dimension, match kind).
  pub also_seen:   Vec<CoverageNote>,
}

/// A note that a group's duplication also surfaced as redundant groups in
/// another dimension before cross-dimension dedup suppressed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageNote {
  /// Dimension the redundant shadow groups were found in.
  pub dimension:   DetectionDimension,
  /// Match kind of the shadow groups.
  pub match_kind:  MatchKind,
  /// Number of shadow groups suppressed for this (dimension, match kind).
  pub group_count: usize,
}

/// Statistics about duplication in the analyzed codebase.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DuplicationStats {
  /// Total code units analyzed (suppressed units included).
  pub total_code_units:              usize,
  /// Total source lines covered by all analyzed units.
  pub total_lines:                   usize,
  /// Visible AST exact-duplicate groups.
  pub exact_duplicate_groups:        usize,
  /// Members across all AST exact-duplicate groups.
  pub exact_duplicate_units:         usize,
  /// Visible AST near-duplicate groups.
  pub near_duplicate_groups:         usize,
  /// Members across all AST near-duplicate groups.
  pub near_duplicate_units:          usize,
  /// Source lines covered by AST exact-duplicate members.
  pub exact_duplicate_lines:         usize,
  /// Source lines covered by AST near-duplicate members.
  pub near_duplicate_lines:          usize,
  // Sub-function stats
  /// Visible sub-function exact groups.
  pub sub_exact_groups:              usize,
  /// Members across all sub-function exact groups.
  pub sub_exact_units:               usize,
  /// Visible sub-function near groups.
  pub sub_near_groups:               usize,
  /// Members across all sub-function near groups.
  pub sub_near_units:                usize,
  // Generic token / line stats
  /// Visible normalized token-window exact groups.
  pub token_normalized_exact_groups: usize,
  /// Members across all normalized token-window exact groups.
  pub token_normalized_exact_units:  usize,
  /// Visible normalized token-window near groups.
  pub token_normalized_near_groups:  usize,
  /// Members across all normalized token-window near groups.
  pub token_normalized_near_units:   usize,
  /// Visible raw token-window exact groups.
  pub token_raw_exact_groups:        usize,
  /// Members across all raw token-window exact groups.
  pub token_raw_exact_units:         usize,
  /// Visible line-window exact groups.
  pub line_exact_groups:             usize,
  /// Members across all line-window exact groups.
  pub line_exact_units:              usize,
  // Suppression and ignore accounting
  /// Units tagged by suppression rules across all dimensions.
  pub suppressed_unit_count:         usize,
  /// Groups hidden from the default report by suppression rules.
  pub suppressed_group_count:        usize,
  /// Suppressed unit/group counts attributed per rule id.
  pub suppressed_by_rule:            BTreeMap<String, usize>,
  /// Groups hidden by registered `.dupes-ignore.toml` entries.
  pub ignored_group_count:           usize,
}

/// A duplicate-group total cannot be represented by the statistics count type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot add {incoming} {dimension} {match_kind} groups to the completed total {completed}")]
pub struct GroupCountOverflow {
  /// Complete statistics whose per-dimension counts were being combined.
  pub stats:      Box<DuplicationStats>,
  /// Exact or near-duplicate total being calculated.
  pub match_kind: MatchKind,
  /// Detection dimension whose addition could not be represented.
  pub dimension:  DetectionDimension,
  /// Exact total completed before the rejected addition.
  pub completed:  usize,
  /// Native count of the detection dimension being added.
  pub incoming:   usize,
}

/// The failed step of a duplicate-line percentage calculation.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PercentageFailureCause {
  /// Conversion or division of the original integer counts failed.
  #[error(transparent)]
  Ratio(#[from] Box<RatioFailure>),
  /// Scaling the rounded ratio produced a non-finite value.
  #[error(transparent)]
  Scaling(#[from] ScalingFailure),
}

/// A failed percentage retaining its match kind, complete statistics, and native cause.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("cannot calculate {match_kind} duplicate-line percentage: {source}")]
pub struct PercentageFailure {
  /// Original integer statistics before percentage calculation.
  pub stats:      Box<DuplicationStats>,
  /// Exact or near-duplicate line population being measured.
  pub match_kind: MatchKind,
  /// Complete rejected calculation.
  pub source:     PercentageFailureCause,
}

impl DuplicationStats {
  /// Count visible groups of one match kind across every supported dimension.
  ///
  /// # Errors
  ///
  /// Returns the complete statistics and the interrupted addition when their
  /// total exceeds `usize` capacity. Counts are never wrapped or saturated.
  pub fn group_count(&self, match_kind: MatchKind) -> Result<usize, GroupCountOverflow> {
    let counts: &[(DetectionDimension, usize)] = match match_kind {
      MatchKind::Exact => &[
        (DetectionDimension::Ast, self.exact_duplicate_groups),
        (DetectionDimension::SubAst, self.sub_exact_groups),
        (DetectionDimension::TokenNormalized, self.token_normalized_exact_groups),
        (DetectionDimension::TokenRaw, self.token_raw_exact_groups),
        (DetectionDimension::Line, self.line_exact_groups),
      ],
      MatchKind::Near => &[
        (DetectionDimension::Ast, self.near_duplicate_groups),
        (DetectionDimension::SubAst, self.sub_near_groups),
        (DetectionDimension::TokenNormalized, self.token_normalized_near_groups),
      ],
    };
    let mut completed: usize = 0;
    for &(dimension, incoming) in counts {
      completed = completed.checked_add(incoming).ok_or_else(|| GroupCountOverflow {
        stats: Box::new(self.clone()),
        match_kind,
        dimension,
        completed,
        incoming,
      })?;
    }
    Ok(completed)
  }

  /// Express a covered-line count as a percentage, with zero for an empty corpus.
  fn percent_of_total(&self, match_kind: MatchKind) -> Result<f64, PercentageFailure> {
    if self.total_lines == 0 {
      return Ok(0.0);
    }
    let lines = match match_kind {
      MatchKind::Exact => self.exact_duplicate_lines,
      MatchKind::Near => self.near_duplicate_lines,
    };
    calculation::ratio(lines, self.total_lines)
      .map_err(|source| PercentageFailureCause::Ratio(Box::new(source)))
      .and_then(|ratio| calculation::scale(ratio, 100.0).map_err(PercentageFailureCause::Scaling))
      .map_err(|source| PercentageFailure {
        stats: Box::new(self.clone()),
        match_kind,
        source,
      })
  }

  /// Percentage of total lines that are exact duplicates.
  ///
  /// # Errors
  ///
  /// Returns the complete integer statistics and failed ratio or scaling operation.
  pub fn exact_duplicate_percent(&self) -> Result<f64, PercentageFailure> {
    self.percent_of_total(MatchKind::Exact)
  }

  /// Percentage of total lines that are near duplicates.
  ///
  /// # Errors
  ///
  /// Returns the complete integer statistics and failed ratio or scaling operation.
  pub fn near_duplicate_percent(&self) -> Result<f64, PercentageFailure> {
    self.percent_of_total(MatchKind::Near)
  }
}

/// Group code units by exact fingerprint match.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "The AST grouping facade supplies the default dimension for external language-analyzer consumers."
)]
pub fn group_exact_duplicates(units: &[CodeUnit]) -> Vec<DuplicateGroup> {
  group_exact_duplicates_for(units, DetectionDimension::Ast)
}

/// Group code units by exact fingerprint match for a specific dimension.
#[must_use]
pub fn group_exact_duplicates_for(units: &[CodeUnit], dimension: DetectionDimension) -> Vec<DuplicateGroup> {
  let mut groups: BTreeMap<Fingerprint, Vec<CodeUnit>> = BTreeMap::new();

  for unit in units {
    groups.entry(unit.fingerprint).or_default().push(unit.clone());
  }

  let mut result: Vec<DuplicateGroup> = groups
    .into_iter()
    .filter(|group| group.1.len() > 1)
    .map(|(fp, members)| DuplicateGroup {
      suppressed: None,
      also_seen: Vec::new(),
      dimension,
      match_kind: MatchKind::Exact,
      fingerprint: group_fingerprint(dimension, MatchKind::Exact, fp),
      members,
      similarity: 1.0,
    })
    .collect();

  // Sort by group size (largest first), then by fingerprint for stability
  result.sort_by(compare_group_size_desc_then_fingerprint);

  result
}

/// Order groups by member count (largest first), then fingerprint for stability.
pub(crate) fn compare_group_size_desc_then_fingerprint(first: &DuplicateGroup, second: &DuplicateGroup) -> Ordering {
  second
    .members
    .len()
    .cmp(&first.members.len())
    .then_with(|| first.fingerprint.cmp(&second.fingerprint))
}

/// Order similarity scores descending, treating incomparable values as equal.
pub(crate) fn compare_similarity_desc(first: f64, second: f64) -> Ordering {
  second.partial_cmp(&first).unwrap_or(Ordering::Equal)
}

/// Find near-duplicate groups above the similarity threshold.
/// Pre-filters by `CodeUnitKind` and approximate size to reduce pairwise comparisons.
///
/// # Errors
///
/// Retains the candidate population, completed pair measurements, and native
/// calculation or unordered-comparison failure.
pub fn find_near_duplicates(
  units: &[CodeUnit],
  threshold: f64,
  exact_fingerprints: &[Fingerprint],
) -> Result<Vec<DuplicateGroup>, NearGroupingFailure> {
  find_near_duplicates_for(units, threshold, exact_fingerprints, DetectionDimension::Ast)
}

/// A completed pair measurement and its native ordering against the requested threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredPair {
  /// First member's index in the candidate population.
  pub first:    usize,
  /// Second member's index in the candidate population.
  pub second:   usize,
  /// Complete Dice calculation, including original integer counts.
  pub score:    SimilarityScore,
  /// Native comparison against the grouping threshold.
  pub ordering: Ordering,
}

/// The pair operation that interrupted near-duplicate grouping.
#[derive(Debug, thiserror::Error)]
pub enum PairFailure {
  /// The pair's Dice calculation failed.
  #[error("similarity calculation failed for candidates {first} and {second}: {source}")]
  Similarity {
    /// First candidate index.
    first:  usize,
    /// Second candidate index.
    second: usize,
    /// Complete failed calculation and original integer counts.
    source: SimilarityFailure,
  },
  /// The completed score and threshold had no native ordering.
  #[error("threshold comparison is unordered for candidates {first} and {second}: {score:?}")]
  Unordered {
    /// First candidate index.
    first:  usize,
    /// Second candidate index.
    second: usize,
    /// Completed score and integer counts before the unordered comparison.
    score:  SimilarityScore,
  },
}

/// An interrupted grouping request with its full candidate and calculation evidence.
#[derive(Debug, thiserror::Error)]
#[error("near grouping failed in {dimension} at threshold {threshold}: {source}")]
pub struct NearGroupingFailure {
  /// Requested detection dimension.
  pub dimension:          DetectionDimension,
  /// Original configured binary64 threshold.
  pub threshold:          f64,
  /// Exact-member identities excluded before near comparison.
  pub exact_fingerprints: Vec<Fingerprint>,
  /// Full candidate population addressed by pair indices.
  pub candidates:         Vec<CodeUnit>,
  /// Every ordered pair measurement completed before the failed operation.
  pub completed:          Vec<ScoredPair>,
  /// Complete failed pair operation.
  pub source:             Box<PairFailure>,
}

/// Same-kind, same-size candidates retaining their population indices.
type CandidateBucket<'units> = Vec<(usize, &'units CodeUnit)>;

/// Find near-duplicate groups above the similarity threshold for a dimension.
///
/// # Errors
///
/// Retains the original request, all candidates and completed measurements, and
/// the exact failed calculation or unordered comparison.
pub fn find_near_duplicates_for(
  units: &[CodeUnit],
  threshold: f64,
  exact_fingerprints: &[Fingerprint],
  dimension: DetectionDimension,
) -> Result<Vec<DuplicateGroup>, NearGroupingFailure> {
  let exact_set: BTreeSet<Fingerprint> = exact_fingerprints.iter().copied().collect();
  let candidates: Vec<&CodeUnit> = units.iter().filter(|unit| !exact_set.contains(&unit.fingerprint)).collect();
  let mut buckets: BTreeMap<(CodeUnitKind, u32), CandidateBucket<'_>> = BTreeMap::new();
  for (index, &unit) in candidates.iter().enumerate() {
    // Integer logarithms preserve the power-of-two bucket boundary without a float conversion.
    let size_bucket = unit.node_count.checked_ilog2().unwrap_or(0);
    buckets.entry((unit.kind, size_bucket)).or_default().push((index, unit));
  }

  let mut pairs = Vec::new();
  for bucket in buckets.values() {
    if let Err(source) = compare_bucket(bucket, threshold, &mut pairs) {
      return Err(NearGroupingFailure {
        dimension,
        threshold,
        exact_fingerprints: exact_fingerprints.to_vec(),
        candidates: candidates.into_iter().cloned().collect(),
        completed: pairs,
        source: Box::new(source),
      });
    }
  }
  let mut parents = BTreeMap::new();
  for pair in pairs.iter().filter(|pair| pair.ordering != Ordering::Less) {
    union(&mut parents, pair.first, pair.second);
  }

  let mut group_map: BTreeMap<usize, (f64, Vec<CodeUnit>)> = BTreeMap::new();
  for pair in pairs.into_iter().filter(|pair| pair.ordering != Ordering::Less) {
    let root = find(&mut parents, pair.first);
    let &mut (ref mut minimum, _) = group_map.entry(root).or_insert_with(|| (pair.score.value, Vec::new()));
    *minimum = minimum.min(pair.score.value);
  }
  for (index, unit) in candidates.into_iter().enumerate() {
    let root = find(&mut parents, index);
    if let Some(&mut (_, ref mut members)) = group_map.get_mut(&root) {
      members.push(unit.clone());
    }
  }

  let mut result: Vec<DuplicateGroup> = group_map
    .into_values()
    .map(|(similarity, members)| {
      let member_fps: Vec<Fingerprint> = members.iter().map(|member| member.fingerprint).collect();
      let composite_fp = Fingerprint::from_fingerprints(&member_fps);

      DuplicateGroup {
        suppressed: None,
        also_seen: Vec::new(),
        dimension,
        match_kind: MatchKind::Near,
        fingerprint: group_fingerprint(dimension, MatchKind::Near, composite_fp),
        members,
        similarity,
      }
    })
    .collect();

  result.sort_by(|first, second| {
    second
      .members
      .len()
      .cmp(&first.members.len())
      .then(compare_similarity_desc(first.similarity, second.similarity))
      .then_with(|| first.fingerprint.cmp(&second.fingerprint))
  });

  Ok(result)
}

/// Compare each distinct pair in a same-kind, same-size bucket exactly once.
#[allow(
  clippy::single_call_fn,
  reason = "Bucket comparison owns pair eligibility while transitive grouping consumes the resulting scored edges."
)]
fn compare_bucket(bucket: &[(usize, &CodeUnit)], threshold: f64, completed: &mut Vec<ScoredPair>) -> Result<(), PairFailure> {
  let mut remaining = bucket;
  while let Some((&(first, first_unit), tail)) = remaining.split_first() {
    for &(second, second_unit) in tail {
      let score = similarity::similarity_score(&first_unit.body, &second_unit.body).map_err(|source| PairFailure::Similarity {
        first,
        second,
        source,
      })?;
      let ordering = score.value.partial_cmp(&threshold).ok_or(PairFailure::Unordered {
        first,
        second,
        score,
      })?;
      completed.push(ScoredPair {
        first,
        second,
        score,
        ordering,
      });
    }
    remaining = tail;
  }
  Ok(())
}

/// Build a stable group fingerprint tied to dimension, match kind, and content.
fn group_fingerprint(dimension: DetectionDimension, match_kind: MatchKind, content_fingerprint: Fingerprint) -> Fingerprint {
  Fingerprint::from_bytes(format!("{dimension}:{match_kind}:{content_fingerprint}").as_bytes())
}

/// Build the stable group fingerprint for an exact group in a dimension.
///
/// Used when the analysis pipeline rebuilds a group from merged window
/// content so the result is identical to a directly grouped window.
#[allow(
  clippy::single_call_fn,
  reason = "Merged windows must reuse the exact-group identity rule instead of reconstructing its hash domain in the pipeline."
)]
pub(crate) fn exact_group_fingerprint(dimension: DetectionDimension, content_fingerprint: Fingerprint) -> Fingerprint {
  group_fingerprint(dimension, MatchKind::Exact, content_fingerprint)
}

/// Return the member fingerprints of every group, in group order.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "External analyzer integrations consume the owned member fingerprint list when excluding exact matches from near grouping."
)]
pub fn member_fingerprints(groups: &[DuplicateGroup]) -> Vec<Fingerprint> {
  member_fingerprints_iter(groups.iter()).collect()
}

/// Project the member fingerprints of `groups`, in group order.
pub(crate) fn member_fingerprints_iter<'a>(
  groups: impl Iterator<Item = &'a DuplicateGroup> + 'a,
) -> impl Iterator<Item = Fingerprint> + 'a {
  groups.flat_map(|group| group.members.iter().map(|member| member.fingerprint))
}

/// Source-line population being measured for the statistics document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinePopulation {
  /// All analyzed top-level units.
  Corpus,
  /// Members of exact duplicate groups.
  Exact,
  /// Members of near-duplicate groups.
  Near,
}

/// A completed integer line total from an interrupted statistics calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineMeasurement {
  /// Population whose measurement completed.
  pub population: LinePopulation,
  /// Complete integer count for that population.
  pub lines:      usize,
}

/// The native operation that interrupted a source-line sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LineSumFailureCause {
  /// The current unit's source interval could not be measured.
  #[error(transparent)]
  Range(#[from] LineRangeFailure),
  /// Adding a measured unit exceeded the counting representation.
  #[error("adding {incoming} source lines exceeds usize capacity")]
  Overflow {
    /// Complete line count of the current unit.
    incoming: usize,
  },
}

/// A source-line sum failure with the complete failed unit and accumulated count.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("source-line sum failed after {completed} lines for {}: {source}", unit.name)]
pub struct LineSumFailure {
  /// Full source unit whose measurement or addition failed.
  pub unit:      Box<CodeUnit>,
  /// Exact total before the current unit.
  pub completed: usize,
  /// Complete interval or accumulation failure.
  pub source:    LineSumFailureCause,
}

/// A statistics failure retaining every completed line-population measurement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("statistics failed while measuring {population:?}: {source}")]
pub struct StatisticsFailure {
  /// Line totals that completed before the failing population.
  pub completed:  Vec<LineMeasurement>,
  /// Population whose measurement was interrupted.
  pub population: LinePopulation,
  /// Full current unit, accumulated count, and failed native operation.
  pub source:     LineSumFailure,
}

/// Compute the inclusive source-line count while retaining rejected coordinates.
pub(crate) fn unit_line_count(unit: &CodeUnit) -> Result<usize, LineRangeFailure> {
  calculation::inclusive_line_count(unit.line_start, unit.line_end)
}

/// Accumulate one line population and record its complete total before the next population.
fn measure_lines<'units>(
  mut units: impl Iterator<Item = &'units CodeUnit>,
  population: LinePopulation,
  measurements: &mut Vec<LineMeasurement>,
) -> Result<usize, StatisticsFailure> {
  let outcome = units.try_fold(0_usize, |completed, unit| {
    let measured = unit_line_count(unit).map_err(LineSumFailureCause::Range).and_then(|incoming| {
      completed.checked_add(incoming).ok_or(LineSumFailureCause::Overflow {
        incoming,
      })
    });
    measured.map_err(|source| LineSumFailure {
      unit: Box::new(unit.clone()),
      completed,
      source,
    })
  });
  let lines = outcome.map_err(|source| StatisticsFailure {
    completed: measurements.clone(),
    population,
    source,
  })?;
  measurements.push(LineMeasurement {
    population,
    lines,
  });
  Ok(lines)
}

/// Compute duplication statistics.
///
/// # Errors
///
/// Retains the failed source unit, original coordinates and counts, and every
/// earlier completed population measurement.
#[allow(
  clippy::single_call_fn,
  reason = "The AST-only statistics facade remains the supported composition boundary for language-analyzer integrations."
)]
pub fn compute_stats(
  units: &[CodeUnit],
  exact_groups: &[DuplicateGroup],
  near_groups: &[DuplicateGroup],
) -> Result<DuplicationStats, StatisticsFailure> {
  let mut measurements = Vec::new();
  let total_lines = measure_lines(units.iter(), LinePopulation::Corpus, &mut measurements)?;
  let exact_duplicate_lines = measure_lines(
    exact_groups.iter().flat_map(|group| &group.members),
    LinePopulation::Exact,
    &mut measurements,
  )?;
  let near_duplicate_lines = measure_lines(
    near_groups.iter().flat_map(|group| &group.members),
    LinePopulation::Near,
    &mut measurements,
  )?;

  Ok(DuplicationStats {
    suppressed_unit_count: 0,
    suppressed_group_count: 0,
    suppressed_by_rule: BTreeMap::new(),
    ignored_group_count: 0,
    total_code_units: units.len(),
    total_lines,
    exact_duplicate_groups: exact_groups.len(),
    exact_duplicate_units: exact_groups.iter().flat_map(|group| &group.members).count(),
    near_duplicate_groups: near_groups.len(),
    near_duplicate_units: near_groups.iter().flat_map(|group| &group.members).count(),
    exact_duplicate_lines,
    near_duplicate_lines,
    sub_exact_groups: 0,
    sub_exact_units: 0,
    sub_near_groups: 0,
    sub_near_units: 0,
    token_normalized_exact_groups: 0,
    token_normalized_exact_units: 0,
    token_normalized_near_groups: 0,
    token_normalized_near_units: 0,
    token_raw_exact_groups: 0,
    token_raw_exact_units: 0,
    line_exact_groups: 0,
    line_exact_units: 0,
  })
}

/// Compute duplication statistics including sub-function results.
///
/// # Errors
///
/// Retains every completed line measurement and the native failure from the
/// AST statistics calculation.
#[allow(
  clippy::single_call_fn,
  reason = "Sub-function statistics extend the shared AST statistics contract at the grouping owner."
)]
pub fn compute_stats_with_sub(
  units: &[CodeUnit],
  exact_groups: &[DuplicateGroup],
  near_groups: &[DuplicateGroup],
  sub_exact_groups: &[DuplicateGroup],
  sub_near_groups: &[DuplicateGroup],
) -> Result<DuplicationStats, StatisticsFailure> {
  let mut stats = compute_stats(units, exact_groups, near_groups)?;
  stats.sub_exact_groups = sub_exact_groups.len();
  stats.sub_exact_units = sub_exact_groups.iter().flat_map(|group| &group.members).count();
  stats.sub_near_groups = sub_near_groups.len();
  stats.sub_near_units = sub_near_groups.iter().flat_map(|group| &group.members).count();
  Ok(stats)
}

/// Add generic token and line group counts to existing stats.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Token and line counts are composed with AST statistics through one dimension-aware owner."
)]
pub fn with_generic_stats(
  mut stats: DuplicationStats,
  token_normalized_exact_groups: &[DuplicateGroup],
  token_normalized_near_groups: &[DuplicateGroup],
  token_raw_exact_groups: &[DuplicateGroup],
  line_exact_groups: &[DuplicateGroup],
) -> DuplicationStats {
  stats.token_normalized_exact_groups = token_normalized_exact_groups.len();
  stats.token_normalized_exact_units = token_normalized_exact_groups.iter().flat_map(|group| &group.members).count();
  stats.token_normalized_near_groups = token_normalized_near_groups.len();
  stats.token_normalized_near_units = token_normalized_near_groups.iter().flat_map(|group| &group.members).count();
  stats.token_raw_exact_groups = token_raw_exact_groups.len();
  stats.token_raw_exact_units = token_raw_exact_groups.iter().flat_map(|group| &group.members).count();
  stats.line_exact_groups = line_exact_groups.len();
  stats.line_exact_units = line_exact_groups.iter().flat_map(|group| &group.members).count();
  stats
}

/// Resolve and compress a candidate's parent chain; roots have no parent entry.
fn find(parents: &mut BTreeMap<usize, usize>, index: usize) -> usize {
  let mut root = index;
  while let Some(&parent) = parents.get(&root) {
    root = parent;
  }
  let mut cursor = index;
  while let Some(parent) = parents.get_mut(&cursor) {
    let next = *parent;
    *parent = root;
    cursor = next;
  }
  root
}

/// Join distinct roots, preserving the acyclic parent relation.
#[allow(
  clippy::single_call_fn,
  reason = "Only union may create parent edges, so root resolution and the no-cycle guard remain one invariant."
)]
fn union(parents: &mut BTreeMap<usize, usize>, first: usize, second: usize) {
  let first_root = find(parents, first);
  let second_root = find(parents, second);
  if first_root != second_root {
    *parents.entry(first_root).or_insert(second_root) = second_root;
  }
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use strict_test_support::TestFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::DuplicateGroup;
  use super::DuplicationStats;
  use super::GroupCountOverflow;
  use super::LineMeasurement;
  use super::LinePopulation;
  use super::LineSumFailure;
  use super::LineSumFailureCause;
  use super::MatchKind;
  use super::NearGroupingFailure;
  use super::PairFailure;
  use super::PercentageFailure;
  use super::StatisticsFailure;
  use super::compute_stats;
  use super::find_near_duplicates_for;
  use super::group_exact_duplicates;
  use super::group_exact_duplicates_for;
  use crate::code_unit::CodeUnit;
  use crate::code_unit::CodeUnitKind;
  use crate::code_unit::DetectionDimension;
  use crate::fingerprint::Fingerprint;
  use crate::node::NodeKind;
  use crate::node::NormalizedNode;
  use crate::node::count_nodes;
  use crate::similarity::SimilarityCounts;
  use crate::similarity::SimilarityScore;

  /// A complete near-group calculation, including any retained partial work.
  type NearGroupingOutcome = Result<Vec<DuplicateGroup>, NearGroupingFailure>;

  /// Preserve native grouping and measurement failures at the test boundary.
  #[derive(Debug, thiserror::Error)]
  enum GrouperTestFailure {
    /// A threshold boundary produced an unexpected complete pair of outcomes.
    #[error("threshold boundary expectation failed: {source}; outcomes: {outcomes:?}")]
    Threshold {
      /// Results at the requested threshold and its immediate successor.
      outcomes: Box<[NearGroupingOutcome; 2]>,
      /// Failed behavioral expectation.
      source:   TestFailure,
    },
    /// An unordered comparison did not retain the original request and score.
    #[error("unordered threshold expectation failed: {source}; outcome: {outcome:?}")]
    Unordered {
      /// Complete grouping result or failure.
      outcome: Box<Result<Vec<DuplicateGroup>, NearGroupingFailure>>,
      /// Failed behavioral expectation.
      source:  TestFailure,
    },
    /// Relocating source units changed more than the group members' locations.
    #[error("{match_kind} relocation expectation failed: {source}; inputs: {inputs:?}; outcomes: {outcomes:?}")]
    Relocation {
      /// Grouping contract exercised by both corpora.
      match_kind: MatchKind,
      /// Complete original and relocated source units.
      inputs:     Box<[Vec<CodeUnit>; 2]>,
      /// Complete original and relocated grouping outcomes.
      outcomes:   Box<[NearGroupingOutcome; 2]>,
      /// Native assertion failure.
      source:     TestFailure,
    },
    /// A line-total failure did not retain its exact reached state.
    #[error("line statistics expectation failed: {source}; outcome: {outcome:?}; expected: {expected:?}")]
    LineStatistics {
      /// Complete result or failure from statistics.
      outcome:  Box<Result<DuplicationStats, StatisticsFailure>>,
      /// Complete expected result or failure.
      expected: Box<Result<DuplicationStats, StatisticsFailure>>,
      /// Failed behavioral expectation.
      source:   TestFailure,
    },
    /// Near-group calculation failed with its candidate and pair evidence.
    #[error(transparent)]
    Grouping(#[from] NearGroupingFailure),
    /// Percentage calculation did not preserve the expected result for both line populations.
    #[error("percentage expectation failed: {source}; stats: {stats:?}; outcomes: {outcomes:?}; expected: {expected:?}")]
    Percentages {
      /// Complete original integer statistics supplied to both calculations.
      stats:    Box<DuplicationStats>,
      /// Complete exact and near outcomes, including either calculation failure.
      outcomes: Box<[Result<f64, PercentageFailure>; 2]>,
      /// Independently specified exact and near percentages.
      expected: [f64; 2],
      /// Native behavioral assertion failure.
      source:   TestFailure,
    },
    /// Statistics calculation retained its completed population measurements.
    #[error(transparent)]
    Statistics(#[from] StatisticsFailure),
    /// A successfully completed operation violated the test's behavioral expectation.
    #[error(transparent)]
    Assertion(#[from] TestFailure),
  }

  /// Complete inputs and outcomes of a failed group-total expectation.
  #[derive(Debug, thiserror::Error)]
  #[error("group-count expectation failed for {match_kind}: {source}; observed: {outcome:?}; expected: {expected:?}")]
  struct CountTestFailure {
    /// Original statistics submitted to the counting operation.
    stats:      DuplicationStats,
    /// Requested exact or near total.
    match_kind: MatchKind,
    /// Complete observed total or typed overflow.
    outcome:    Result<usize, GroupCountOverflow>,
    /// Complete expected total or typed overflow.
    expected:   Result<usize, GroupCountOverflow>,
    /// Failed behavioral expectation.
    source:     TestFailure,
  }

  /// Compare a complete group-count result and retain its inputs on mismatch.
  fn check_group_count(
    stats: DuplicationStats,
    match_kind: MatchKind,
    expected: Result<usize, GroupCountOverflow>,
  ) -> Result<(), Box<CountTestFailure>> {
    let outcome = stats.group_count(match_kind);
    ensure(
      outcome == expected,
      "group totals preserve exact counts or the complete interrupted addition",
    )
    .map_err(|source| {
      Box::new(CountTestFailure {
        stats,
        match_kind,
        outcome,
        expected,
        source,
      })
    })
  }

  /// Every supported dimension contributes to the total for its own match kind.
  #[test]
  fn group_totals_include_all_supported_dimensions() -> Result<(), Box<CountTestFailure>> {
    let stats = DuplicationStats {
      exact_duplicate_groups: 1,
      sub_exact_groups: 2,
      token_normalized_exact_groups: 3,
      token_raw_exact_groups: 4,
      line_exact_groups: 5,
      near_duplicate_groups: 7,
      sub_near_groups: 11,
      token_normalized_near_groups: 13,
      ..DuplicationStats::default()
    };
    check_group_count(stats.clone(), MatchKind::Exact, Ok(15))?;
    check_group_count(stats, MatchKind::Near, Ok(31))
  }

  /// Zero and the largest representable total remain valid counts.
  #[test]
  fn group_totals_preserve_representable_boundaries() -> Result<(), Box<CountTestFailure>> {
    for match_kind in [MatchKind::Exact, MatchKind::Near] {
      check_group_count(DuplicationStats::default(), match_kind, Ok(0))?;
      let stats = match match_kind {
        MatchKind::Exact => DuplicationStats {
          exact_duplicate_groups: usize::MAX,
          ..DuplicationStats::default()
        },
        MatchKind::Near => DuplicationStats {
          near_duplicate_groups: usize::MAX,
          ..DuplicationStats::default()
        },
      };
      check_group_count(stats, match_kind, Ok(usize::MAX))?;
    }
    Ok(())
  }

  /// An unrepresentable total retains all statistics, the failed dimension, and both operands.
  #[test]
  fn group_total_overflow_retains_complete_statistics() -> Result<(), Box<CountTestFailure>> {
    for match_kind in [MatchKind::Exact, MatchKind::Near] {
      let stats = match match_kind {
        MatchKind::Exact => DuplicationStats {
          exact_duplicate_groups: usize::MAX,
          sub_exact_groups: 1,
          ..DuplicationStats::default()
        },
        MatchKind::Near => DuplicationStats {
          near_duplicate_groups: usize::MAX,
          sub_near_groups: 1,
          ..DuplicationStats::default()
        },
      };
      let expected = Err(GroupCountOverflow {
        stats: Box::new(stats.clone()),
        match_kind,
        dimension: DetectionDimension::SubAst,
        completed: usize::MAX,
        incoming: 1,
      });
      check_group_count(stats, match_kind, expected)?;
    }
    Ok(())
  }

  /// Build a complete source unit with content-derived identity and a three-line span.
  fn test_unit(name: &str, file: &str, line_start: usize, body: NormalizedNode) -> CodeUnit {
    let fingerprint = Fingerprint::from_node(&body);
    CodeUnit {
      suppressed: None,
      parent_chain: None,
      kind: CodeUnitKind::Function,
      name: name.to_owned(),
      file: PathBuf::from(file),
      line_start,
      line_end: line_start.saturating_add(2),
      signature: NormalizedNode::leaf(NodeKind::Opaque),
      node_count: count_nodes(&body),
      body,
      fingerprint,
      parent_name: None,
      is_test: false,
    }
  }

  /// Construct a block whose token payload distinguishes its exact identity.
  fn token_body(token: &str) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::leaf(NodeKind::Token(token.to_owned()))])
  }

  /// Build a similarity chain with two qualifying edges and nonmatching endpoints.
  fn similarity_chain() -> Vec<CodeUnit> {
    [("first", "a", "fixed"), ("bridge", "b", "fixed"), ("last", "b", "other")]
      .into_iter()
      .map(|(name, first_token, second_token)| {
        let body = NormalizedNode::with_children(NodeKind::Block, vec![
          NormalizedNode::leaf(NodeKind::Token(first_token.to_owned())),
          NormalizedNode::leaf(NodeKind::Token(second_token.to_owned())),
        ]);
        test_unit(name, "src/chain.rs", 1, body)
      })
      .collect()
  }

  /// Construct five-node bodies with four matching nodes and distinct identities.
  fn threshold_pair() -> Vec<CodeUnit> {
    ["left", "right"]
      .into_iter()
      .map(|last| {
        let body = NormalizedNode::with_children(
          NodeKind::Block,
          ["first", "second", "third", last]
            .into_iter()
            .map(|token| NormalizedNode::leaf(NodeKind::Token(token.to_owned())))
            .collect(),
        );
        test_unit(last, "threshold.rs", 1, body)
      })
      .collect()
  }

  /// The rounded value of four fifths qualifies at 0.8 and fails at the next binary64 value.
  #[test]
  fn near_group_threshold_preserves_rounded_four_fifths() -> Result<(), GrouperTestFailure> {
    let units = threshold_pair();
    let outcomes = [
      find_near_duplicates_for(&units, 0.8, &[], DetectionDimension::Ast),
      find_near_duplicates_for(&units, 0.8_f64.next_up(), &[], DetectionDimension::Ast),
    ];
    ensure(
      matches!(&outcomes, [Ok(accepted), Ok(rejected)]
      if matches!(accepted.as_slice(), [group] if group.members == units && group.similarity.to_bits() == 0.8_f64.to_bits())
        && rejected.is_empty()),
      "rounded four-fifths score passes the stored 0.8 threshold and fails its immediate successor",
    )
    .map_err(|source| GrouperTestFailure::Threshold {
      outcomes: Box::new(outcomes),
      source,
    })
  }

  /// NaN comparisons retain the original threshold, candidate identities, and completed score.
  #[test]
  fn unordered_threshold_retains_original_integer_measurement() -> Result<(), GrouperTestFailure> {
    let units = threshold_pair();
    let excluded = Fingerprint::from_bytes(b"unrelated exact identity");
    let threshold = f64::from_bits(0x7ff8_0000_0000_0042);
    let outcome = find_near_duplicates_for(&units, threshold, &[excluded], DetectionDimension::TokenNormalized);
    let expected_score = SimilarityScore {
      counts: SimilarityCounts {
        first:    5,
        second:   5,
        matching: 4,
      },
      value:  0.8,
    };
    ensure(
      matches!(&outcome, Err(failure)
      if failure.threshold.to_bits() == threshold.to_bits()
        && failure.dimension == DetectionDimension::TokenNormalized
        && failure.candidates == units && failure.exact_fingerprints == [excluded]
        && failure.completed.is_empty()
        && matches!(*failure.source, PairFailure::Unordered { first: 0, second: 1, score } if score == expected_score)),
      "unordered comparison preserves the complete request and original integer score evidence",
    )
    .map_err(|source| GrouperTestFailure::Unordered {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// A later population overflow retains earlier totals and the failing source unit.
  #[test]
  fn statistics_overflow_retains_completed_populations() -> Result<(), GrouperTestFailure> {
    let corpus = test_unit("corpus", "corpus.rs", 1, token_body("corpus"));
    let mut largest = test_unit("largest", "large.rs", 1, token_body("large"));
    largest.line_end = usize::MAX;
    let mut final_unit = test_unit("final", "final.rs", 1, token_body("final"));
    final_unit.line_end = 1;
    let near = DuplicateGroup {
      dimension:   DetectionDimension::Ast,
      match_kind:  MatchKind::Near,
      fingerprint: Fingerprint::from_bytes(b"independently supplied near group"),
      members:     vec![largest, final_unit.clone()],
      similarity:  0.9,
      suppressed:  None,
      also_seen:   Vec::new(),
    };
    let outcome = compute_stats(&[corpus], &[], &[near]);
    let expected = Err(StatisticsFailure {
      completed:  vec![
        LineMeasurement {
          population: LinePopulation::Corpus,
          lines:      3,
        },
        LineMeasurement {
          population: LinePopulation::Exact,
          lines:      0,
        },
      ],
      population: LinePopulation::Near,
      source:     LineSumFailure {
        unit:      Box::new(final_unit),
        completed: usize::MAX,
        source:    LineSumFailureCause::Overflow {
          incoming: 1
        },
      },
    });
    ensure(
      outcome == expected,
      "near-line overflow retains earlier corpus and exact totals, original unit, and rejected integer addition",
    )
    .map_err(|source| GrouperTestFailure::LineStatistics {
      outcome: Box::new(outcome),
      expected: Box::new(expected),
      source,
    })
  }

  /// A corpus without source units produces no exact groups.
  #[test]
  fn empty_input_no_groups() -> Result<(), TestFailure> {
    let groups = group_exact_duplicates(&[]);
    ensure(groups.is_empty(), "an empty corpus has no exact groups")
  }

  /// Moving exact or near duplicates changes member locations while preserving the complete group
  /// contract.
  #[test]
  fn group_identity_and_measurement_survive_relocation() -> Result<(), GrouperTestFailure> {
    let cases: [(MatchKind, &[&str]); 2] = [
      (MatchKind::Exact, &["same", "same"]),
      (MatchKind::Near, &["left", "right", "middle"]),
    ];
    for (match_kind, tokens) in cases {
      let mut inputs = [Vec::new(), Vec::new()];
      for ((name, file, line_start, moved_file, moved_start), token) in [
        ("a", "src/a.rs", 1, "renamed/a.rs", 100),
        ("b", "src/b.rs", 10, "renamed/b.rs", 200),
        ("c", "src/c.rs", 20, "renamed/c.rs", 300),
      ]
      .into_iter()
      .zip(tokens)
      {
        let [ref mut original, ref mut relocated] = inputs;
        original.push(test_unit(name, file, line_start, token_body(token)));
        relocated.push(test_unit(name, moved_file, moved_start, token_body(token)));
      }
      let outcomes = inputs.each_ref().map(|units| match match_kind {
        MatchKind::Exact => Ok(group_exact_duplicates_for(units, DetectionDimension::Ast)),
        MatchKind::Near => find_near_duplicates_for(units, 0.0, &[], DetectionDimension::Ast),
      });
      let [ref original, ref relocated] = inputs;
      ensure(
        matches!(&outcomes, [Ok(first), Ok(second)]
          if matches!(first.as_slice(), [group] if &group.members == original && group.match_kind == match_kind)
            && *second == first.iter().map(|group| DuplicateGroup {
              members: relocated.clone(),
              ..group.clone()
            }).collect::<Vec<_>>()),
        "relocation preserves the complete group identity, measurement, and metadata while retaining the moved members",
      )
      .map_err(|source| GrouperTestFailure::Relocation {
        match_kind,
        inputs: Box::new(inputs),
        outcomes: Box::new(outcomes),
        source,
      })?;
    }
    Ok(())
  }

  /// Qualifying similarity edges connect endpoints through an intermediate member.
  #[test]
  fn near_groups_close_transitive_matches() -> Result<(), GrouperTestFailure> {
    let units = similarity_chain();
    let groups = find_near_duplicates_for(&units, 0.6, &[], DetectionDimension::Ast)?;
    ensure_eq(&groups.len(), &1, "two qualifying edges produce one connected near group")?;
    ensure(
      groups
        .iter()
        .flat_map(|group| &group.members)
        .map(|member| member.name.as_str())
        .collect::<Vec<_>>()
        == vec!["first", "bridge", "last"],
      "transitive closure retains both endpoints and the connecting unit in source order",
    )?;
    ensure(
      groups.iter().all(|group| group.similarity > 0.66 && group.similarity < 0.67),
      "group similarity is the minimum qualifying edge score, excluding the nonmatching endpoint pair",
    )
    .map_err(GrouperTestFailure::from)
  }

  /// Edges below the configured threshold cannot connect a near group.
  #[test]
  fn near_groups_reject_edges_below_threshold() -> Result<(), GrouperTestFailure> {
    let units = similarity_chain();
    let groups = find_near_duplicates_for(&units, 0.7, &[], DetectionDimension::Ast)?;
    ensure(groups.is_empty(), "nonqualifying similarity edges do not connect candidates").map_err(GrouperTestFailure::from)
  }

  /// Excluded exact members cannot connect otherwise unrelated near candidates.
  #[test]
  fn exact_members_cannot_bridge_near_groups() -> Result<(), GrouperTestFailure> {
    let units = similarity_chain();
    let exact_fingerprints = units
      .iter()
      .filter(|unit| unit.name == "bridge")
      .map(|unit| unit.fingerprint)
      .collect::<Vec<_>>();
    let groups = find_near_duplicates_for(&units, 0.6, &exact_fingerprints, DetectionDimension::Ast)?;
    ensure(
      groups.is_empty(),
      "excluding an exact member also removes its connecting near-match edges",
    )
    .map_err(GrouperTestFailure::from)
  }

  /// Each line population uses its own count, and an empty corpus always reports zero.
  #[test]
  fn percentages_preserve_population_counts_and_empty_corpus_behavior() -> Result<(), GrouperTestFailure> {
    for (stats, expected) in [
      (
        DuplicationStats {
          total_code_units: 10,
          total_lines: 200,
          exact_duplicate_groups: 2,
          exact_duplicate_units: 4,
          near_duplicate_groups: 1,
          near_duplicate_units: 3,
          exact_duplicate_lines: 50,
          near_duplicate_lines: 30,
          ..DuplicationStats::default()
        },
        [25.0, 15.0],
      ),
      (DuplicationStats::default(), [0.0, 0.0]),
      (
        DuplicationStats {
          exact_duplicate_lines: 50,
          near_duplicate_lines: 30,
          ..DuplicationStats::default()
        },
        [0.0, 0.0],
      ),
    ] {
      let outcomes = [stats.exact_duplicate_percent(), stats.near_duplicate_percent()];
      ensure(
        matches!(&outcomes, [Ok(exact), Ok(near)]
          if [exact.to_bits(), near.to_bits()] == expected.map(f64::to_bits)),
        "exact and near percentages use their own line counts and preserve the explicit empty-corpus result",
      )
      .map_err(|source| GrouperTestFailure::Percentages {
        stats: Box::new(stats),
        outcomes: Box::new(outcomes),
        expected,
        source,
      })?;
    }
    Ok(())
  }
}
