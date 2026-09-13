//! Typed error model of the analysis pipeline.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Debug;

use thiserror::Error as ThisError;

use crate::LineRange;
use crate::analysis::AnalysisProgress;
use crate::calculation::LineRangeFailure;
use crate::calculation::RatioFailure;
use crate::code_unit::CodeUnit;
use crate::grouper::NearGroupingFailure;
use crate::grouper::StatisticsFailure;
use crate::ignore::IgnoreFileError;
use crate::suppression::RuleId;

/// Analysis failed with its actual operation state and original calculation evidence.
#[derive(Debug, ThisError)]
#[error("analysis failed during {phase:?}: {source}", phase = .analysis.phase)]
pub struct AnalysisError<ParseError: Debug = Infallible> {
  /// Typed cause of the stage that failed.
  pub source:   Box<AnalysisFailure>,
  /// Actual inputs, completed findings, earlier failures, and native source outcomes.
  pub analysis: Box<AnalysisProgress<ParseError>>,
}

/// Native calculation or registry failure at the analysis boundary.
#[derive(Debug, ThisError)]
pub enum AnalysisFailure {
  /// Pair scoring failed after retaining every earlier comparison.
  #[error(transparent)]
  Grouping(#[from] NearGroupingFailure),
  /// Line statistics could not represent the measured population.
  #[error(transparent)]
  Statistics(#[from] StatisticsFailure),
  /// The ignore registry could not be loaded.
  #[error(transparent)]
  Ignore(#[from] IgnoreFileError),
  /// Suppression accounting could not represent a complete tally.
  #[error(transparent)]
  Suppression(#[from] SuppressionCountFailure),
  /// A window's inclusive source interval could not be measured.
  #[error(transparent)]
  Window(#[from] UnitSpanFailure),
  /// Source coverage could not be measured without losing integer evidence.
  #[error(transparent)]
  Coverage(#[from] CoverageFailure),
}

/// Native source unit and rejected line-interval measurement.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
#[error("source unit line measurement failed: {source}")]
pub struct UnitSpanFailure {
  /// Complete unit whose source interval was measured.
  pub unit:   Box<CodeUnit>,
  /// Original endpoints and failed interval operation.
  pub source: LineRangeFailure,
}

/// Arithmetic step that rejected a coverage calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ThisError)]
pub enum CoverageFailureCause {
  /// An inclusive source interval is invalid or unrepresentable.
  #[error(transparent)]
  Interval(#[from] LineRangeFailure),
  /// Adding a disjoint intersection would exceed the integer capacity.
  #[error("covered-line total overflow while adding {incoming}")]
  TotalOverflow {
    /// Original interval length being accumulated.
    incoming: usize,
  },
  /// Binary64 conversion or division failed with original count evidence.
  #[error(transparent)]
  Ratio(#[from] RatioFailure),
}

/// Original coverage population and the completed integer sum at failure.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
#[error("source coverage measurement failed after {completed} lines: {source}")]
pub struct CoverageFailure {
  /// Complete candidate whose lines form the denominator.
  pub candidate: Box<CodeUnit>,
  /// Original covering intervals from the candidate's source file.
  pub ranges:    Vec<LineRange>,
  /// Completed covered-line count before the failed operation.
  pub completed: usize,
  /// Complete arithmetic failure, including rejected counts or endpoints.
  pub source:    CoverageFailureCause,
}

/// The population whose suppression count could not be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionPopulation {
  /// Tagged units for one rule.
  Units,
  /// Suppressed groups for one rule.
  Groups,
  /// Sum of all unit-rule tallies.
  TotalUnits,
}

/// Complete suppression accounting at the rejected addition.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
#[error("{population:?} suppression count overflow for {rule:?}: {completed} + {incoming}")]
pub struct SuppressionCountFailure {
  /// Completed unit tallies, including any initial sub-unit counts.
  pub unit_counts:  BTreeMap<RuleId, usize>,
  /// Completed group tallies.
  pub group_counts: BTreeMap<RuleId, usize>,
  /// The population being measured.
  pub population:   SuppressionPopulation,
  /// Rule whose contribution could not be added.
  pub rule:         RuleId,
  /// Accumulated integer before the rejected addition.
  pub completed:    usize,
  /// Original contribution to that integer.
  pub incoming:     usize,
}
