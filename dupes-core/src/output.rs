//! Report rendering: the [`Reporter`] trait, shared presentation options
//! and section vocabulary, plus the [`text`] and [`json`] reporters.

pub mod json;
pub mod text;

use std::borrow::Cow;
use std::fmt::Display;
use std::io;
use std::path::Path;

#[cfg(feature = "cli")]
use clap::Args;
use thiserror::Error;

use self::json::JsonReporter;
use self::text::TextReporter;
use crate::AnalysisResult;
use crate::SourceAnalysis;
use crate::calculation;
use crate::calculation::ScalingFailure;
use crate::grouper::DuplicateGroup;
use crate::grouper::DuplicationStats;
use crate::grouper::PercentageFailure;

/// A report failed while calculating a measurement, encoding, or writing its output stream.
#[derive(Debug, Error)]
pub enum ReportError {
  /// The output writer returned its native I/O failure.
  #[error(transparent)]
  Write(#[from] io::Error),
  /// JSON serialization returned its complete native failure.
  #[error(transparent)]
  Json(#[from] serde_json::Error),
  /// A percentage calculation retained its complete original integer statistics.
  #[error(transparent)]
  Percentage(#[from] PercentageFailure),
  /// A group's displayed similarity could not be represented as a finite measurement.
  #[error("cannot render similarity for group {}: {source}", group.fingerprint)]
  Similarity {
    /// Complete group whose original similarity was being rendered.
    group:  Box<DuplicateGroup>,
    /// Original floating-point input, multiplier, and rejected native result.
    source: ScalingFailure,
  },
}

/// Express a group score in the renderer's units while retaining non-finite evidence.
pub(crate) fn displayed_similarity(group: &DuplicateGroup, multiplier: f64) -> Result<f64, ReportError> {
  calculation::scale(group.similarity, multiplier).map_err(|source| ReportError::Similarity {
    group: Box::new(group.clone()),
    source,
  })
}

/// A selected built-in renderer and its complete presentation configuration.
#[derive(Debug)]
pub enum ReportRenderer {
  /// Human-readable rendering with its base path and presentation options.
  Text(TextReporter),
  /// JSON rendering with its base path and presentation options.
  Json(JsonReporter),
}

impl Reporter for ReportRenderer {
  fn report_full<ParseError: Display>(&self, result: &AnalysisResult<ParseError>, writer: &mut impl io::Write) -> Result<(), ReportError> {
    match *self {
      Self::Text(ref reporter) => reporter.report_full(result, writer),
      Self::Json(ref reporter) => reporter.report_full(result, writer),
    }
  }

  fn report_stats(&self, stats: &DuplicationStats, writer: &mut impl io::Write) -> Result<(), ReportError> {
    match *self {
      Self::Text(ref reporter) => reporter.report_stats(stats, writer),
      Self::Json(ref reporter) => reporter.report_stats(stats, writer),
    }
  }

  fn report_groups(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write, section: ReportSection) -> Result<(), ReportError> {
    match *self {
      Self::Text(ref reporter) => reporter.report_groups(groups, writer, section),
      Self::Json(ref reporter) => reporter.report_groups(groups, writer, section),
    }
  }
}

/// Derive display diagnostics while borrowing every original typed source outcome.
pub(crate) fn warning_messages<ParseError: Display>(result: &AnalysisResult<ParseError>) -> Vec<String> {
  let mut messages: Vec<_> = result.warnings.iter().map(ToString::to_string).collect();
  for observed in &result.sources {
    match *observed {
      SourceAnalysis::Ast(Err(ref source)) | SourceAnalysis::Text(Err(ref source)) => messages.push(source.to_string()),
      SourceAnalysis::Ast(Ok(ref source)) => match source.parsed {
        Err(ref failure) => messages.push(failure.to_string()),
        Ok(ref parsed) => {
          if let Some(Err(ref failure)) = parsed.sub_units {
            messages.push(failure.to_string());
          }
        }
      },
      SourceAnalysis::Text(Ok(_)) => {}
    }
  }
  messages
}

/// Compute a display path relative to an optional base, falling back to the absolute path.
#[must_use]
pub fn display_path<'a>(base: Option<&Path>, path: &'a Path) -> Cow<'a, str> {
  if let Some(base_path) = base
    && let Ok(relative) = path.strip_prefix(base_path)
  {
    return relative.to_string_lossy();
  }
  path.to_string_lossy()
}

/// Presentation options shared by all reporters.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "cli", derive(Args))]
pub struct ReportOptions {
  /// Include rule-suppressed duplicate groups in the report body.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub show_suppressed: bool,
  /// Verbose statistics: per-rule suppression breakdown.
  #[cfg_attr(feature = "cli", arg(short = 'v', long, global = true))]
  pub verbose:         bool,
}

impl ReportOptions {
  /// Default presentation settings usable by constant reporter constructors.
  pub const DEFAULT: Self = Self {
    show_suppressed: false,
    verbose:         false,
  };
}

/// Duplicate group section requested from a reporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSection {
  /// Top-level exact duplicates.
  Exact,
  /// Top-level near duplicates.
  Near,
  /// Sub-function exact duplicates.
  SubExact,
  /// Sub-function near duplicates.
  SubNear,
}

impl ReportSection {
  /// The section's rendered heading.
  #[must_use]
  pub const fn title(self) -> &'static str {
    match self {
      Self::Exact => "Exact Duplicates",
      Self::Near => "Near Duplicates",
      Self::SubExact => "Sub-function Exact Duplicates",
      Self::SubNear => "Sub-function Near Duplicates",
    }
  }

  /// Message rendered when the section has no groups; `None` skips the section.
  #[must_use]
  pub const fn empty_message(self) -> Option<&'static str> {
    match self {
      Self::Exact => Some("No exact duplicates found."),
      Self::Near => Some("No near duplicates found."),
      Self::SubExact | Self::SubNear => None,
    }
  }

  /// Whether member rows render a similarity score.
  #[must_use]
  pub const fn show_similarity(self) -> bool {
    matches!(self, Self::Near | Self::SubNear)
  }

  /// Whether member rows name the owning parent function.
  #[must_use]
  pub const fn show_parent(self) -> bool {
    matches!(self, Self::SubExact | Self::SubNear)
  }
}

/// Trait for reporting analysis results.
pub trait Reporter {
  /// Render the full report (stats plus every group section).
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_full<ParseError: Display>(&self, result: &AnalysisResult<ParseError>, writer: &mut impl io::Write) -> Result<(), ReportError>;

  /// Render the statistics summary only.
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_stats(&self, stats: &DuplicationStats, writer: &mut impl io::Write) -> Result<(), ReportError>;

  /// Render one duplicate-group section.
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_groups(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write, section: ReportSection) -> Result<(), ReportError>;

  /// Render the top-level exact-duplicates section.
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_exact(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write) -> Result<(), ReportError> {
    self.report_groups(groups, writer, ReportSection::Exact)
  }

  /// Render the top-level near-duplicates section.
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_near(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write) -> Result<(), ReportError> {
    self.report_groups(groups, writer, ReportSection::Near)
  }

  /// Render the sub-function exact-duplicates section.
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_sub_exact(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write) -> Result<(), ReportError> {
    self.report_groups(groups, writer, ReportSection::SubExact)
  }

  /// Render the sub-function near-duplicates section.
  ///
  /// # Errors
  ///
  /// Returns the complete calculation failure or native encoding or output-write failure.
  fn report_sub_near(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write) -> Result<(), ReportError> {
    self.report_groups(groups, writer, ReportSection::SubNear)
  }
}

#[cfg(test)]
mod tests {
  use std::io::ErrorKind;
  use std::slice;

  use strict_test_support::ensure;

  use super::ReportError;
  use super::ReportRenderer;
  use super::Reporter as _;
  use super::json::JsonReporter;
  use super::text::TextReporter;
  use crate::ReportTestFailure;
  use crate::check_render;
  use crate::fingerprint::Fingerprint;
  use crate::grouper::DuplicationStats;
  use crate::make_unit;
  use crate::near_group;

  /// Both rendering formats reject a non-finite score with its complete original group.
  #[test]
  fn non_finite_similarity_retains_group_and_calculation() -> Result<(), ReportTestFailure> {
    let group = near_group(Fingerprint::from_bytes(b"non-finite score"), f64::INFINITY, vec![
      make_unit("first", "first.rs", 1, 3),
      make_unit("second", "second.rs", 5, 7),
    ]);
    for (renderer, multiplier) in [
      (ReportRenderer::Text(TextReporter::new(None)), 100.0_f64),
      (ReportRenderer::Json(JsonReporter::new(None)), 1.0_f64),
    ] {
      let mut output = Vec::new();
      let outcome = renderer.report_near(slice::from_ref(&group), &mut output);
      check_render(outcome, output, |observed, _bytes| {
        ensure(
          matches!(observed, Err(ReportError::Similarity { group: retained, source })
          if retained.as_ref() == &group
            && source.operand.to_bits() == f64::INFINITY.to_bits()
            && source.multiplier.to_bits() == multiplier.to_bits()
            && source.result.to_bits() == f64::INFINITY.to_bits()),
          "the renderer preserves the native non-finite value, scale, result, and complete group",
        )
      })?;
    }
    Ok(())
  }

  /// Both renderer variants retain the native failure when the destination cannot accept bytes.
  #[test]
  fn writer_failures_remain_native_through_renderer_dispatch() -> Result<(), ReportTestFailure> {
    for renderer in [
      ReportRenderer::Text(TextReporter::new(None)),
      ReportRenderer::Json(JsonReporter::new(None)),
    ] {
      let mut storage = [];
      let mut writer = storage.as_mut_slice();
      let outcome = renderer.report_stats(&DuplicationStats::default(), &mut writer);
      check_render(outcome, storage.to_vec(), |observed, output| {
        ensure(
          matches!(*observed, Err(ReportError::Write(ref source)) if source.kind() == ErrorKind::WriteZero) && output.is_empty(),
          "renderer dispatch preserves the native exhausted-writer failure and writes no bytes",
        )
      })?;
    }
    Ok(())
  }
}
