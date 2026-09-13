//! The JSON reporter: machine-readable stats, report, and group documents.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io;
use std::num::NonZero;
use std::path::PathBuf;

use serde::Serialize;
use serde::Serializer;

use crate::AnalysisResult;
use crate::code_unit::CodeUnitKind;
use crate::code_unit::DetectionDimension;
use crate::fingerprint::Fingerprint;
use crate::grouper::DuplicateGroup;
use crate::grouper::DuplicationStats;
use crate::grouper::MatchKind;
use crate::grouper::PercentageFailure;
use crate::output::ReportError;
use crate::output::ReportOptions;
use crate::output::ReportSection;
use crate::output::Reporter;
use crate::output::display_path;
use crate::output::warning_messages;
use crate::suppression::RuleId;
use crate::suppression::SuppressionWarning;

/// Renders analysis results as JSON documents.
#[derive(Debug)]
pub struct JsonReporter {
  /// Base path for displaying relative paths.
  pub base_path: Option<PathBuf>,
  /// Presentation options.
  pub options:   ReportOptions,
}

/// JSON statistics, including derived percentages and omission of optional zero counts.
#[derive(Serialize)]
struct JsonStats {
  /// Analyzed units, including rule-suppressed units.
  total_code_units:              usize,
  /// Source lines covered by analyzed units.
  total_lines:                   usize,
  /// Visible exact AST groups.
  exact_duplicate_groups:        usize,
  /// Members of exact AST groups.
  exact_duplicate_units:         usize,
  /// Visible near AST groups.
  near_duplicate_groups:         usize,
  /// Members of near AST groups.
  near_duplicate_units:          usize,
  /// Lines covered by exact AST duplicates.
  exact_duplicate_lines:         usize,
  /// Lines covered by near AST duplicates.
  near_duplicate_lines:          usize,
  /// Exact duplicate lines as a percentage of the corpus.
  exact_duplicate_percent:       f64,
  /// Near duplicate lines as a percentage of the corpus.
  near_duplicate_percent:        f64,
  /// Nonzero sub-function exact groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  sub_exact_groups:              Option<NonZero<usize>>,
  /// Nonzero sub-function exact members, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  sub_exact_units:               Option<NonZero<usize>>,
  /// Nonzero sub-function near groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  sub_near_groups:               Option<NonZero<usize>>,
  /// Nonzero sub-function near members, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  sub_near_units:                Option<NonZero<usize>>,
  /// Nonzero normalized-token exact groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  token_normalized_exact_groups: Option<NonZero<usize>>,
  /// Nonzero normalized-token exact members, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  token_normalized_exact_units:  Option<NonZero<usize>>,
  /// Nonzero normalized-token near groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  token_normalized_near_groups:  Option<NonZero<usize>>,
  /// Nonzero normalized-token near members, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  token_normalized_near_units:   Option<NonZero<usize>>,
  /// Nonzero raw-token exact groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  token_raw_exact_groups:        Option<NonZero<usize>>,
  /// Nonzero raw-token exact members, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  token_raw_exact_units:         Option<NonZero<usize>>,
  /// Nonzero line-window exact groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  line_exact_groups:             Option<NonZero<usize>>,
  /// Nonzero line-window exact members, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  line_exact_units:              Option<NonZero<usize>>,
  /// Rule-suppressed units across all dimensions.
  suppressed_unit_count:         usize,
  /// Rule-suppressed groups across all dimensions.
  suppressed_group_count:        usize,
  /// Counts attributed to rule identifiers in deterministic order.
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  suppressed_by_rule:            BTreeMap<String, usize>,
  /// Nonzero registered-ignore groups, omitted when absent.
  #[serde(skip_serializing_if = "Option::is_none")]
  ignored_group_count:           Option<NonZero<usize>>,
}

/// A duplicate group projected into the documented JSON schema.
#[derive(Serialize)]
struct JsonGroup {
  /// Native detection dimension, serialized using its stable label.
  dimension:   DetectionDimension,
  /// Native exact/near classification.
  match_kind:  MatchKind,
  /// Native content identity, serialized as hexadecimal text.
  #[serde(serialize_with = "serialize_display")]
  fingerprint: Fingerprint,
  /// Similarity assigned by the grouping owner.
  similarity:  f64,
  /// Optional suppression rule label.
  #[serde(skip_serializing_if = "Option::is_none")]
  suppressed:  Option<&'static str>,
  /// Other dimensions that found redundant copies of this group.
  #[serde(skip_serializing_if = "Vec::is_empty")]
  also_seen:   Vec<JsonCoverageNote>,
  /// Source members in their canonical group order.
  members:     Vec<JsonMember>,
}

/// Cross-dimension coverage reported alongside a group.
#[derive(Serialize)]
struct JsonCoverageNote {
  /// Native dimension of the redundant groups.
  dimension:   DetectionDimension,
  /// Native match classification of the redundant groups.
  match_kind:  MatchKind,
  /// Number of redundant groups in this dimension and match class.
  group_count: usize,
}

/// Source location and identity fields exposed for one group member.
#[derive(Serialize)]
struct JsonMember {
  /// Display name assigned by the analyzer.
  name:        String,
  /// Native unit kind rendered through its documented display label.
  #[serde(serialize_with = "serialize_display")]
  kind:        CodeUnitKind,
  /// Content fingerprint of the member unit, for authoring resilient
  /// `.dupes-ignore.toml` entries (`member_fingerprints`).
  #[serde(serialize_with = "serialize_display")]
  fingerprint: Fingerprint,
  /// File path relative to the reporter's configured base when possible.
  file:        String,
  /// Inclusive first source line.
  line_start:  usize,
  /// Inclusive final source line.
  line_end:    usize,
  /// Optional suppression rule label.
  #[serde(skip_serializing_if = "Option::is_none")]
  suppressed:  Option<&'static str>,
}

/// Complete JSON report envelope.
#[derive(Serialize)]
struct JsonReport<'analysis> {
  /// Statistics and derived percentages.
  stats:             JsonStats,
  /// Visible duplicate groups across all enabled dimensions.
  groups:            Vec<JsonGroup>,
  /// Rule-suppressed groups when explicitly requested.
  #[serde(skip_serializing_if = "Vec::is_empty")]
  suppressed_groups: Vec<JsonGroup>,
  /// Nonfatal analysis diagnostics in observation order.
  warnings:          Vec<String>,
  /// Complete typed rule warnings alongside their human-readable messages.
  #[serde(skip_serializing_if = "<[SuppressionWarning]>::is_empty")]
  rule_warnings:     &'analysis [SuppressionWarning],
}

/// Serialize an identity or unit-kind value at the textual JSON boundary.
fn serialize_display<Subject: Display, Encoder: Serializer>(subject: &Subject, encoder: Encoder) -> Result<Encoder::Ok, Encoder::Error> {
  encoder.collect_str(subject)
}

/// Finish encoding before the first output write, then terminate the JSON document with a newline.
fn write_document(document: &impl Serialize, writer: &mut impl io::Write) -> Result<(), ReportError> {
  let json = serde_json::to_string_pretty(document)?;
  writeln!(writer, "{json}")?;
  Ok(())
}

impl Reporter for JsonReporter {
  fn report_full<ParseError: Display>(&self, result: &AnalysisResult<ParseError>, writer: &mut impl io::Write) -> Result<(), ReportError> {
    let report = JsonReport {
      stats:             Self::to_json_stats(&result.stats)?,
      groups:            result
        .groups()
        .map(|group| self.to_json_group(group))
        .collect::<Result<_, _>>()?,
      suppressed_groups: if self.options.show_suppressed {
        result
          .suppressed_groups
          .iter()
          .map(|group| self.to_json_group(group))
          .collect::<Result<_, _>>()?
      } else {
        Vec::new()
      },
      warnings:          warning_messages(result),
      rule_warnings:     &result.warnings,
    };
    write_document(&report, writer)
  }

  fn report_stats(&self, stats: &DuplicationStats, writer: &mut impl io::Write) -> Result<(), ReportError> {
    let json_stats = Self::to_json_stats(stats)?;
    write_document(&json_stats, writer)
  }

  fn report_groups(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write, _section: ReportSection) -> Result<(), ReportError> {
    let json_groups: Vec<JsonGroup> = groups.iter().map(|group| self.to_json_group(group)).collect::<Result<_, _>>()?;
    write_document(&json_groups, writer)
  }
}

impl JsonReporter {
  /// Reporter with default presentation options.
  #[must_use]
  pub const fn new(base_path: Option<PathBuf>) -> Self {
    Self::with_options(base_path, ReportOptions::DEFAULT)
  }

  /// Reporter with explicit presentation options.
  #[must_use]
  pub const fn with_options(base_path: Option<PathBuf>, options: ReportOptions) -> Self {
    Self {
      base_path,
      options,
    }
  }

  /// Preserve statistics while expressing optional JSON counts as nonzero values.
  fn to_json_stats(stats: &DuplicationStats) -> Result<JsonStats, PercentageFailure> {
    Ok(JsonStats {
      total_code_units:              stats.total_code_units,
      total_lines:                   stats.total_lines,
      exact_duplicate_groups:        stats.exact_duplicate_groups,
      exact_duplicate_units:         stats.exact_duplicate_units,
      near_duplicate_groups:         stats.near_duplicate_groups,
      near_duplicate_units:          stats.near_duplicate_units,
      exact_duplicate_lines:         stats.exact_duplicate_lines,
      near_duplicate_lines:          stats.near_duplicate_lines,
      exact_duplicate_percent:       stats.exact_duplicate_percent()?,
      near_duplicate_percent:        stats.near_duplicate_percent()?,
      sub_exact_groups:              NonZero::new(stats.sub_exact_groups),
      sub_exact_units:               NonZero::new(stats.sub_exact_units),
      sub_near_groups:               NonZero::new(stats.sub_near_groups),
      sub_near_units:                NonZero::new(stats.sub_near_units),
      token_normalized_exact_groups: NonZero::new(stats.token_normalized_exact_groups),
      token_normalized_exact_units:  NonZero::new(stats.token_normalized_exact_units),
      token_normalized_near_groups:  NonZero::new(stats.token_normalized_near_groups),
      token_normalized_near_units:   NonZero::new(stats.token_normalized_near_units),
      token_raw_exact_groups:        NonZero::new(stats.token_raw_exact_groups),
      token_raw_exact_units:         NonZero::new(stats.token_raw_exact_units),
      line_exact_groups:             NonZero::new(stats.line_exact_groups),
      line_exact_units:              NonZero::new(stats.line_exact_units),
      suppressed_unit_count:         stats.suppressed_unit_count,
      suppressed_group_count:        stats.suppressed_group_count,
      suppressed_by_rule:            stats.suppressed_by_rule.clone(),
      ignored_group_count:           NonZero::new(stats.ignored_group_count),
    })
  }

  /// Convert one group into its JSON presentation without replacing its native identities.
  fn to_json_group(&self, group: &DuplicateGroup) -> Result<JsonGroup, ReportError> {
    Ok(JsonGroup {
      dimension:   group.dimension,
      match_kind:  group.match_kind,
      fingerprint: group.fingerprint,
      similarity:  super::displayed_similarity(group, 1.0)?,
      suppressed:  group.suppressed.map(RuleId::as_str),
      also_seen:   group
        .also_seen
        .iter()
        .map(|note| JsonCoverageNote {
          dimension:   note.dimension,
          match_kind:  note.match_kind,
          group_count: note.group_count,
        })
        .collect(),
      members:     group
        .members
        .iter()
        .map(|member| JsonMember {
          name:        member.name.clone(),
          kind:        member.kind,
          fingerprint: member.fingerprint,
          file:        display_path(self.base_path.as_deref(), &member.file).into_owned(),
          line_start:  member.line_start,
          line_end:    member.line_end,
          suppressed:  member.suppressed.map(RuleId::as_str),
        })
        .collect(),
    })
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;
  use std::path::PathBuf;

  use serde_json::Value;
  use serde_json::json;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::JsonReporter;
  use super::write_document;
  use crate::ReportTestFailure;
  use crate::analysis_result;
  use crate::block_fingerprint;
  use crate::check_json;
  use crate::check_render;
  use crate::exact_group;
  use crate::make_unit;
  use crate::near_group;
  use crate::output::ReportError;
  use crate::output::Reporter as _;
  use crate::render_json;
  use crate::stats;
  use crate::suppression::SuppressionWarning;
  use crate::with_duplicate_lines;

  /// A native JSON encoding failure leaves all existing destination bytes intact.
  #[test]
  fn serialization_failure_preserves_json_cause_before_output_writes() -> Result<(), ReportTestFailure> {
    let document = BTreeMap::from([([1_u8, 2_u8], 3_u8)]);
    let mut output = b"existing output".to_vec();
    let outcome = write_document(&document, &mut output);
    check_render(outcome, output, |observed, bytes| {
      ensure(
        matches!(*observed, Err(ReportError::Json(_))) && bytes == b"existing output",
        "an unsupported object key returns its native encoding failure before any destination write",
      )
      .map(drop)
    })
  }

  /// Statistics retain the complete JSON schema and omit optional zero-valued dimensions.
  #[test]
  fn json_report_stats() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(None);
    let statistics = with_duplicate_lines(stats(50, 500, 3, 8, 2, 5), 30, 20);
    let document = render_json(|writer| reporter.report_stats(&statistics, writer))?;
    ensure_eq(
      document,
      json!({
        "total_code_units": 50,
        "total_lines": 500,
        "exact_duplicate_groups": 3,
        "exact_duplicate_units": 8,
        "near_duplicate_groups": 2,
        "near_duplicate_units": 5,
        "exact_duplicate_lines": 30,
        "near_duplicate_lines": 20,
        "exact_duplicate_percent": 6.0,
        "near_duplicate_percent": 4.0,
        "suppressed_unit_count": 0,
        "suppressed_group_count": 0
      }),
      "preserve the complete statistics schema while omitting empty optional dimensions",
    )
    .map(drop)
    .map_err(ReportTestFailure::from)
  }

  /// An empty exact-duplicate population renders a valid empty group array.
  #[test]
  fn json_report_exact_empty() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(None);
    let document = render_json(|writer| reporter.report_exact(&[], writer))?;
    ensure_eq(document, json!([]), "empty exact groups render as an empty JSON array")
      .map(drop)
      .map_err(ReportTestFailure::from)
  }

  /// Exact reports retain both members, complete similarity, and the group identity.
  #[test]
  fn json_report_exact_with_groups() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(Some(PathBuf::from("/project")));
    let group = exact_group(vec![
      make_unit("foo", "/project/src/a.rs", 10, 20),
      make_unit("bar", "/project/src/b.rs", 30, 40),
    ]);
    let document = render_json(|writer| reporter.report_exact(&[group], writer))?;
    check_json(document, |parsed| {
      ensure(parsed.as_array().map(Vec::len) == Some(1), "render one exact group").map(drop)?;
      ensure(
        parsed.pointer("/0/members").and_then(Value::as_array).map(Vec::len) == Some(2),
        "retain both exact members",
      )
      .map(drop)?;
      ensure(
        parsed.pointer("/0/similarity") == Some(&json!(1.0)),
        "exact groups have complete similarity",
      )
      .map(drop)?;
      ensure(
        parsed.pointer("/0/fingerprint").is_some_and(Value::is_string),
        "group identity is serialized as hexadecimal text",
      )
      .map(drop)
    })
  }

  /// Near reports preserve the selected similarity and content identity.
  #[test]
  fn json_report_near_with_groups() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(None);
    let fp = block_fingerprint();
    let group = near_group(fp, 0.85, vec![
      make_unit("process", "/src/a.rs", 10, 25),
      make_unit("compute", "/src/b.rs", 30, 45),
    ]);
    let document = render_json(|writer| reporter.report_near(&[group], writer))?;
    check_json(document, |parsed| {
      ensure(parsed.as_array().map(Vec::len) == Some(1), "render one near group").map(drop)?;
      ensure(
        parsed.pointer("/0/fingerprint") == Some(&json!(fp.to_hex())),
        "retain the near-group content identity",
      )
      .map(drop)?;
      ensure(
        parsed.pointer("/0/similarity") == Some(&json!(0.85)),
        "retain the computed near similarity",
      )
      .map(drop)
    })
  }

  /// A rendered group document decodes as a JSON array.
  #[test]
  fn json_is_valid() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(Some(PathBuf::from("/project")));
    let group = exact_group(vec![make_unit("foo", "/project/src/a.rs", 10, 20)]);
    let document = render_json(|writer| reporter.report_exact(&[group], writer))?;
    check_json(document, |parsed| {
      ensure(parsed.is_array(), "the group document is valid JSON with an array root").map(drop)
    })
  }

  /// Configured report roots make member locations relative without changing their identity.
  #[test]
  fn json_relative_paths() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(Some(PathBuf::from("/project")));
    let fp = block_fingerprint();
    let group = near_group(fp, 0.9, vec![make_unit("foo", "/project/src/main.rs", 1, 10)]);
    let document = render_json(|writer| reporter.report_near(&[group], writer))?;
    check_json(document, |parsed| {
      ensure(
        parsed.pointer("/0/members/0/file") == Some(&json!("src/main.rs")),
        "strip the configured base from the member path",
      )
      .map(drop)
    })
  }

  /// Full reports retain group sections, warning messages, and typed rule requests.
  #[test]
  fn json_report_full_includes_groups_and_warnings() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(None);
    let result = analysis_result(
      with_duplicate_lines(stats(3, 120, 1, 2, 1, 2), 18, 12),
      vec![exact_group(vec![
        make_unit("foo", "/src/a.rs", 1, 10),
        make_unit("bar", "/src/b.rs", 20, 30),
      ])],
      vec![near_group(block_fingerprint(), 0.75, vec![
        make_unit("process", "/src/c.rs", 40, 50),
        make_unit("compute", "/src/d.rs", 60, 70),
      ])],
      vec![
        SuppressionWarning::UnknownDisabledRule {
          id: "no.such-rule".to_owned(),
        },
        SuppressionWarning::UnknownEnabledRule {
          id: "no.such-rule".to_owned(),
        },
      ],
    );
    let document = render_json(|writer| reporter.report_full(&result, writer))?;
    check_json(document, |parsed| {
      ensure(
        parsed.get("groups").and_then(Value::as_array).map(Vec::len) == Some(2),
        "include exact and near groups in the complete report",
      )
      .map(drop)?;
      ensure(
        parsed.get("warnings")
          == Some(&json!([
            "unknown suppression rule id: no.such-rule",
            "unknown suppression rule id: no.such-rule",
          ]))
          && parsed.get("rule_warnings")
            == Some(&json!([
              { "kind": "unknown_disabled_rule", "id": "no.such-rule" },
              { "kind": "unknown_enabled_rule", "id": "no.such-rule" },
            ])),
        "retain each complete requested rule action alongside the existing warning message format",
      )
      .map(drop)
    })
  }

  /// Reports without rule-selection failures retain an empty warning list and omit the optional
  /// typed section.
  #[test]
  fn json_report_without_rule_warnings_omits_optional_section() -> Result<(), ReportTestFailure> {
    let reporter = JsonReporter::new(None);
    let result = analysis_result(stats(0, 0, 0, 0, 0, 0), Vec::new(), Vec::new(), Vec::new());
    let document = render_json(|writer| reporter.report_full(&result, writer))?;
    check_json(document, |parsed| {
      ensure(
        parsed.get("warnings") == Some(&json!([])) && parsed.get("rule_warnings").is_none(),
        "an empty warning population does not fabricate rule failures or an optional rule-warning section",
      )
      .map(drop)
    })
  }
}
