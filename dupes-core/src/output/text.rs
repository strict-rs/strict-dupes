//! The text reporter: the human-readable stats summary and group sections.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io;
use std::path::PathBuf;

use crate::AnalysisResult;
use crate::grouper::DuplicateGroup;
use crate::grouper::DuplicationStats;
use crate::grouper::MatchKind;
use crate::output::ReportError;
use crate::output::ReportOptions;
use crate::output::ReportSection;
use crate::output::Reporter;
use crate::output::display_path;
use crate::output::displayed_similarity;

/// Render a source-line count with decimal thousands separators.
#[allow(
  clippy::single_call_fn,
  reason = "The statistics formatter owns decimal grouping independently of report layout."
)]
fn format_with_commas(count: usize) -> String {
  let digits = count.to_string();
  let mut result = String::with_capacity(digits.len());
  for (index, character) in digits.char_indices() {
    if index > 0 && digits.len().saturating_sub(index).is_multiple_of(3) {
      result.push(',');
    }
    result.push(character);
  }
  result
}

/// Renders analysis results as human-readable text.
#[derive(Debug)]
pub struct TextReporter {
  /// Base path for displaying relative paths.
  pub base_path: Option<PathBuf>,
  /// Presentation options.
  pub options:   ReportOptions,
}

impl TextReporter {
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

  /// Render a requested section, including its empty-state policy and group rows.
  fn write_groups(
    &self,
    groups: &[DuplicateGroup],
    writer: &mut impl io::Write,
    title: &str,
    empty_message: Option<&str>,
    show_similarity: bool,
    show_parent: bool,
  ) -> Result<(), ReportError> {
    if groups.is_empty() {
      if let Some(msg) = empty_message {
        writeln!(writer, "{msg}")?;
      }
      return Ok(());
    }

    writeln!(writer, "{title}")?;
    writeln!(writer, "{}", "=".repeat(title.len()))?;
    writeln!(writer)?;

    for (index, group) in groups.iter().enumerate() {
      self.write_group(group, index, writer, show_similarity, show_parent)?;
    }
    Ok(())
  }

  /// Render one group's identity, member locations, and requested cross-dimension notes.
  #[allow(
    clippy::single_call_fn,
    reason = "Each report section reuses the same complete group rendering contract."
  )]
  fn write_group(
    &self,
    group: &DuplicateGroup,
    index: usize,
    writer: &mut impl io::Write,
    show_similarity: bool,
    show_parent: bool,
  ) -> Result<(), ReportError> {
    let fp = group.fingerprint.to_hex();
    let group_rule = group
      .suppressed
      .map(|rule| format!(" [rule: {}]", rule.as_str()))
      .unwrap_or_default();
    if show_similarity {
      let percentage = displayed_similarity(group, 100.0)?;
      writeln!(
        writer,
        "Group {} (fingerprint: {}, similarity: {:.0}%, {} members):{}",
        index.saturating_add(1),
        fp,
        percentage,
        group.members.len(),
        group_rule,
      )?;
    } else {
      writeln!(
        writer,
        "Group {} (fingerprint: {}, {} members):{}",
        index.saturating_add(1),
        fp,
        group.members.len(),
        group_rule,
      )?;
    }
    for member in &group.members {
      let parent = if show_parent {
        member
          .parent_name
          .as_deref()
          .map(|parent_name| format!(" in {parent_name}"))
          .unwrap_or_default()
      } else {
        String::new()
      };
      let marker = if group.suppressed.is_none() {
        member
          .suppressed
          .map(|rule| format!(" [suppressed: {}]", rule.as_str()))
          .unwrap_or_default()
      } else {
        String::new()
      };
      writeln!(
        writer,
        "  - {} ({}){} at {}:{}-{}{}",
        member.name,
        member.kind,
        parent,
        display_path(self.base_path.as_deref(), &member.file),
        member.line_start,
        member.line_end,
        marker,
      )?;
    }
    if self.options.show_suppressed {
      for note in &group.also_seen {
        writeln!(
          writer,
          "  also seen as: {} {} {} group(s)",
          note.group_count, note.dimension, note.match_kind,
        )?;
      }
    }
    writeln!(writer)?;
    Ok(())
  }

  /// Write the suppression and registry accounting lines of the stats.
  fn write_suppression_stats(&self, stats: &DuplicationStats, writer: &mut impl io::Write) -> io::Result<()> {
    let has_suppressed = stats.suppressed_unit_count > 0 || stats.suppressed_group_count > 0;
    if has_suppressed {
      writeln!(writer)?;
      writeln!(
        writer,
        "Suppressed: {} units, {} groups (--show-suppressed to list)",
        stats.suppressed_unit_count, stats.suppressed_group_count
      )?;
    }
    if has_suppressed && self.options.verbose {
      write_rule_counts(&stats.suppressed_by_rule, writer)?;
    }
    if stats.ignored_group_count > 0 {
      writeln!(writer, "Ignored (registry): {} groups", stats.ignored_group_count)?;
    }
    Ok(())
  }

  /// Write the rule-suppressed groups, partitioned per dimension and match
  /// kind under `Suppressed ...` section titles.
  fn write_suppressed_sections(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write) -> Result<(), ReportError> {
    use crate::code_unit::DetectionDimension;
    let sections = [
      (DetectionDimension::Ast, MatchKind::Exact, "Suppressed Exact Duplicates"),
      (DetectionDimension::Ast, MatchKind::Near, "Suppressed Near Duplicates"),
      (
        DetectionDimension::SubAst,
        MatchKind::Exact,
        "Suppressed Sub-function Exact Duplicates",
      ),
      (
        DetectionDimension::SubAst,
        MatchKind::Near,
        "Suppressed Sub-function Near Duplicates",
      ),
      (
        DetectionDimension::TokenNormalized,
        MatchKind::Exact,
        "Suppressed Normalized Token Exact Duplicates",
      ),
      (
        DetectionDimension::TokenNormalized,
        MatchKind::Near,
        "Suppressed Normalized Token Near Duplicates",
      ),
      (
        DetectionDimension::TokenRaw,
        MatchKind::Exact,
        "Suppressed Raw Token Exact Duplicates",
      ),
      (DetectionDimension::Line, MatchKind::Exact, "Suppressed Line Exact Duplicates"),
    ];
    for (dimension, match_kind, title) in sections {
      let section: Vec<DuplicateGroup> = groups
        .iter()
        .filter(|group| group.dimension == dimension && group.match_kind == match_kind)
        .cloned()
        .collect();
      self.write_groups(
        &section,
        writer,
        title,
        None,
        match_kind == MatchKind::Near,
        dimension == DetectionDimension::SubAst,
      )?;
    }
    Ok(())
  }
}

impl Reporter for TextReporter {
  fn report_full<ParseError: Display>(&self, result: &AnalysisResult<ParseError>, writer: &mut impl io::Write) -> Result<(), ReportError> {
    self.report_stats(&result.stats, writer)?;
    writeln!(writer)?;
    self.report_exact(&result.exact_groups, writer)?;
    if !result.near_groups.is_empty() {
      self.report_near(&result.near_groups, writer)?;
    }
    if !result.sub_exact_groups.is_empty() {
      self.report_sub_exact(&result.sub_exact_groups, writer)?;
    }
    if !result.sub_near_groups.is_empty() {
      self.report_sub_near(&result.sub_near_groups, writer)?;
    }
    self.write_groups(
      &result.token_normalized_exact_groups,
      writer,
      "Normalized Token Exact Duplicates",
      None,
      false,
      false,
    )?;
    self.write_groups(
      &result.token_normalized_near_groups,
      writer,
      "Normalized Token Near Duplicates",
      None,
      true,
      false,
    )?;
    self.write_groups(
      &result.token_raw_exact_groups, writer, "Raw Token Exact Duplicates", None, false, false,
    )?;
    self.write_groups(&result.line_exact_groups, writer, "Line Exact Duplicates", None, false, false)?;
    if self.options.show_suppressed {
      self.write_suppressed_sections(&result.suppressed_groups, writer)?;
    }
    Ok(())
  }

  fn report_stats(&self, stats: &DuplicationStats, writer: &mut impl io::Write) -> Result<(), ReportError> {
    let exact_percent = stats.exact_duplicate_percent()?;
    let near_percent = stats.near_duplicate_percent()?;
    writeln!(writer, "Duplication Statistics")?;
    writeln!(writer, "=====================")?;
    writeln!(writer, "Total code units analyzed: {}", stats.total_code_units)?;
    writeln!(writer)?;
    writeln!(
      writer,
      "Exact duplicates: {} groups ({} code units)",
      stats.exact_duplicate_groups, stats.exact_duplicate_units
    )?;
    writeln!(
      writer,
      "Near duplicates:  {} groups ({} code units)",
      stats.near_duplicate_groups, stats.near_duplicate_units
    )?;
    writeln!(writer)?;
    writeln!(writer, "Duplicated lines (exact): {}", stats.exact_duplicate_lines)?;
    writeln!(writer, "Duplicated lines (near):  {}", stats.near_duplicate_lines)?;
    writeln!(
      writer,
      "Duplication: {:.1}% exact, {:.1}% near (of {} total lines)",
      exact_percent,
      near_percent,
      format_with_commas(stats.total_lines),
    )?;
    write_dimension_pair(
      writer,
      "Sub-function exact: ",
      "Sub-function near:  ",
      (stats.sub_exact_groups, stats.sub_exact_units),
      (stats.sub_near_groups, stats.sub_near_units),
    )?;
    write_dimension_pair(
      writer,
      "Normalized token exact: ",
      "Normalized token near:  ",
      (stats.token_normalized_exact_groups, stats.token_normalized_exact_units),
      (stats.token_normalized_near_groups, stats.token_normalized_near_units),
    )?;
    if stats.token_raw_exact_groups > 0 {
      writeln!(
        writer,
        "Raw token exact:        {} groups ({} units)",
        stats.token_raw_exact_groups, stats.token_raw_exact_units
      )?;
    }
    if stats.line_exact_groups > 0 {
      writeln!(
        writer,
        "Line exact:             {} groups ({} units)",
        stats.line_exact_groups, stats.line_exact_units
      )?;
    }
    self.write_suppression_stats(stats, writer)?;
    Ok(())
  }

  fn report_groups(&self, groups: &[DuplicateGroup], writer: &mut impl io::Write, section: ReportSection) -> Result<(), ReportError> {
    self.write_groups(
      groups,
      writer,
      section.title(),
      section.empty_message(),
      section.show_similarity(),
      section.show_parent(),
    )?;
    Ok(())
  }
}

/// Render rule accounting in registry order with each rule's counting unit.
#[allow(
  clippy::single_call_fn,
  reason = "Rule accounting owns its row labels and ordering separately from the statistics section's visibility policy."
)]
fn write_rule_counts(counts: &BTreeMap<String, usize>, writer: &mut impl io::Write) -> io::Result<()> {
  writeln!(writer, "Suppressed by rule:")?;
  for (rule, count) in counts {
    let noun = if rule.starts_with("group.") { "groups" } else { "units" };
    writeln!(writer, "  {rule}: {count} {noun}")?;
  }
  Ok(())
}

/// Write one paired exact/near dimension stats block when either side has
/// groups; the labels carry their own alignment padding.
fn write_dimension_pair(
  writer: &mut impl io::Write,
  exact_label: &str,
  near_label: &str,
  exact: (usize, usize),
  near: (usize, usize),
) -> io::Result<()> {
  if exact.0 == 0 && near.0 == 0 {
    return Ok(());
  }
  writeln!(writer)?;
  writeln!(writer, "{exact_label}{} groups ({} units)", exact.0, exact.1)?;
  writeln!(writer, "{near_label}{} groups ({} units)", near.0, near.1)?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::path::Path;
  use std::path::PathBuf;

  use strict_test_support::ComparisonFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::TextReporter;
  use crate::ReportTestFailure;
  use crate::analysis_result;
  use crate::block_fingerprint;
  use crate::check_text;
  use crate::code_unit::CodeUnitKind;
  use crate::code_unit::DetectionDimension;
  use crate::exact_group;
  use crate::make_unit;
  use crate::near_group;
  use crate::output::ReportSection;
  use crate::output::Reporter as _;
  use crate::output::display_path;
  use crate::render_text;
  use crate::stats;
  use crate::suppression::RuleId;
  use crate::with_duplicate_lines;

  /// The summary renders distinct counts, percentages, and grouped source-line totals.
  #[test]
  fn text_report_stats() -> Result<(), ReportTestFailure> {
    let reporter = TextReporter::new(None);
    let statistics = with_duplicate_lines(stats(100, 1000, 5, 12, 3, 8), 61, 43);
    let rendered = render_text(|writer| reporter.report_stats(&statistics, writer))?;
    check_text(rendered, |output| {
      ensure(output.contains("Total code units analyzed: 100"), "render the analyzed-unit total").map(drop)?;
      ensure(output.contains("Exact duplicates: 5 groups"), "render the exact-group count").map(drop)?;
      ensure(output.contains("Near duplicates:  3 groups"), "render the near-group count").map(drop)?;
      ensure(output.contains("Duplicated lines (exact): 61"), "render exact duplicate lines").map(drop)?;
      ensure(output.contains("Duplicated lines (near):  43"), "render near duplicate lines").map(drop)?;
      ensure(
        output.contains("Duplication: 6.1% exact, 4.3% near (of 1,000 total lines)"),
        "render both percentages with one decimal place and group the total source-line count",
      )
      .map(drop)
    })
  }

  /// Empty AST sections show their messages while empty sub-function sections emit no bytes.
  #[test]
  fn empty_sections_follow_their_presentation_contract() -> Result<(), ReportTestFailure> {
    let reporter = TextReporter::new(None);
    for (section, expected) in [
      (ReportSection::Exact, "No exact duplicates found.\n"),
      (ReportSection::Near, "No near duplicates found.\n"),
      (ReportSection::SubExact, ""),
      (ReportSection::SubNear, ""),
    ] {
      let rendered = render_text(|writer| reporter.report_groups(&[], writer, section))?;
      ensure_eq(rendered, expected.to_owned(), "render the section's documented empty state").map(drop)?;
    }
    Ok(())
  }

  /// Visible exact groups retain their identity, relative locations, and each member's suppression.
  #[test]
  fn text_report_exact_with_groups() -> Result<(), ReportTestFailure> {
    let reporter = TextReporter::new(Some(PathBuf::from("/project")));
    let mut tagged = make_unit("foo", "/project/src/a.rs", 10, 20);
    tagged.suppressed = Some(RuleId::AstForwardingAccessor);
    let group = exact_group(vec![tagged, make_unit("bar", "/project/src/b.rs", 30, 40)]);
    let fingerprint = group.fingerprint;
    let expected = format!(
      "Exact Duplicates\n================\n\nGroup 1 (fingerprint: {fingerprint}, 2 members):\n  - foo (function) at src/a.rs:10-20 \
       [suppressed: ast.forwarding-accessor]\n  - bar (function) at src/b.rs:30-40\n\n"
    );
    let rendered = render_text(|writer| reporter.report_exact(&[group], writer))?;
    ensure_eq(
      rendered,
      expected,
      "a visible mixed group retains its complete identity and locations while attributing suppression only to the tagged member",
    )
    .map(drop)
    .map_err(ReportTestFailure::from)
  }

  /// Near groups retain their content identity, score, and member locations.
  #[test]
  fn text_report_near_with_groups() -> Result<(), ReportTestFailure> {
    let reporter = TextReporter::new(None);
    let fp = block_fingerprint();
    let group = near_group(fp, 0.85, vec![
      make_unit("process", "/src/a.rs", 10, 25),
      make_unit("compute", "/src/b.rs", 30, 45),
    ]);
    let rendered = render_text(|writer| reporter.report_near(&[group], writer))?;
    check_text(rendered, |output| {
      ensure(output.contains(&format!("fingerprint: {fp}")), "render the near-group identity").map(drop)?;
      ensure(output.contains("85%"), "render near similarity as a percentage").map(drop)?;
      ensure(
        output.contains("process (function) at /src/a.rs:10-25"),
        "retain the first near member's location",
      )
      .map(drop)?;
      ensure(
        output.contains("compute (function) at /src/b.rs:30-45"),
        "retain the second near member's location",
      )
      .map(drop)
    })
  }

  /// Full reports dispatch AST and sub-function sections with their identities and parent names.
  #[test]
  fn text_report_full_includes_stats_and_group_sections() -> Result<(), ReportTestFailure> {
    let reporter = TextReporter::new(None);
    let mut result = analysis_result(
      with_duplicate_lines(stats(4, 200, 1, 2, 1, 2), 20, 15),
      vec![exact_group(vec![
        make_unit("foo", "/src/a.rs", 1, 10),
        make_unit("bar", "/src/b.rs", 20, 30),
      ])],
      vec![near_group(block_fingerprint(), 0.8, vec![
        make_unit("process", "/src/c.rs", 40, 50),
        make_unit("compute", "/src/d.rs", 60, 70),
      ])],
      Vec::new(),
    );
    let mut first_branch = make_unit("then branch", "/src/e.rs", 80, 85);
    first_branch.kind = CodeUnitKind::IfBranch;
    first_branch.parent_name = Some("validate".to_owned());
    let mut second_branch = make_unit("else branch", "/src/f.rs", 100, 105);
    second_branch.kind = CodeUnitKind::IfBranch;
    second_branch.parent_name = Some("prepare".to_owned());
    let mut sub_near = near_group(block_fingerprint(), 0.75, vec![first_branch, second_branch]);
    sub_near.dimension = DetectionDimension::SubAst;
    let sub_fingerprint = sub_near.fingerprint;
    result.sub_near_groups.push(sub_near);
    result.stats.sub_near_groups = 1;
    result.stats.sub_near_units = 2;
    let rendered = render_text(|writer| reporter.report_full(&result, writer))?;
    check_text(rendered, |output| {
      ensure(
        output.contains("Duplication Statistics"),
        "include statistics in the complete report",
      )
      .map(drop)?;
      ensure(output.contains("Exact Duplicates"), "include the exact group section").map(drop)?;
      ensure(output.contains("Near Duplicates"), "include the near group section").map(drop)?;
      ensure(output.contains("process"), "include members of near groups").map(drop)?;
      ensure(
        output.contains(&format!(
          "Sub-function Near Duplicates\n============================\n\nGroup 1 (fingerprint: {sub_fingerprint}, similarity: 75%, 2 \
           members):\n  - then branch (if branch) in validate at /src/e.rs:80-85\n  - else branch (if branch) in prepare at \
           /src/f.rs:100-105\n\n"
        )),
        "a full report must retain the sub-function near section, group identity, score, member spans, and parent names",
      )
      .map(drop)
    })
  }

  /// Member paths below the configured report root are displayed relative to it.
  #[test]
  fn relative_path_stripping() -> Result<(), ComparisonFailure<String, &'static str>> {
    let base = PathBuf::from("/project");
    let result = display_path(Some(base.as_path()), Path::new("/project/src/main.rs"));
    ensure_eq(
      result.into_owned(),
      "src/main.rs",
      "strip the configured base path from a nested source path",
    )
    .map(drop)
  }
}
