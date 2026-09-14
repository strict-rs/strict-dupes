//! Self-corpus regression gates: consolidated source must not re-group,
//! and registered fixture duplicates must remain detectable.
//!
//! The pinned command excludes `refactor/` and both CLI fixture trees so the
//! corpus is the product code itself. The dupes-treesitter
//! `normalize_as_block` and dispatch-return consolidations are pinned by
//! unit tests next to their code, not here.
//!
//! Sub-units and windows carry generic names ("if-then branch", "line
//! window") and the JSON member surface does not include the parent, so the
//! fn-interior sites are pinned by line span against the current source; the
//! top-level units (the override helpers, closures) are pinned by name.
//!
//! Allowance validation uses the full corpus and configured check defaults,
//! including fixture projects. Stale-entry diagnostics fail the test without
//! rewriting either fixtures or the registry.

mod source_spans;

use std::num::TryFromIntError;
use std::path::PathBuf;

use dupes_cli_test_support::CliTestFailure;
use dupes_cli_test_support::assert_member_needles_absent;
use dupes_cli_test_support::cargo_dupes;
use dupes_cli_test_support::check_json;
use dupes_cli_test_support::json_array;
use dupes_cli_test_support::json_count;
use dupes_cli_test_support::json_field;
use dupes_cli_test_support::json_from_stdout;
use dupes_cli_test_support::json_text;
use dupes_cli_test_support::run_for_path;
use dupes_cli_test_support::workspace_root;
use serde_json::Value;
use strict_test_support::ensure;

/// Product-source report used by the consolidation gate.
const SELF_CORPUS_ARGS: &[&str] = &[
  "--exclude", "refactor", "--exclude", "cargo-dupes/tests/fixtures", "--exclude", "code-dupes/tests/fixtures", "--sub-function",
  "--format", "json", "report",
];

/// The consolidated sites: (workspace-relative file, fn name).
const CONSOLIDATED_FN_SITES: &[(&str, &str)] = &[
  ("dupes-core/src/cli.rs", "cmd_check"),
  ("dupes-core/src/output/text.rs", "report_stats"),
  ("dupes-core/src/extractor.rs", "add_if_branches"),
  ("dupes-core/src/config.rs", "override_with"),
  ("dupes-core/src/config.rs", "override_option"),
];

/// Native evidence from preparing the source-location oracle or checking the report.
#[derive(Debug, thiserror::Error)]
enum CorpusFailure {
  /// Shared command or report check failed.
  #[error(transparent)]
  Cli(#[from] CliTestFailure),
  /// A source function could not be located uniquely.
  #[error("could not locate the consolidated source in `{}`: {source}", path.display())]
  Source {
    /// Complete source path.
    path:   PathBuf,
    /// Original source read, parse, or selection failure.
    source: source_spans::FunctionFailure,
  },
  /// The host's source-line index cannot be represented in the report's numeric format.
  #[error(transparent)]
  Line(#[from] TryFromIntError),
}

/// Every registered fixture duplicate remains live under the repository's check configuration.
#[test]
fn fixture_allowances_remain_live() -> Result<(), CliTestFailure> {
  let root = workspace_root()?;
  run_for_path(cargo_dupes, &root, &["cleanup", "--dry-run"])?
    .try_success()?
    .try_stdout("No stale entries found.\n")
    .map(drop)
    .map_err(CliTestFailure::from)
}

#[test]
fn consolidated_sites_stay_consolidated() -> Result<(), CorpusFailure> {
  let root = workspace_root()?;
  let assertion = run_for_path(cargo_dupes, &root, SELF_CORPUS_ARGS)?
    .try_success()
    .map_err(CliTestFailure::from)?;
  let report = json_from_stdout(&assertion.get_output().stdout).map_err(|source| CliTestFailure::Output {
    captured: Box::new(assertion),
    source:   Box::new(source),
  })?;

  let sites = CONSOLIDATED_FN_SITES
    .iter()
    .map(|&(file, fn_name)| {
      let path = root.join(file);
      let span = source_spans::function_span(&path, fn_name).map_err(|source| CorpusFailure::Source {
        path,
        source,
      })?;
      Ok((file, fn_name, u64::try_from(span.start().line)?, u64::try_from(span.end().line)?))
    })
    .collect::<Result<Vec<_>, CorpusFailure>>()?;

  check_json(report, |document| {
    // Top-level units named after consolidated fns must not group anywhere
    // in dupes-core ("override_" covers override_with/override_option).
    assert_member_needles_absent(
      document,
      &["cmd_check", "report_stats", "add_if_branches", "override_"],
      "dupes-core/src",
      "re-grouped: consolidated units must stay consolidated",
    )?;

    // No visible member of any dimension may lie inside a consolidated fn.
    // The member-fingerprint projection consolidation: no visible group may
    // pair closures across grouper.rs and lib.rs again.
    for group in json_array(json_field(document, "groups")?)? {
      check_member_spans(document, group, &sites)?;
      ensure(
        !(group_has_closure_in(group, "dupes-core/src/grouper.rs")? && group_has_closure_in(group, "dupes-core/src/lib.rs")?),
        "closures re-grouped across grouper.rs and lib.rs",
      )
      .map(drop)?;
    }
    Ok(())
  })
  .map_err(CorpusFailure::from)
}

/// Reject visible members that overlap any protected function definition.
#[allow(
  clippy::single_call_fn,
  reason = "the self-corpus gate names its source-span overlap contract separately from cross-file group checks"
)]
fn check_member_spans(document: &Value, group: &Value, sites: &[(&str, &str, u64, u64)]) -> Result<(), CliTestFailure> {
  for member in json_array(json_field(group, "members")?)? {
    let file = json_text(json_field(member, "file")?)?;
    for &(relative_path, fn_name, start, end) in sites {
      if !file.ends_with(relative_path) {
        continue;
      }
      let member_start = json_count(member, "line_start")?;
      let member_end = json_count(member, "line_end")?;
      if member_end >= start && member_start <= end {
        return Err(CliTestFailure::UnexpectedMember {
          report:      document.clone(),
          needle:      fn_name.to_owned(),
          file_needle: relative_path.to_owned(),
          why:         "re-grouped inside a consolidated function definition".to_owned(),
        });
      }
    }
  }
  Ok(())
}

/// True when the group has a closure-named member in the given file.
fn group_has_closure_in(group: &Value, file_needle: &str) -> Result<bool, CliTestFailure> {
  for member in json_array(json_field(group, "members")?)? {
    if json_text(json_field(member, "name")?)?.contains("closure") && json_text(json_field(member, "file")?)?.ends_with(file_needle) {
      return Ok(true);
    }
  }
  Ok(false)
}
