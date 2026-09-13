//! Shared integration-test support for the `cargo-dupes` and `code-dupes`
//! CLIs: `assert_cmd` command factories, fixture path resolution, JSON
//! report helpers, and the [`cli_support_tests!`] macro that stamps the
//! shared CLI test suite into both binaries' test crates.

mod error;

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process;

use assert_cmd::Command;
use assert_cmd::assert::Assert;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use serde_json::Value;
use strict_test_support::ensure;
use tempfile::TempDir;

pub use crate::error::CliTestFailure;

/// Constructor of a fresh [`assert_cmd::Command`] for the CLI binary under test.
///
/// Every shared helper takes one so the same test body runs against both binaries;
/// [`cargo_dupes`] and [`code_dupes`] are the two factories the binaries' test crates pass in.
pub type CommandFactory = fn() -> Result<Command, CliTestFailure>;

/// Stamps one named `#[test]` that runs a shared helper against a CLI command factory,
/// forwarding any trailing arguments to the helper.
///
/// The single-test companion to [`cli_support_tests!`] for suites that pin only one shared case.
#[macro_export]
macro_rules! cli_support_test {
    ($name:ident, $command:path, $helper:path $(, $arg:expr)* $(,)?) => {
        #[doc = concat!("Exercise the shared CLI contract `", stringify!($helper), "`.")]
        #[test]
        fn $name() -> Result<(), $crate::CliTestFailure> {
            $helper($command $(, $arg)*)
        }
    };
}

/// Stamps a block of the shared CLI suite into a binary's integration-test crate.
///
/// The leading path names the crate's [`CommandFactory`]; each `name => helper;` line becomes a
/// `#[test]` invoking that shared helper against the factory. A trailing parenthesized argument
/// list forwards binary-specific inputs (such as the binary's expected stderr diagnostic) to the
/// helper after the factory.
///
/// Named suites (`check`, `ignore`, `options`, `report`, and `sub_function`) keep both binaries'
/// test membership identical. The `options` suite also accepts generic-dimension filtering and
/// the binary's missing-source diagnostic.
#[macro_export]
macro_rules! cli_support_tests {
    (check, $command:path) => {
        $crate::cli_support_tests! {
            $command;
            check_no_thresholds_passes_with_duplicates => $crate::check_no_thresholds_passes_with_duplicates;
            check_fails_with_duplicates => $crate::check_fails_with_duplicates;
            check_passes_with_high_threshold => $crate::check_passes_with_high_threshold;
            check_no_dupes_passes => $crate::check_no_dupes_passes;
            check_fails_with_percentage_threshold_exceeded => $crate::check_fails_with_percentage_threshold_exceeded;
            check_passes_with_generous_percentage_threshold => $crate::check_passes_with_generous_percentage_threshold;
            check_absolute_passes_percentage_fails => $crate::check_absolute_passes_percentage_fails;
        }
    };
    (ignore, $command:path) => {
        $crate::cli_support_tests! {
            $command;
            ignore_workflow => $crate::ignore_workflow;
            ignore_near_duplicate_workflow => $crate::ignore_near_duplicate_workflow;
            cleanup_removes_stale_entries => $crate::cleanup_removes_stale_entries;
            cleanup_dry_run => $crate::cleanup_dry_run;
        }
    };
    (options, $command:path, $disable_generic:expr, $missing_source:expr) => {
        $crate::cli_support_tests! {
            $command;
            min_nodes_option => $crate::min_nodes_option;
            min_lines_option => $crate::min_lines_option;
            exclude_option => $crate::exclude_option($disable_generic, "No source files");
            exclude_tests_flag_reduces_duplicates => $crate::exclude_tests_flag_reduces_duplicates;
            exclude_tests_text_report => $crate::exclude_tests_text_report;
            dimension_option_limits_reported_dimensions => $crate::dimension_option_limits_reported_dimensions;
            error_on_nonexistent_path => $crate::error_on_nonexistent_path($missing_source);
            help_works => $crate::help_works;
            version_works => $crate::version_works;
            invalid_arguments_use_stderr => $crate::invalid_arguments_use_stderr;
            help_write_failure_is_reported => $crate::help_write_failure_is_reported;
        }
    };
    (report, $command:path) => {
        $crate::cli_support_tests! {
            $command;
            report_exact_dupes_fixture => $crate::report_exact_dupes_fixture;
            report_no_dupes_fixture => $crate::report_no_dupes_fixture;
            report_mixed_fixture => $crate::report_mixed_fixture;
            stats_shows_summary => $crate::stats_shows_summary;
            stats_shows_duplicate_lines => $crate::stats_shows_duplicate_lines;
            default_command_is_report => $crate::default_command_is_report;
            near_dupes_detected => $crate::near_dupes_detected;
            json_format_stats => $crate::json_format_stats;
            json_format_report => $crate::json_format_report;
            json_decoder_retains_text_report => $crate::json_decoder_retains_text_report;
            json_stats_includes_line_counts => $crate::json_stats_includes_line_counts;
        }
    };
    (sub_function, $command:path) => {
        $crate::cli_support_tests! {
            $command;
            sub_function_detects_duplicate_branches => $crate::sub_function_detects_duplicate_branches;
            sub_function_shows_parent_names => $crate::sub_function_shows_parent_names;
            sub_function_stats_shown => $crate::sub_function_stats_shown;
            sub_function_json_stats => $crate::sub_function_json_stats;
            without_sub_function_flag_no_sub_sections => $crate::without_sub_function_flag_no_sub_sections;
            without_sub_function_json_no_sub_fields => $crate::without_sub_function_json_no_sub_fields;
            sub_function_min_sub_nodes_filters => $crate::sub_function_min_sub_nodes_filters;
        }
    };
    ($command:path; $($name:ident => $helper:ident $(::$segment:ident)* $(($($arg:expr),* $(,)?))?;)+) => {
        #[cfg(test)]
        mod tests {
        $(
            #[doc = concat!("Exercise the shared CLI contract `", stringify!($helper $(::$segment)*), "`.")]
            #[test]
            fn $name() -> Result<(), $crate::CliTestFailure> {
                $helper $(::$segment)*($command $(, $($arg),*)?)
            }
        )+
        }
    };
}

/// One data-driven stdout expectation shared by both CLI binaries: run `fixture` with `args` and
/// require the expected exit status plus every stdout needle.
#[derive(Clone, Copy)]
struct StdoutCase {
  /// Shared Rust fixture directory name under `cargo-dupes/tests/fixtures/`.
  fixture: &'static str,
  /// CLI arguments appended after the fixture's `--path`.
  args:    &'static [&'static str],
  /// Expected exit code; `None` requires plain success.
  code:    Option<i32>,
  /// Substrings that must all appear in the run's stdout.
  needles: &'static [&'static str],
}

/// Path to the workspace root.
///
/// # Errors
///
/// Returns the complete manifest path if it has no workspace parent.
#[allow(
  clippy::single_call_fn,
  reason = "the self-corpus integration gate and fixture resolver share the workspace-root identity"
)]
pub fn workspace_root() -> Result<PathBuf, CliTestFailure> {
  let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  manifest.parent().map(Path::to_path_buf).ok_or(CliTestFailure::WorkspaceRoot {
    manifest,
  })
}

/// Path to `fixture` under `crate_name`'s `tests/fixtures/` directory.
fn fixture_path(crate_name: &str, fixture: &str) -> Result<PathBuf, CliTestFailure> {
  Ok(workspace_root()?.join(crate_name).join("tests").join("fixtures").join(fixture))
}

/// Path to a shared Rust fixture used by both CLI crates.
///
/// # Errors
/// Returns the workspace-root resolution failure.
pub fn rust_fixture_path(name: &str) -> Result<PathBuf, CliTestFailure> {
  fixture_path("cargo-dupes", name)
}

/// Path to a `code-dupes`-local fixture.
///
/// # Errors
/// Returns the workspace-root resolution failure.
pub fn code_fixture_path(name: &str) -> Result<PathBuf, CliTestFailure> {
  fixture_path("code-dupes", name)
}

/// Command for the compiled workspace binary identified by Cargo's runtime artifact variable.
fn compiled_binary(binary: &'static str) -> Result<Command, CliTestFailure> {
  let variable = format!("CARGO_BIN_EXE_{binary}");
  env::var_os(&variable).map(Command::new).ok_or(CliTestFailure::Binary {
    binary,
    variable,
  })
}

/// Command for running the `cargo-dupes` binary in integration tests.
///
/// # Errors
///
/// Returns the requested binary and missing Cargo runtime artifact variable.
pub fn cargo_dupes() -> Result<Command, CliTestFailure> {
  compiled_binary("cargo-dupes")
}

/// Command for running the `code-dupes` binary in integration tests.
///
/// # Errors
///
/// Returns the requested binary and missing Cargo runtime artifact variable.
pub fn code_dupes() -> Result<Command, CliTestFailure> {
  compiled_binary("code-dupes")
}

/// Execute one CLI command and expose its complete native output for fallible assertions.
///
/// # Errors
/// Returns binary-discovery or execution failure, preserving the prepared command on execution
/// failure.
#[allow(
  clippy::single_call_fn,
  reason = "The shared execution boundary retains the prepared command and native failure independently of fixture argument construction"
)]
pub fn run_command(command: CommandFactory, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<Assert, CliTestFailure> {
  let mut prepared = command()?;
  prepared
    .args(args)
    .output()
    .map(Assert::new)
    .map_err(|source| CliTestFailure::Command {
      command: Box::new(prepared),
      source,
    })
}

/// Execute a CLI against an arbitrary native path without converting it to UTF-8.
///
/// # Errors
/// Returns the complete binary-discovery or command execution failure.
#[allow(
  clippy::single_call_fn,
  reason = "Both CLI integration suites share native path argument construction independently of fixture lookup"
)]
pub fn run_for_path(command: CommandFactory, path: impl AsRef<Path>, args: &[&str]) -> Result<Assert, CliTestFailure> {
  run_command(
    command,
    [OsStr::new("--path"), path.as_ref().as_os_str()]
      .into_iter()
      .chain(args.iter().map(OsStr::new)),
  )
}

/// Execute a CLI against a shared Rust fixture.
///
/// # Errors
/// Returns fixture resolution, binary discovery, or execution failure.
pub fn run_for_fixture(command: CommandFactory, fixture: &str, args: &[&str]) -> Result<Assert, CliTestFailure> {
  run_for_path(command, rust_fixture_path(fixture)?, args)
}

/// Assert that a run's stdout contains every needle.
///
/// # Errors
///
/// Returns the native assertion failure, including captured output, when a needle is missing.
pub fn assert_stdout_contains(mut assertion: Assert, needles: &[&str]) -> Result<Assert, CliTestFailure> {
  for needle in needles {
    assertion = assertion.try_stdout(contains(*needle))?;
  }
  Ok(assertion)
}

/// Run one [`StdoutCase`] against the CLI, dispatching on its expected exit code.
fn assert_case(command: CommandFactory, case: &StdoutCase) -> Result<(), CliTestFailure> {
  let assertion = run_for_fixture(command, case.fixture, case.args)?;
  let status_checked = match case.code {
    Some(code) => assertion.try_code(code)?,
    None => assertion.try_success()?,
  };
  assert_stdout_contains(status_checked, case.needles).map(drop)
}

/// Stamps a documented `pub fn <name>(command: CommandFactory)` wrapper over [`assert_case`] for
/// each `name => CASE;` pair, so shared stdout cases stay declared as data.
macro_rules! stdout_case_helpers {
    ($($name:ident => $case:ident;)+) => {
        $(
            #[doc = concat!("Run the shared `", stringify!($case), "` stdout case against the CLI built by `command`.")]
            ///
            /// # Errors
            ///
            /// Returns preparation, execution, or expectation failure for the shared case.
            pub fn $name(command: CommandFactory) -> Result<(), CliTestFailure> {
                assert_case(command, &$case)
            }
        )+
    };
}

/// Parse a JSON document straight from captured stdout bytes.
///
/// # Errors
///
/// Preserves the complete input bytes and original parser failure when parsing fails.
#[allow(
  clippy::single_call_fn,
  reason = "shared fixtures and the self-corpus integration gate use the same native JSON decoding boundary"
)]
pub fn json_from_stdout(output: &[u8]) -> Result<Value, CliTestFailure> {
  serde_json::from_slice(output).map_err(|source| CliTestFailure::Json {
    input: output.to_vec(),
    source,
  })
}

/// Parsed JSON document from a successful CLI run against a shared fixture.
///
/// # Errors
///
/// Returns preparation, execution, status, or JSON parsing failure.
pub fn fixture_json(command: CommandFactory, fixture: &str, args: &[&str]) -> Result<Value, CliTestFailure> {
  let assertion = run_for_fixture(command, fixture, args)?.try_success()?;
  json_from_stdout(&assertion.get_output().stdout).map_err(|source| CliTestFailure::Output {
    captured: Box::new(assertion),
    source:   Box::new(source),
  })
}

/// Supplying text output to the JSON helper retains the successful command and native decoder
/// error.
///
/// # Errors
/// Returns the complete unexpected command or decoding failure, or an unexpectedly accepted
/// document.
pub fn json_decoder_retains_text_report(command: CommandFactory) -> Result<(), CliTestFailure> {
  match fixture_json(command, "exact_dupes", &["report"]) {
    Err(failure) => {
      if let CliTestFailure::Output {
        ref captured,
        source: ref decoding,
      } = failure
      {
        let output = captured.get_output();
        if output.status.success()
          && !output.stdout.is_empty()
          && output.stderr.is_empty()
          && matches!(**decoding, CliTestFailure::Json { ref input, source: ref parser }
            if input == &output.stdout && parser.is_syntax())
        {
          return Ok(());
        }
      }
      Err(failure)
    }
    Ok(document) => Err(CliTestFailure::JsonShape {
      document,
      context: "text output must be rejected by the JSON decoder",
    }),
  }
}

/// All groups of one detection dimension from a JSON `report` document.
///
/// # Errors
/// Returns the complete invalid field or object when the report shape is malformed.
pub fn groups_of_dimension<'a>(report: &'a Value, dimension: &str) -> Result<Vec<&'a Value>, CliTestFailure> {
  let mut selected = Vec::new();
  for group in json_array(json_field(report, "groups")?)? {
    if json_text(json_field(group, "dimension")?)? == dimension {
      selected.push(group);
    }
  }
  Ok(selected)
}

/// First group with a member matching both name and file needles.
///
/// # Errors
/// Returns malformed report fields instead of interpreting them as absent members.
#[allow(
  clippy::single_call_fn,
  reason = "detector-coverage integration tests and shared consolidation checks query the same member identity"
)]
pub fn group_containing_member<'a>(report: &'a Value, name_needle: &str, file_needle: &str) -> Result<Option<&'a Value>, CliTestFailure> {
  for group in json_array(json_field(report, "groups")?)? {
    for member in json_array(json_field(group, "members")?)? {
      let name = json_text(json_field(member, "name")?)?;
      let file = json_text(json_field(member, "file")?)?;
      if name.contains(name_needle) && file.contains(file_needle) {
        return Ok(Some(group));
      }
    }
  }
  Ok(None)
}

/// Assert no visible group has a member matching any needle in files
/// matching `file_needle`; `why` finishes the failure message after the
/// offending needle.
///
/// # Errors
///
/// Preserves the complete report and matching inputs when a member remains visible.
pub fn assert_member_needles_absent(report: &Value, needles: &[&str], file_needle: &str, why: &str) -> Result<(), CliTestFailure> {
  for needle in needles {
    if group_containing_member(report, needle, file_needle)?.is_some() {
      return Err(CliTestFailure::UnexpectedMember {
        report:      report.clone(),
        needle:      (*needle).to_owned(),
        file_needle: file_needle.to_owned(),
        why:         why.to_owned(),
      });
    }
  }
  Ok(())
}

/// Suppressed count attributed to one rule id in a stats document, zero when
/// the stats document carries no suppression surface.
///
/// # Errors
/// Returns a malformed attribution object or invalid count instead of interpreting it as zero.
pub fn suppressed_count_for_rule(stats: &Value, rule_id: &str) -> Result<u64, CliTestFailure> {
  let Some(counts) = stats.get("suppressed_by_rule") else {
    return Ok(0);
  };
  let rules = counts.as_object().ok_or_else(|| CliTestFailure::JsonShape {
    document: counts.clone(),
    context:  "suppression attribution must be an object",
  })?;
  if rules.contains_key(rule_id) {
    json_count(counts, rule_id)
  } else {
    Ok(0)
  }
}

/// Stdout of a successful CLI run against an arbitrary path.
///
/// # Errors
///
/// Returns preparation, execution, status, or UTF-8 decoding failure.
pub fn path_stdout(command: CommandFactory, path: impl AsRef<Path>, args: &[&str]) -> Result<String, CliTestFailure> {
  let assertion = run_for_path(command, path, args)?.try_success()?;
  String::from_utf8(assertion.get_output().stdout.clone()).map_err(|source| CliTestFailure::Output {
    captured: Box::new(assertion),
    source:   Box::new(CliTestFailure::Utf8(source)),
  })
}

/// Assert that a run against an arbitrary path succeeds with every stdout needle present.
///
/// # Errors
///
/// Returns preparation, execution, status, or stdout assertion failure.
pub fn assert_path_success_stdout(
  command: CommandFactory,
  path: impl AsRef<Path>,
  args: &[&str],
  needles: &[&str],
) -> Result<(), CliTestFailure> {
  assert_stdout_contains(run_for_path(command, path, args)?.try_success()?, needles).map(drop)
}

/// Extract the fingerprint a user would copy from a text report: the first `fingerprint:` line,
/// restricted to near-duplicate lines (those also carrying `similarity:`) when
/// `require_similarity` is set.
///
/// # Errors
///
/// Retains the complete report and requested kind when no copyable fingerprint is present.
pub fn report_fingerprint(text: &str, require_similarity: bool) -> Result<String, CliTestFailure> {
  text
    .lines()
    .find(|line| line.contains("fingerprint:") && (!require_similarity || line.contains("similarity:")))
    .and_then(|line| {
      let (_, fingerprint_tail) = line.split_once("fingerprint: ")?;
      let (fingerprint, _) = fingerprint_tail.split_once(',')?;
      Some(fingerprint.to_owned())
    })
    .ok_or_else(|| CliTestFailure::ReportFingerprint {
      report: text.to_owned(),
      require_similarity,
    })
}

/// Temp-dir copy of a shared fixture's `src/lib.rs`, so ignore-file workflows write their
/// `.dupes-ignore.toml` into a scratch project instead of the repo's own fixtures.
///
/// # Errors
///
/// Returns native allocation or filesystem failures with their operation paths.
pub fn temp_copy_fixture(fixture: &str) -> Result<TempDir, CliTestFailure> {
  let directory = TempDir::new().map_err(|source| CliTestFailure::TemporaryDirectory {
    source,
  })?;
  let source_path = rust_fixture_path(fixture)?.join("src/lib.rs");
  let contents = fs::read(&source_path).map_err(|source| CliTestFailure::Fixture {
    path: source_path,
    source,
  })?;
  let source_directory = directory.path().join("src");
  fs::create_dir_all(&source_directory).map_err(|source| CliTestFailure::Fixture {
    path: source_directory,
    source,
  })?;
  let destination = directory.path().join("src/lib.rs");
  write_fixture(&destination, contents)?;
  Ok(directory)
}

/// Borrow a required field while preserving its complete object on failure.
///
/// # Errors
/// Returns the inspected object and absent field name.
pub fn json_field<'a>(document: &'a Value, field: &str) -> Result<&'a Value, CliTestFailure> {
  document.get(field).ok_or_else(|| CliTestFailure::JsonField {
    document: document.clone(),
    field:    field.to_owned(),
  })
}

/// Borrow an array from a report field.
///
/// # Errors
/// Returns the complete field when it is not an array.
pub fn json_array(document: &Value) -> Result<&[Value], CliTestFailure> {
  document.as_array().map(Vec::as_slice).ok_or_else(|| CliTestFailure::JsonShape {
    document: document.clone(),
    context:  "field must be an array",
  })
}

/// Borrow text from a report field.
///
/// # Errors
/// Returns the complete field when it is not a string.
pub fn json_text(document: &Value) -> Result<&str, CliTestFailure> {
  document.as_str().ok_or_else(|| CliTestFailure::JsonShape {
    document: document.clone(),
    context:  "field must be a string",
  })
}

/// Read an unsigned count from a report object.
///
/// # Errors
/// Returns a missing-field failure or the complete invalid count.
pub fn json_count(document: &Value, field: &str) -> Result<u64, CliTestFailure> {
  let count = json_field(document, field)?;
  count.as_u64().ok_or_else(|| CliTestFailure::JsonShape {
    document: count.clone(),
    context:  "count must be an unsigned integer",
  })
}

/// Preserve the complete parsed report when one of its semantic checks fails.
///
/// # Errors
/// Returns the complete report together with the original failed check.
pub fn check_json(document: Value, check: impl FnOnce(&Value) -> Result<(), CliTestFailure>) -> Result<(), CliTestFailure> {
  check(&document).map_err(|source| CliTestFailure::Report {
    document,
    source: Box::new(source),
  })
}

/// `check` with no thresholds passes even though the fixture has duplicates.
const CHECK_NO_THRESHOLDS_PASSES_WITH_DUPLICATES: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["check"],
  code:    None,
  needles: &["Check passed"],
};

/// `check --max-exact 0` fails (exit 1) on the duplicated fixture.
const CHECK_FAILS_WITH_DUPLICATES: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["check", "--max-exact", "0"],
  code:    Some(1),
  needles: &["Check FAILED"],
};

/// `check` passes when the exact-duplicate ceiling is generous.
const CHECK_PASSES_WITH_HIGH_THRESHOLD: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["check", "--max-exact", "100"],
  code:    None,
  needles: &["Check passed"],
};

/// `check --max-exact 0` passes on a fixture with no duplicates.
const CHECK_NO_DUPES_PASSES: StdoutCase = StdoutCase {
  fixture: "no_dupes",
  args:    &["check", "--max-exact", "0"],
  code:    None,
  needles: &["Check passed"],
};

/// `check` fails once the exact duplicate-line percentage ceiling is exceeded.
const CHECK_FAILS_WITH_PERCENTAGE_THRESHOLD_EXCEEDED: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["check", "--max-exact", "100", "--max-exact-percent", "0.0"],
  code:    Some(1),
  needles: &["Check FAILED", "exact duplicate lines"],
};

/// `check` passes when the percentage ceiling admits all duplicated lines.
const CHECK_PASSES_WITH_GENEROUS_PERCENTAGE_THRESHOLD: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["check", "--max-exact", "100", "--max-exact-percent", "100.0"],
  code:    None,
  needles: &["Check passed"],
};

/// `check` still fails when the absolute ceiling passes but the percentage ceiling does not.
const CHECK_ABSOLUTE_PASSES_PERCENTAGE_FAILS: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["check", "--max-exact", "100", "--max-exact-percent", "0.0"],
  code:    Some(1),
  needles: &["Check FAILED"],
};

/// `report` renders an exact-duplicates section with numbered groups.
const REPORT_EXACT_DUPES_FIXTURE: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["report"],
  code:    None,
  needles: &["Exact Duplicates", "Group 1"],
};

/// `report` states that a clean fixture has no exact duplicates.
const REPORT_NO_DUPES_FIXTURE: StdoutCase = StdoutCase {
  fixture: "no_dupes",
  args:    &["report"],
  code:    None,
  needles: &["No exact duplicates"],
};

/// `report` still renders exact groups on the mixed exact/near fixture.
const REPORT_MIXED_FIXTURE: StdoutCase = StdoutCase {
  fixture: "mixed",
  args:    &["report"],
  code:    None,
  needles: &["Exact Duplicates", "Group 1"],
};

/// `stats` renders the analyzed-unit total and the exact-duplicate summary line.
const STATS_SHOWS_SUMMARY: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["stats"],
  code:    None,
  needles: &["Total code units analyzed", "Exact duplicates"],
};

/// `stats` renders both the exact and the near duplicated-line counts.
const STATS_SHOWS_DUPLICATE_LINES: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["stats"],
  code:    None,
  needles: &["Duplicated lines (exact):", "Duplicated lines (near):"],
};

/// With no subcommand the CLI renders the full report (stats plus groups).
const DEFAULT_COMMAND_IS_REPORT: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &[],
  code:    None,
  needles: &["Duplication Statistics", "Exact Duplicates"],
};

/// A lowered `--threshold` surfaces near-duplicate groups with similarity scores.
const NEAR_DUPES_DETECTED: StdoutCase = StdoutCase {
  fixture: "near_dupes",
  args:    &["--threshold", "0.7", "report"],
  code:    None,
  needles: &["Near Duplicates", "Group 1", "similarity:"],
};

/// An extreme `--min-nodes` floor filters every duplicate group out.
const MIN_NODES_OPTION: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["--min-nodes", "1000", "stats"],
  code:    None,
  needles: &["Exact duplicates: 0 groups"],
};

/// An extreme `--min-lines` floor filters every duplicate group out.
const MIN_LINES_OPTION: StdoutCase = StdoutCase {
  fixture: "exact_dupes",
  args:    &["--min-lines", "1000", "stats"],
  code:    None,
  needles: &["Exact duplicates: 0 groups"],
};

/// `--exclude-tests` still reports the fixture's non-test duplicates in the text report.
const EXCLUDE_TESTS_TEXT_REPORT: StdoutCase = StdoutCase {
  fixture: "test_code",
  args:    &["--exclude-tests", "report"],
  code:    None,
  needles: &["Exact Duplicates", "Group 1"],
};

/// `--sub-function report` surfaces duplicated branch, match-arm, and loop-body units.
const SUB_FUNCTION_DETECTS_DUPLICATE_BRANCHES: StdoutCase = StdoutCase {
  fixture: "sub_function_dupes",
  args:    &["--sub-function", "report"],
  code:    None,
  needles: &["Sub-function Exact Duplicates", "if-then branch", "match arm", "for body"],
};

/// Sub-function members name the function that owns each duplicated region.
const SUB_FUNCTION_SHOWS_PARENT_NAMES: StdoutCase = StdoutCase {
  fixture: "sub_function_dupes",
  args:    &["--sub-function", "report"],
  code:    None,
  needles: &[
    "in handle_positive", "in process_value", "in classify_number", "in describe_value",
  ],
};

/// `--sub-function stats` counts the fixture's sub-function exact groups.
const SUB_FUNCTION_STATS_SHOWN: StdoutCase = StdoutCase {
  fixture: "sub_function_dupes",
  args:    &["--sub-function", "stats"],
  code:    None,
  needles: &["Sub-function exact: 3 groups"],
};

stdout_case_helpers! {
    check_no_thresholds_passes_with_duplicates => CHECK_NO_THRESHOLDS_PASSES_WITH_DUPLICATES;
    check_fails_with_duplicates => CHECK_FAILS_WITH_DUPLICATES;
    check_passes_with_high_threshold => CHECK_PASSES_WITH_HIGH_THRESHOLD;
    check_no_dupes_passes => CHECK_NO_DUPES_PASSES;
    check_fails_with_percentage_threshold_exceeded => CHECK_FAILS_WITH_PERCENTAGE_THRESHOLD_EXCEEDED;
    check_passes_with_generous_percentage_threshold => CHECK_PASSES_WITH_GENEROUS_PERCENTAGE_THRESHOLD;
    check_absolute_passes_percentage_fails => CHECK_ABSOLUTE_PASSES_PERCENTAGE_FAILS;
    report_exact_dupes_fixture => REPORT_EXACT_DUPES_FIXTURE;
    report_no_dupes_fixture => REPORT_NO_DUPES_FIXTURE;
    report_mixed_fixture => REPORT_MIXED_FIXTURE;
    stats_shows_summary => STATS_SHOWS_SUMMARY;
    stats_shows_duplicate_lines => STATS_SHOWS_DUPLICATE_LINES;
    default_command_is_report => DEFAULT_COMMAND_IS_REPORT;
    near_dupes_detected => NEAR_DUPES_DETECTED;
}

/// `--format json stats` emits a document with a positive analyzed-unit total.
///
/// # Errors
///
/// Returns the run or report-check failure with its native evidence.
pub fn json_format_stats(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(fixture_json(command, "exact_dupes", &["--format", "json", "stats"])?, |report| {
    ensure(json_count(report, "total_code_units")? > 0, "stats must count analyzed code units")?;
    Ok(())
  })
}

/// `--format json report` nests the stats document and renders every group with its fingerprint,
/// dimension, match kind, and members.
///
/// # Errors
///
/// Returns the run or report-check failure with its native evidence.
pub fn json_format_report(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(fixture_json(command, "exact_dupes", &["--format", "json", "report"])?, |report| {
    let stats = json_field(report, "stats")?;
    ensure(json_count(stats, "total_code_units")? > 0, "report stats must count analyzed units")?;
    ensure(
      json_count(stats, "exact_duplicate_groups")? > 0,
      "report stats must count exact groups",
    )?;
    let groups = json_array(json_field(report, "groups")?)?;
    ensure(!groups.is_empty(), "the duplicated fixture must produce groups")?;
    for group in groups {
      ensure(json_field(group, "fingerprint")?.is_string(), "group fingerprints must be strings")?;
      ensure(json_field(group, "dimension")?.is_string(), "group dimensions must be strings")?;
      ensure(json_field(group, "match_kind")?.is_string(), "group match kinds must be strings")?;
      ensure(json_field(group, "members")?.is_array(), "group members must be arrays")?;
    }
    Ok(())
  })
}

/// The JSON stats document carries the exact and near duplicated-line counts.
///
/// # Errors
///
/// Returns the run or report-check failure with its native evidence.
pub fn json_stats_includes_line_counts(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(fixture_json(command, "exact_dupes", &["--format", "json", "stats"])?, |report| {
    ensure(
      json_field(report, "exact_duplicate_lines")?.is_u64(),
      "exact duplicate lines must be an unsigned count",
    )?;
    ensure(
      json_field(report, "near_duplicate_lines")?.is_u64(),
      "near duplicate lines must be an unsigned count",
    )?;
    Ok(())
  })
}

stdout_case_helpers! {
    min_nodes_option => MIN_NODES_OPTION;
    min_lines_option => MIN_LINES_OPTION;
}

/// Excluding the fixture's only source file makes the run exit 2 with `expected_stderr`.
///
/// `disable_generic_dimensions` first turns off the token and line dimensions for binaries whose
/// generic window scan accepts non-Rust files (`code-dupes` would otherwise keep analyzing the
/// fixture's `Cargo.toml` instead of failing).
///
/// # Errors
///
/// Returns preparation, execution, status, or stderr assertion failure.
pub fn exclude_option(command: CommandFactory, disable_generic_dimensions: bool, expected_stderr: &str) -> Result<(), CliTestFailure> {
  let mut arguments = vec!["--exclude", "lib.rs"];
  if disable_generic_dimensions {
    arguments.extend([
      "--disable-dimension", "token-normalized", "--disable-dimension", "token-raw", "--disable-dimension", "line",
    ]);
  }
  arguments.push("stats");
  run_for_fixture(command, "exact_dupes", &arguments)?
    .try_code(2)?
    .try_stderr(contains(expected_stderr))
    .map(drop)
    .map_err(CliTestFailure::from)
}

/// `--exclude-tests` drops the fixture's test-code unit from both the duplicate and total counts.
///
/// # Errors
///
/// Returns the run or count-check failure with the complete affected report.
pub fn exclude_tests_flag_reduces_duplicates(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(fixture_json(command, "test_code", &["--format", "json", "stats"])?, |report| {
    ensure(
      json_count(report, "exact_duplicate_units")? == 3,
      "the unfiltered fixture includes its test duplicate",
    )?;
    Ok(())
  })?;
  check_json(
    fixture_json(command, "test_code", &["--exclude-tests", "--format", "json", "stats"])?,
    |report| {
      ensure(
        (
          json_count(report, "exact_duplicate_units")?,
          json_count(report, "total_code_units")?,
        ) == (2, 2),
        "excluding tests must preserve both non-test duplicates",
      )?;
      Ok(())
    },
  )
}

stdout_case_helpers! {
    exclude_tests_text_report => EXCLUDE_TESTS_TEXT_REPORT;
}

/// `--dimension line` restricts the report to line groups: line windows are still found while the
/// fixture's AST exact groups disappear from the stats.
///
/// # Errors
///
/// Returns the run or dimension-check failure with the complete affected report.
pub fn dimension_option_limits_reported_dimensions(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(
    fixture_json(command, "sub_function_dupes", &["--format", "json", "stats"])?,
    |report| {
      ensure(
        json_count(report, "exact_duplicate_groups")? > 0,
        "the fixture must have exact groups before dimension filtering",
      )?;
      Ok(())
    },
  )?;
  check_json(
    fixture_json(command, "sub_function_dupes", &[
      "--dimension", "line", "--line-min-lines", "3", "--format", "json", "report",
    ])?,
    |report| {
      let groups = json_array(json_field(report, "groups")?)?;
      ensure(!groups.is_empty(), "line-only analysis must report line duplicate groups")?;
      for group in groups {
        ensure(
          json_text(json_field(group, "dimension")?)? == "line",
          "line-only analysis must report only line groups",
        )?;
      }
      ensure(
        json_count(json_field(report, "stats")?, "exact_duplicate_groups")? == 0,
        "line-only analysis must omit AST exact groups",
      )?;
      Ok(())
    },
  )
}

/// A nonexistent `--path` exits 2 with the binary's own missing-source diagnostic
/// (`expected_stderr` differs because the two binaries fail at different pipeline stages).
///
/// # Errors
///
/// Returns preparation, execution, status, or stderr assertion failure.
pub fn error_on_nonexistent_path(command: CommandFactory, expected_stderr: &str) -> Result<(), CliTestFailure> {
  run_for_path(command, "/nonexistent/path/that/does/not/exist", &["stats"])?
    .try_code(2)?
    .try_stderr(contains(expected_stderr))
    .map(drop)
    .map_err(CliTestFailure::from)
}

/// `--help` succeeds without analyzing the requested path or writing to stderr.
///
/// # Errors
///
/// Returns preparation, execution, status, or stream assertion failure.
pub fn help_works(command: CommandFactory) -> Result<(), CliTestFailure> {
  run_for_path(command, "/nonexistent/path/that/does/not/exist", &["--help"])?
    .try_success()?
    .try_stderr("")?
    .try_stdout(contains("Detect duplicate code"))
    .map(drop)
    .map_err(CliTestFailure::from)
}

/// `--version` succeeds on stdout without starting analysis or emitting diagnostics.
///
/// # Errors
///
/// Returns preparation, execution, status, or stream assertion failure.
pub fn version_works(command: CommandFactory) -> Result<(), CliTestFailure> {
  run_for_path(command, "/nonexistent/path/that/does/not/exist", &["--version"])?
    .try_success()?
    .try_stderr("")?
    .try_stdout(contains(env!("CARGO_PKG_VERSION")))
    .map(drop)
    .map_err(CliTestFailure::from)
}

/// Invalid grammar and values retain Clap's stderr diagnostics and usage status.
///
/// # Errors
///
/// Returns preparation, execution, status, or stream assertion failure.
pub fn invalid_arguments_use_stderr(command: CommandFactory) -> Result<(), CliTestFailure> {
  let cases: [(&[&str], &str); 2] = [
    (&["--unknown-option"], "unexpected argument '--unknown-option'"),
    (&["--min-nodes", "invalid"], "invalid value 'invalid'"),
  ];
  for (arguments, diagnostic) in cases {
    run_for_path(command, "/nonexistent/path/that/does/not/exist", arguments)?
      .try_code(2)?
      .try_stdout("")?
      .try_stderr(contains(diagnostic).and(contains("Error: ").not()))
      .map(drop)?;
  }
  Ok(())
}

/// A stdout pipe without a reader makes help return a reporting failure with its native causes.
///
/// # Errors
///
/// Returns pipe creation, binary discovery, execution, or captured-output assertion failure.
pub fn help_write_failure_is_reported(command: CommandFactory) -> Result<(), CliTestFailure> {
  let (reader, writer) = io::pipe().map_err(|source| CliTestFailure::Pipe {
    source,
  })?;
  drop(reader);
  let binary = command()?;
  let mut prepared = process::Command::new(binary.get_program());
  let captured = prepared
    .arg("--help")
    .stdout(writer)
    .output()
    .map(Assert::new)
    .map_err(|source| CliTestFailure::Command {
      command: Box::new(Command::from_std(prepared)),
      source,
    })?;
  captured
    .try_code(1)?
    .try_stdout("")?
    .try_stderr(contains("Arguments").and(contains("DisplayHelp")).and(contains("source: Os")))
    .map(drop)
    .map_err(CliTestFailure::from)
}

stdout_case_helpers! {
    sub_function_detects_duplicate_branches => SUB_FUNCTION_DETECTS_DUPLICATE_BRANCHES;
    sub_function_shows_parent_names => SUB_FUNCTION_SHOWS_PARENT_NAMES;
    sub_function_stats_shown => SUB_FUNCTION_STATS_SHOWN;
}

/// `--sub-function` JSON stats pin the fixture's sub-function group and unit counts.
///
/// # Errors
///
/// Returns the run or count-check failure with the complete report.
pub fn sub_function_json_stats(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(
    fixture_json(command, "sub_function_dupes", &["--sub-function", "--format", "json", "stats"])?,
    |report| {
      ensure(
        (json_count(report, "sub_exact_groups")?, json_count(report, "sub_exact_units")?) == (3, 6),
        "sub-function stats must retain the fixture's three pairs",
      )?;
      Ok(())
    },
  )
}

/// Without `--sub-function` the text report renders no sub-function section.
///
/// # Errors
///
/// Returns preparation, execution, status, or section assertion failure.
pub fn without_sub_function_flag_no_sub_sections(command: CommandFactory) -> Result<(), CliTestFailure> {
  run_for_fixture(command, "sub_function_dupes", &["report"])?
    .try_success()?
    .try_stdout(contains("Exact Duplicates"))?
    .try_stdout(contains("Sub-function").not())
    .map(drop)
    .map_err(CliTestFailure::from)
}

/// Without `--sub-function` the JSON stats document omits the sub-function fields entirely.
///
/// # Errors
///
/// Returns the run or field-presence failure with the complete report.
pub fn without_sub_function_json_no_sub_fields(command: CommandFactory) -> Result<(), CliTestFailure> {
  check_json(
    fixture_json(command, "sub_function_dupes", &["--format", "json", "stats"])?,
    |report| {
      ensure(
        report.get("sub_exact_groups").is_none() && report.get("sub_near_groups").is_none(),
        "disabled sub-function analysis must omit its JSON stats fields",
      )?;
      Ok(())
    },
  )
}

/// An extreme `--min-sub-nodes` floor filters every sub-function group out of the stats output.
///
/// # Errors
///
/// Returns preparation, execution, status, or section assertion failure.
pub fn sub_function_min_sub_nodes_filters(command: CommandFactory) -> Result<(), CliTestFailure> {
  run_for_fixture(command, "sub_function_dupes", &[
    "--sub-function", "--min-sub-nodes", "1000", "stats",
  ])?
  .try_success()?
  .try_stdout(contains("Sub-function").not())
  .map(drop)
  .map_err(CliTestFailure::from)
}

/// Fingerprint of the first exact group in a text report over `path`.
fn exact_fingerprint_for_path(command: CommandFactory, path: &Path) -> Result<String, CliTestFailure> {
  let text = path_stdout(command, path, &["report"])?;
  report_fingerprint(&text, false)
}

/// Run `ignore <fingerprint>` (with an optional `--reason`) and require the Added confirmation.
fn add_ignore(command: CommandFactory, path: &Path, fingerprint: &str, reason: Option<&str>) -> Result<(), CliTestFailure> {
  let mut arguments = vec!["ignore", fingerprint];
  if let Some(explanation) = reason {
    arguments.extend(["--reason", explanation]);
  }
  assert_path_success_stdout(command, path, &arguments, &["Added"])
}

/// Read a fixture file while retaining its native path and filesystem cause on failure.
fn read_fixture(path: &Path) -> Result<String, CliTestFailure> {
  fs::read_to_string(path).map_err(|source| CliTestFailure::Fixture {
    path: path.to_path_buf(),
    source,
  })
}

/// Write fixture bytes while retaining the destination and native cause on failure.
///
/// # Errors
/// Returns the complete destination path and original filesystem failure.
pub fn write_fixture(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), CliTestFailure> {
  fs::write(path, contents).map_err(|source| CliTestFailure::Fixture {
    path: path.to_path_buf(),
    source,
  })
}

/// End-to-end ignore workflow: capture a real fingerprint, `ignore` it with a reason, see it
/// listed by `ignored`, and watch the exact group disappear from `stats`.
///
/// # Errors
///
/// Returns the failed workflow step's complete native failure.
pub fn ignore_workflow(command: CommandFactory) -> Result<(), CliTestFailure> {
  let directory = temp_copy_fixture("exact_dupes")?;
  let fingerprint = exact_fingerprint_for_path(command, directory.path())?;
  add_ignore(command, directory.path(), &fingerprint, Some("test ignore"))?;
  assert_path_success_stdout(command, directory.path(), &["ignored"], &[fingerprint.as_str(), "test ignore"])?;
  assert_path_success_stdout(command, directory.path(), &["stats"], &["Exact duplicates: 0 groups"])
}

/// The ignore workflow also silences a near-duplicate group captured at a lowered threshold.
///
/// # Errors
///
/// Returns the failed workflow step's complete native failure.
pub fn ignore_near_duplicate_workflow(command: CommandFactory) -> Result<(), CliTestFailure> {
  let directory = temp_copy_fixture("near_dupes")?;
  let report = path_stdout(command, directory.path(), &["--threshold", "0.7", "report"])?;
  let fingerprint = report_fingerprint(&report, true)?;
  add_ignore(command, directory.path(), &fingerprint, Some("near dupe ignore test"))?;
  assert_path_success_stdout(command, directory.path(), &["--threshold", "0.7", "stats"], &[
    "Near duplicates:  0 groups"
  ])
}

/// `cleanup` removes the stale ignore entry, reports it, and keeps the still-matching entry.
///
/// # Errors
///
/// Returns the failed workflow step's complete native failure.
pub fn cleanup_removes_stale_entries(command: CommandFactory) -> Result<(), CliTestFailure> {
  let directory = temp_copy_fixture("exact_dupes")?;
  let real_fingerprint = exact_fingerprint_for_path(command, directory.path())?;
  add_ignore(command, directory.path(), &real_fingerprint, None)?;

  let ignore_path = directory.path().join(".dupes-ignore.toml");
  let original = read_fixture(&ignore_path)?;
  write_fixture(
    &ignore_path,
    format!("{original}\n[[ignore]]\nfingerprint = \"deadbeefdeadbeef\"\nreason = \"stale entry\"\n"),
  )?;

  assert_path_success_stdout(command, directory.path(), &["cleanup"], &[
    "Removed stale entries", "deadbeefdeadbeef", "Removed 1 stale entries",
  ])?;
  assert_path_success_stdout(command, directory.path(), &["ignored"], &[real_fingerprint.as_str()])?;
  let final_content = read_fixture(&ignore_path)?;
  ensure(
    !final_content.contains("deadbeefdeadbeef"),
    "cleanup must remove the stale fingerprint",
  )?;
  Ok(())
}

/// `cleanup --dry-run` reports the stale entry without rewriting the ignore file.
///
/// # Errors
///
/// Returns the failed workflow step's complete native failure.
pub fn cleanup_dry_run(command: CommandFactory) -> Result<(), CliTestFailure> {
  let directory = temp_copy_fixture("exact_dupes")?;
  let ignore_path = directory.path().join(".dupes-ignore.toml");
  let original = "[[ignore]]\nfingerprint = \"deadbeefdeadbeef\"\nreason = \"stale\"\n";
  write_fixture(&ignore_path, original)?;
  assert_path_success_stdout(command, directory.path(), &["cleanup", "--dry-run"], &[
    "Stale entries (dry run)", "deadbeefdeadbeef", "would be removed",
  ])?;
  let content = read_fixture(&ignore_path)?;
  ensure(content == original, "cleanup dry-run must preserve the complete ignore file")?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::ffi::OsStr;
  use std::io::ErrorKind;

  use assert_cmd::Command;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::CliTestFailure;
  use super::assert_stdout_contains;
  use super::check_json;
  use super::compiled_binary;
  use super::group_containing_member;
  use super::groups_of_dimension;
  use super::json_count;
  use super::json_field;
  use super::json_from_stdout;
  use super::read_fixture;
  use super::report_fingerprint;
  use super::run_command;
  use super::rust_fixture_path;
  use super::suppressed_count_for_rule;
  use super::temp_copy_fixture;
  use super::workspace_root;
  use super::write_fixture;

  /// Command preparation failures retain the requested binary through the execution boundary.
  #[test]
  fn missing_binary_retains_requested_identity() -> Result<(), CliTestFailure> {
    let outcome = run_command(|| compiled_binary("missing-cli-test-executable"), ["--help"]);
    ensure(
      matches!(
        outcome,
        Err(CliTestFailure::Binary {
          binary: "missing-cli-test-executable",
          ref variable,
        }) if variable == "CARGO_BIN_EXE_missing-cli-test-executable"
      ),
      "binary discovery must preserve the requested name instead of becoming a launch or assertion failure",
    )?;
    Ok(())
  }

  /// Failed launches preserve the native program and arguments prepared by the command boundary.
  #[test]
  fn launch_failure_retains_the_prepared_command() -> Result<(), CliTestFailure> {
    let root = workspace_root()?;
    let program = root.join("Cargo.toml").join("not-an-executable");
    let outcome = run_command(
      || Ok(Command::new(workspace_root()?.join("Cargo.toml").join("not-an-executable"))),
      ["--path", "source with spaces", "report"],
    );
    ensure(
      matches!(outcome, Err(CliTestFailure::Command { command, source })
        if command.get_program() == program.as_os_str()
          && command.get_args().eq([OsStr::new("--path"), OsStr::new("source with spaces"), OsStr::new("report")])
          && command.get_current_dir().is_none()
          && command.get_envs().next().is_none()
          && matches!(source.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)),
      "a launch failure must retain all prepared command inputs and the native path failure",
    )?;
    Ok(())
  }

  /// A failed stdout predicate carries the successful process's original status and both streams.
  #[test]
  fn stdout_assertion_failures_preserve_native_output() -> Result<(), CliTestFailure> {
    let captured = run_command(|| Ok(Command::new(env!("CARGO"))), ["--version"])?.try_success()?;
    let expected = captured.get_output().clone();
    match assert_stdout_contains(captured, &["\0"]) {
      Err(CliTestFailure::Assertion(failed_predicate)) => {
        let assertion = failed_predicate.assert();
        let observed = assertion.get_output();
        ensure(
          observed.status == expected.status && observed.stdout == expected.stdout && observed.stderr == expected.stderr,
          "the typed assertion failure must retain the native exit status and both complete streams",
        )
        .map_err(|source| CliTestFailure::Output {
          captured: Box::new(assertion),
          source:   Box::new(CliTestFailure::Expectation(source)),
        })
      }
      Err(source) => Err(source),
      Ok(assertion) => {
        ensure(false, "a missing stdout needle must produce the native assertion failure").map_err(|source| CliTestFailure::Output {
          captured: Box::new(assertion),
          source:   Box::new(CliTestFailure::Expectation(source)),
        })
      }
    }
  }

  /// Fixture failures distinguish missing input, missing destination parents, and invalid text.
  #[test]
  fn fixture_io_failures_retain_their_paths() -> Result<(), CliTestFailure> {
    let missing_fixture = "missing-cli-test-fixture";
    let source_path = rust_fixture_path(missing_fixture)?.join("src/lib.rs");
    ensure(
      matches!(temp_copy_fixture(missing_fixture), Err(CliTestFailure::Fixture { path, source })
        if path == source_path && source.kind() == ErrorKind::NotFound),
      "a missing fixture retains the original source path and filesystem failure",
    )?;
    let directory = temp_copy_fixture("no_dupes")?;
    let missing = directory.path().join("missing").join("input.rs");
    for outcome in [read_fixture(&missing).map(drop), write_fixture(&missing, b"source")] {
      ensure(
        matches!(outcome, Err(CliTestFailure::Fixture { path, source })
          if path == missing && source.kind() == ErrorKind::NotFound),
        "both fixture reads and writes retain their complete path and native missing-parent failure",
      )?;
    }
    let invalid_text = directory.path().join("native-bytes");
    write_fixture(&invalid_text, [0xff])?;
    ensure(
      matches!(read_fixture(&invalid_text), Err(CliTestFailure::Fixture { path, source })
        if path == invalid_text && source.kind() == ErrorKind::InvalidData),
      "fixture text decoding preserves the affected path and native invalid-data failure",
    )?;
    Ok(())
  }

  #[test]
  fn report_queries_preserve_members_and_distinguish_absence() -> Result<(), CliTestFailure> {
    let report = json_from_stdout(br#"{"groups":[{"dimension":"ast","members":[{"name":"render","file":"src/view.rs"}]}]}"#)?;
    let groups = groups_of_dimension(&report, "ast")?;
    ensure_eq(&groups.len(), &1, "the report contains one AST group")?;
    ensure(
      group_containing_member(&report, "render", "view.rs")? == groups.first().copied(),
      "member lookup returns the complete matching group",
    )?;
    ensure(
      group_containing_member(&report, "render", "other.rs")?.is_none(),
      "member lookup requires both name and file",
    )?;
    ensure(
      groups_of_dimension(&report, "line")?.is_empty(),
      "dimension filtering preserves actual absence",
    )?;
    Ok(())
  }

  #[test]
  fn malformed_reports_return_original_fields_and_parser_input() -> Result<(), CliTestFailure> {
    let input = b"{\"groups\":";
    ensure(
      matches!(json_from_stdout(input), Err(CliTestFailure::Json { input: bytes, source })
      if bytes == input && source.is_eof()),
      "invalid JSON retains its bytes and native parser category",
    )?;
    let report = json_from_stdout(br#"{"groups":false,"total_code_units":"many"}"#)?;
    ensure(
      matches!(groups_of_dimension(&report, "ast"), Err(CliTestFailure::JsonShape { document, .. })
      if document == false),
      "malformed groups must not become an empty result",
    )?;
    ensure(
      matches!(json_count(&report, "total_code_units"), Err(CliTestFailure::JsonShape { document, .. })
      if document == "many"),
      "malformed counts retain the original value",
    )?;
    ensure(
      matches!(json_field(&report, "members"), Err(CliTestFailure::JsonField { document, field })
      if document == report && field == "members"),
      "missing fields retain the inspected object and requested key",
    )?;
    let invalid_dimension = json_from_stdout(br#"{"groups":[{"dimension":false,"members":[]}]}"#)?;
    ensure(
      matches!(groups_of_dimension(&invalid_dimension, "ast"), Err(CliTestFailure::JsonShape { document, context })
        if document == false && context == "field must be a string"),
      "a malformed dimension must retain its original value instead of becoming an absent group",
    )?;
    Ok(())
  }

  #[test]
  fn semantic_check_failures_keep_the_complete_report() -> Result<(), CliTestFailure> {
    let report = json_from_stdout(br#"{"groups":[],"stats":{"total_code_units":4}}"#)?;
    let outcome = check_json(report.clone(), |document| {
      ensure(
        json_count(json_field(document, "stats")?, "total_code_units")? == 5,
        "expected five units",
      )?;
      Ok(())
    });
    ensure(
      matches!(outcome, Err(CliTestFailure::Report { document, source })
      if document == report && matches!(*source, CliTestFailure::Expectation(_))),
      "semantic failures must retain the full report and the original expectation",
    )?;
    Ok(())
  }

  #[test]
  fn fingerprint_selection_preserves_copyable_text_and_missing_report() -> Result<(), CliTestFailure> {
    let report = "fingerprint: abc123, members: 2\nfingerprint: def456, similarity: 0.9\n";
    ensure_eq(
      &report_fingerprint(report, false)?.as_str(),
      &"abc123",
      "exact fingerprints remain copyable",
    )?;
    ensure_eq(
      &report_fingerprint(report, true)?.as_str(),
      &"def456",
      "near selection skips the exact group",
    )?;
    let exact_only = "fingerprint: abc123, members: 2\n";
    ensure(
      matches!(report_fingerprint(exact_only, true), Err(CliTestFailure::ReportFingerprint { report: observed_report, require_similarity })
      if observed_report == exact_only && require_similarity),
      "a missing near fingerprint must retain the complete report and requested kind",
    )?;
    Ok(())
  }

  #[test]
  fn suppression_counts_distinguish_absent_rules_from_malformed_counts() -> Result<(), CliTestFailure> {
    let report = json_from_stdout(br#"{"suppressed_by_rule":{"active":3,"invalid":"three"}}"#)?;
    ensure_eq(
      &suppressed_count_for_rule(&report, "active")?,
      &3,
      "present rule counts remain exact",
    )?;
    ensure_eq(
      &suppressed_count_for_rule(&report, "absent")?,
      &0,
      "an absent rule has no suppressed units",
    )?;
    ensure_eq(
      &suppressed_count_for_rule(&json_from_stdout(b"{}")?, "absent")?,
      &0,
      "an absent suppression surface has no suppressed units",
    )?;
    ensure(
      matches!(suppressed_count_for_rule(&report, "invalid"), Err(CliTestFailure::JsonShape { document, .. })
      if document == "three"),
      "malformed suppression counts must retain the invalid value",
    )?;
    let invalid_surface = json_from_stdout(br#"{"suppressed_by_rule":["active",3]}"#)?;
    ensure(
      matches!(suppressed_count_for_rule(&invalid_surface, "active"), Err(CliTestFailure::JsonShape { document, context })
        if &document == json_field(&invalid_surface, "suppressed_by_rule")?
          && context == "suppression attribution must be an object"),
      "malformed suppression attribution must retain the complete surface instead of becoming zero",
    )?;
    Ok(())
  }
}
