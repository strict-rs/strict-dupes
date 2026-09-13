//! Shared argument resolution, analysis, reporting, and registry commands.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::env;
use std::fmt::Debug;
use std::fmt::Display;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(feature = "cli")]
use clap::Args;
#[cfg(feature = "cli")]
use clap::Subcommand;
#[cfg(feature = "cli")]
use clap::ValueEnum;
use thiserror::Error;

use crate::AnalysisResult;
use crate::analyze_with_generic;
use crate::analyzer::LanguageAnalyzer;
use crate::code_unit::CodeUnit;
use crate::code_unit::DetectionDimension;
use crate::config::Config;
use crate::config::ConfigLoadError;
use crate::config::override_with;
use crate::error::AnalysisError;
use crate::fingerprint::Fingerprint;
use crate::fingerprint::FingerprintParseError;
use crate::fingerprint::RecordedFingerprint;
use crate::grouper::DuplicateGroup;
use crate::grouper::DuplicationStats;
use crate::grouper::GroupCountOverflow;
use crate::grouper::MatchKind;
use crate::grouper::PercentageFailure;
use crate::ignore;
use crate::ignore::IgnoreEntry;
use crate::ignore::IgnoreEntryRegistration;
use crate::ignore::IgnoreFileError;
use crate::ignore::IgnoreFileLoad;
use crate::ignore::IgnoreFileWrite;
use crate::ignore::IgnoreMemberObservation;
use crate::output::ReportError;
use crate::output::ReportOptions;
use crate::output::ReportRenderer;
use crate::output::Reporter;
use crate::output::display_path;
use crate::output::json::JsonReporter;
use crate::output::text::TextReporter;
use crate::output::warning_messages;
use crate::scanner::ScanConfig;
use crate::scanner::ScanError;
use crate::scanner::SourceScan;
use crate::scanner::scan_files;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by CLI command functions.
#[derive(Debug, Error)]
pub enum CliError<ParseError: Debug = Infallible> {
  /// An I/O error (exit code 2).
  #[error(transparent)]
  Io(#[from] io::Error),
  /// Resolving the default analysis directory failed (exit code 2).
  #[error("cannot resolve the current working directory: {0}")]
  CurrentDirectory(#[source] io::Error),
  /// Report encoding or writing failed with its native cause (exit code 2).
  #[error(transparent)]
  Report(#[from] ReportError),
  /// Loading or saving the registry failed with its native cause (exit code 2).
  #[error(transparent)]
  Registry(#[from] IgnoreFileError),
  /// Registry listing failed after its native load completed (exit code 2).
  #[error("could not list the loaded ignore registry: {source}")]
  RegistryListing {
    /// Complete registry and native load observation used for the listing.
    registry: Box<IgnoreFileLoad>,
    /// Native output-write failure.
    source:   io::Error,
  },
  /// Persistence failed after the requested entry was evaluated against the loaded registry.
  #[error("could not persist ignore registration: {source}")]
  IgnorePersistence {
    /// Complete original registry, matched group, and registration decision.
    registration: Box<IgnoreRegistration>,
    /// Native encoding or write failure, including the proposed registry.
    source:       IgnoreFileError,
  },
  /// Diagnostic output failed after registration was persisted.
  #[error("could not report the persisted ignore registration: {source}")]
  IgnoreReporting {
    /// Complete registration and successful write retained across reporting failure.
    outcome: Box<IgnoreCommandOutcome>,
    /// Native diagnostic-output failure.
    source:  io::Error,
  },
  /// Cleanup persistence failed after stale entries were selected and removed from the proposal.
  #[error("could not persist registry cleanup: {source}")]
  CleanupPersistence {
    /// Complete registry and native observation from before cleanup.
    registry: Box<IgnoreFileLoad>,
    /// Complete entries removed from the proposed registry.
    removed:  Vec<IgnoreEntry>,
    /// Native encoding or write failure, including the proposed registry.
    source:   IgnoreFileError,
  },
  /// Diagnostic output failed after cleanup or its dry-run decision completed.
  #[error("could not report registry cleanup: {source}")]
  CleanupReporting {
    /// Complete cleanup decision and any successful persistence.
    outcome: Box<CleanupOutcome>,
    /// Native diagnostic-output failure.
    source:  io::Error,
  },
  /// Configuration loading failed with every completed layer retained (exit code 2).
  #[error(transparent)]
  Config(#[from] ConfigLoadError),
  /// A check could not complete its measurements (exit code 2).
  #[error(transparent)]
  CheckEvaluation(#[from] CheckEvaluationFailure),
  /// Report output failed after all threshold decisions were computed (exit code 2).
  #[error("could not report the completed check: {source}")]
  CheckReporting {
    /// Every completed threshold decision, including passes and unset thresholds.
    outcome: Box<CheckOutcome>,
    /// Native report encoding or output-write failure.
    source:  ReportError,
  },
  /// A configured threshold could not be compared with its measurement (exit code 2).
  #[error("Check contains an unordered threshold comparison")]
  CheckUnordered(Box<CheckOutcome>),
  /// No source files found (exit code 2).
  #[error("No source files found in {}", config.root.display())]
  NoSourceFiles {
    /// Configuration used for the empty source selection.
    config: Box<Config>,
    /// Complete scans, including every observed exclusion.
    scans:  Vec<SourceScan>,
  },
  /// Preparation failed after retaining resolved configuration and earlier scans.
  #[error("{source}")]
  Preparation {
    /// Configuration resolved before source discovery started.
    config: Box<Config>,
    /// Source scans completed before the failing scan.
    scans:  Vec<SourceScan>,
    /// Native failure from the incomplete scan.
    source: Box<ScanError>,
  },
  /// Analysis pipeline failed (exit code 2).
  #[error("{source}")]
  Analysis {
    /// Complete resolved configuration and its source observations.
    config: Box<Config>,
    /// Complete source discovery observations supplied to analysis.
    scans:  Vec<SourceScan>,
    /// Native analysis failure, including any partial findings.
    source: Box<AnalysisError<ParseError>>,
  },
  /// Registration rejected its fingerprint before accessing the registry (exit code 2).
  #[error("Invalid fingerprint: {}: {}", source.input, source.source)]
  InvalidFingerprint {
    /// Requested registry root, which was not accessed.
    root:   PathBuf,
    /// Requested registration metadata, which was not applied.
    reason: Option<String>,
    /// Complete original spelling and native integer parsing failure.
    source: FingerprintParseError,
  },
  /// Check thresholds exceeded (exit code 1).
  #[error("Check failed")]
  CheckFailed(Box<CheckOutcome>),
}

impl<ParseError: Debug> CliError<ParseError> {
  /// Map to an appropriate process exit code.
  #[must_use]
  pub const fn exit_code(&self) -> u8 {
    match *self {
      Self::CheckFailed(_) => 1,
      Self::Io(_)
      | Self::CurrentDirectory(_)
      | Self::Report(_)
      | Self::Registry(_)
      | Self::RegistryListing {
        ..
      }
      | Self::IgnorePersistence {
        ..
      }
      | Self::IgnoreReporting {
        ..
      }
      | Self::CleanupPersistence {
        ..
      }
      | Self::CleanupReporting {
        ..
      }
      | Self::Config(_)
      | Self::CheckEvaluation(_)
      | Self::CheckUnordered(_)
      | Self::CheckReporting {
        ..
      }
      | Self::Preparation {
        ..
      }
      | Self::NoSourceFiles {
        ..
      }
      | Self::Analysis {
        ..
      }
      | Self::InvalidFingerprint {
        ..
      } => 2,
    }
  }
}

/// Result type for CLI operations.
pub type CliResult<Outcome = (), ParseError = Infallible> = Result<Outcome, CliError<ParseError>>;

/// Failure to render a native parser diagnostic or an operation error.
#[derive(Debug, Error)]
pub enum ErrorReportFailure<Failure: Debug + Display> {
  /// Help, version output, or a parse failure could not be printed.
  #[cfg(feature = "cli")]
  #[error("could not render command-line diagnostic {diagnostic}: {source}")]
  Arguments {
    /// Complete native diagnostic, including its kind, context, and formatting.
    diagnostic: clap::Error,
    /// Native error from writing to the parser-selected stream.
    source:     io::Error,
  },
  /// An operation's failure could not be printed.
  #[error("could not render {failure}: {source}")]
  Operation {
    /// Complete operation failure whose diagnostic could not be written.
    failure: Box<Failure>,
    /// Native error from writing the diagnostic.
    source:  io::Error,
  },
}

// ---------------------------------------------------------------------------
// Shared CLI types
// ---------------------------------------------------------------------------

/// Output format for CLI reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(ValueEnum))]
pub enum OutputFormat {
  /// Human-readable text (the default).
  #[default]
  Text,
  /// Machine-readable JSON.
  Json,
}

/// Sub-function detection requests shared by both command-line frontends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(Args))]
pub struct SubFunctionArgs {
  /// Enable sub-function duplicate detection.
  #[cfg_attr(
    feature = "cli",
    arg(id = "sub_function", long = "sub-function", short = 's', global = true)
  )]
  pub enable:    bool,
  /// Disable sub-function duplicate detection when enabled by config.
  #[cfg_attr(
    feature = "cli",
    arg(
      id = "no_sub_function",
      long = "no-sub-function",
      global = true,
      conflicts_with = "sub_function"
    )
  )]
  pub disable:   bool,
  /// Minimum AST node count for sub-function units.
  #[cfg_attr(
    feature = "cli",
    arg(id = "min_sub_nodes", long = "min-sub-nodes", global = true)
  )]
  pub min_nodes: Option<usize>,
}

/// Global CLI options shared by `cargo-dupes` and `code-dupes`.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "cli", derive(Args))]
pub struct CommonCliArgs {
  /// Path to analyze (defaults to current directory).
  #[cfg_attr(feature = "cli", arg(short, long, global = true))]
  pub path:              Option<PathBuf>,
  /// Minimum AST node count for analysis.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub min_nodes:         Option<usize>,
  /// Minimum source line count for analysis.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub min_lines:         Option<usize>,
  /// Similarity threshold (0.0-1.0).
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub threshold:         Option<f64>,
  /// Output format.
  #[cfg_attr(feature = "cli", arg(long, global = true, default_value = "text"))]
  pub format:            OutputFormat,
  /// Exclude patterns (can be repeated).
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub exclude:           Vec<String>,
  /// Exclude test code identified by the active language analyzer.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub exclude_tests:     bool,
  /// Sub-function detection and minimum-size requests.
  #[cfg_attr(feature = "cli", command(flatten))]
  pub sub_function:      SubFunctionArgs,
  /// Presentation settings owned by the report renderer.
  #[cfg_attr(feature = "cli", command(flatten))]
  pub report:            ReportOptions,
  /// Disable a suppression/admission rule by id (can be repeated).
  #[cfg_attr(
    feature = "cli",
    arg(long = "disable-rule", value_name = "RULE_ID", global = true)
  )]
  pub disable_rule:      Vec<String>,
  /// Enable a rule by id (can be repeated; overrides config disable).
  #[cfg_attr(
    feature = "cli",
    arg(long = "enable-rule", value_name = "RULE_ID", global = true)
  )]
  pub enable_rule:       Vec<String>,
  /// Enable only the selected detection dimension (can be repeated).
  #[cfg_attr(feature = "cli", arg(long, global = true, conflicts_with = "disable_dimension"))]
  pub dimension:         Vec<DetectionDimension>,
  /// Disable a detection dimension (can be repeated).
  #[cfg_attr(feature = "cli", arg(long, global = true, conflicts_with = "dimension"))]
  pub disable_dimension: Vec<DetectionDimension>,
  /// Minimum token count for token-window detection.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub token_min_tokens:  Option<usize>,
  /// Minimum source line span for token-window detection.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub token_min_lines:   Option<usize>,
  /// Similarity threshold for normalized token near-duplicates.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub token_threshold:   Option<f64>,
  /// Minimum line count for line-window detection.
  #[cfg_attr(feature = "cli", arg(long, global = true))]
  pub line_min_lines:    Option<usize>,
}

impl CommonCliArgs {
  /// Resolve the analysis root from CLI input.
  ///
  /// # Errors
  ///
  /// Returns [`CliError::CurrentDirectory`] with the native cause when no
  /// explicit path was supplied and the working directory cannot be resolved.
  pub fn root(&self) -> CliResult<PathBuf> {
    self
      .path
      .as_ref()
      .map_or_else(|| env::current_dir().map_err(CliError::CurrentDirectory), |path| Ok(path.clone()))
  }

  /// Convert common CLI options into shared core overrides.
  #[must_use]
  pub fn overrides(&self, generic_extensions: Vec<String>) -> CliOverrides {
    CliOverrides {
      min_nodes: self.min_nodes,
      min_lines: self.min_lines,
      threshold: self.threshold,
      exclude: self.exclude.clone(),
      exclude_tests: self.exclude_tests.then_some(true),
      sub_function: if self.sub_function.disable {
        Some(false)
      } else if self.sub_function.enable {
        Some(true)
      } else {
        None
      },
      min_sub_nodes: self.sub_function.min_nodes,
      enabled_dimensions: self.dimension.clone(),
      disabled_dimensions: self.disable_dimension.clone(),
      token_min_tokens: self.token_min_tokens,
      token_min_lines: self.token_min_lines,
      token_threshold: self.token_threshold,
      line_min_lines: self.line_min_lines,
      show_suppressed: self.report.show_suppressed,
      verbose: self.report.verbose,
      disable_rule: self.disable_rule.clone(),
      enable_rule: self.enable_rule.clone(),
      generic_extensions,
    }
  }
}

/// CLI subcommands shared between `cargo-dupes` and `code-dupes`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "cli", derive(Subcommand))]
pub enum Command {
  /// Show duplication statistics only.
  Stats,
  /// Show full duplication report (default).
  Report,
  /// Check for duplicates and exit with non-zero if thresholds exceeded.
  Check {
    /// Maximum group counts and percentages, shared with gate evaluation.
    #[cfg_attr(feature = "cli", command(flatten))]
    thresholds: CheckThresholds,
  },
  /// Add a fingerprint to the ignore list.
  Ignore {
    /// The fingerprint to ignore (hex string).
    fingerprint: String,
    /// Reason for ignoring.
    #[cfg_attr(feature = "cli", arg(long))]
    reason:      Option<String>,
  },
  /// List all ignored fingerprints.
  Ignored,
  /// Remove stale entries from the ignore file.
  Cleanup {
    /// Only list stale entries without removing them.
    #[cfg_attr(feature = "cli", arg(long))]
    dry_run: bool,
  },
}

/// Thresholds for the `check` subcommand.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "cli", derive(Args))]
pub struct CheckThresholds {
  /// Maximum allowed exact duplicate groups.
  #[cfg_attr(feature = "cli", arg(long = "max-exact"))]
  pub exact_groups:  Option<usize>,
  /// Maximum allowed near duplicate groups.
  #[cfg_attr(feature = "cli", arg(long = "max-near"))]
  pub near_groups:   Option<usize>,
  /// Maximum allowed exact duplicate-line percentage.
  #[cfg_attr(feature = "cli", arg(long = "max-exact-percent"))]
  pub exact_percent: Option<f64>,
  /// Maximum allowed near duplicate-line percentage.
  #[cfg_attr(feature = "cli", arg(long = "max-near-percent"))]
  pub near_percent:  Option<f64>,
}

/// Optional CLI overrides applied on top of file-based config.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
  /// Minimum AST node count for analysis.
  pub min_nodes:           Option<usize>,
  /// Minimum source line count for analysis.
  pub min_lines:           Option<usize>,
  /// Similarity threshold for near-duplicates.
  pub threshold:           Option<f64>,
  /// Additional path patterns to exclude from scanning.
  pub exclude:             Vec<String>,
  /// Exclude test code identified by the language analyzer.
  pub exclude_tests:       Option<bool>,
  /// Enable or disable sub-function duplicate detection.
  pub sub_function:        Option<bool>,
  /// Minimum AST node count for sub-function units.
  pub min_sub_nodes:       Option<usize>,
  /// When nonempty, enable only these detection dimensions.
  pub enabled_dimensions:  Vec<DetectionDimension>,
  /// Detection dimensions to disable.
  pub disabled_dimensions: Vec<DetectionDimension>,
  /// Minimum token count for token-window detection.
  pub token_min_tokens:    Option<usize>,
  /// Minimum source line span for token-window detection.
  pub token_min_lines:     Option<usize>,
  /// Similarity threshold for normalized token near-duplicates.
  pub token_threshold:     Option<f64>,
  /// Minimum line count for line-window detection.
  pub line_min_lines:      Option<usize>,
  /// Include rule-suppressed duplicate groups in the report body.
  pub show_suppressed:     bool,
  /// Verbose statistics: per-rule suppression breakdown.
  pub verbose:             bool,
  /// Suppression/admission rule ids to disable.
  pub disable_rule:        Vec<String>,
  /// Rule ids to enable (overriding config disables).
  pub enable_rule:         Vec<String>,
  /// File extensions scanned by the generic token/line dimensions.
  pub generic_extensions:  Vec<String>,
}

/// Result of [`run_analysis`].
#[derive(Debug)]
pub struct AnalysisOutput<Renderer, ParseError = Infallible> {
  /// The fully resolved configuration the analysis ran with.
  pub config:   Config,
  /// The analysis findings.
  pub result:   AnalysisResult<ParseError>,
  /// Complete source discovery, including exclusions and native walker observations.
  pub scans:    Vec<SourceScan>,
  /// Reporter matching the requested output format.
  pub reporter: Renderer,
}

/// Prepared CLI analysis or its complete native preparation failure.
pub type CliAnalysisResult<ParseError = Infallible> = CliResult<AnalysisOutput<ReportRenderer, ParseError>, ParseError>;

/// A requested registration evaluated against the native registry and current findings.
#[derive(Debug)]
pub struct IgnoreRegistration {
  /// Complete registry and native load observation from before registration.
  pub registry: IgnoreFileLoad,
  /// Complete current group whose member information supplied the requested entry, if found.
  pub group:    Option<DuplicateGroup>,
  /// Complete insertion or already-registered decision, including unapplied requested metadata.
  pub change:   IgnoreEntryRegistration,
}

/// A completed ignore registration and the complete write that persisted its resulting registry.
#[derive(Debug)]
pub struct IgnoreCommandOutcome {
  /// Native inputs and the in-memory registration decision.
  pub registration: IgnoreRegistration,
  /// Destination, complete resulting registry, and exact persisted document.
  pub write:        IgnoreFileWrite,
}

/// The complete result of a cleanup decision, including dry runs and unchanged registries.
#[derive(Debug)]
pub enum CleanupOutcome {
  /// A dry run selected stale entries without changing or persisting the registry.
  Preview {
    /// Complete registry and its original native load observation.
    registry:   IgnoreFileLoad,
    /// Complete entries that an applying cleanup would remove.
    stale:      Vec<IgnoreEntry>,
    /// Successor searches reached while reporting stale entries, including nonfatal parse failures.
    successors: Vec<IgnoreEntrySuccessors>,
  },
  /// Applying cleanup found no stale entries and did not write the registry.
  Unchanged(IgnoreFileLoad),
  /// Applying cleanup persisted the registry after removing stale entries.
  Removed {
    /// Complete registry and native load observation from before cleanup.
    registry: IgnoreFileLoad,
    /// Complete entries removed from the persisted registry.
    removed:  Vec<IgnoreEntry>,
    /// Destination, resulting registry, and exact persisted document.
    write:    IgnoreFileWrite,
  },
}

/// Recorded locations and candidate decisions from one stale entry's successor search.
#[derive(Debug, Clone, PartialEq)]
pub struct IgnoreEntrySuccessors {
  /// Complete stale entry whose recorded locations were considered.
  pub entry:      IgnoreEntry,
  /// Every original member description and its native parsing outcome.
  pub members:    Vec<IgnoreMemberObservation>,
  /// Evaluated live groups, or no search when every recorded location was unusable.
  pub candidates: Option<Vec<SuccessorCandidate>>,
}

/// A live group's relationship to the stale entry's usable recorded locations.
#[derive(Debug, Clone, PartialEq)]
pub enum SuccessorCandidate {
  /// At least one member overlaps a recorded location within the allowed line drift.
  Overlapping(DuplicateGroup),
  /// No member overlaps any usable recorded location within the allowed line drift.
  NoOverlap(DuplicateGroup),
}

/// Completed action performed against an analysis result.
#[derive(Debug)]
pub enum AnalysisCommandOutcome {
  /// The statistics document was rendered.
  Stats,
  /// The complete duplicate report was rendered.
  Report,
  /// Every configured check passed, with all decisions retained.
  Check(CheckOutcome),
  /// The requested ignore registration and its diagnostic output completed.
  Ignore(Box<IgnoreCommandOutcome>),
  /// A cleanup or dry-run request and its diagnostic output completed.
  Cleanup(Box<CleanupOutcome>),
  /// The current registry was listed without discarding its native load observation.
  Ignored(IgnoreFileLoad),
}

/// A completed shared command with its requested action and native analysis evidence.
#[derive(Debug)]
pub enum CommandOutput<Renderer, ParseError = Infallible> {
  /// Registry listing completed without invoking analysis or constructing a reporter.
  Ignored(IgnoreFileLoad),
  /// An analysis-dependent action completed with its full preparation and action outcome.
  Analyzed {
    /// Original command, including its explicit thresholds or registry arguments.
    command:  Command,
    /// Complete analysis, configuration, source scans, and selected reporter.
    analysis: Box<AnalysisOutput<Renderer, ParseError>>,
    /// Typed outcome of the action performed against that analysis.
    outcome:  AnalysisCommandOutcome,
  },
}

/// A failed shared command with its request, completed preparation, and native cause.
#[derive(Debug, Error)]
pub enum CommandFailure<Renderer, ParseError: Debug = Infallible, PreparationError = CliError<ParseError>> {
  /// Analysis preparation failed before command dispatch.
  #[error("{source}")]
  Preparation {
    /// Original analysis root supplied to the command runner.
    root:    PathBuf,
    /// Requested action, including thresholds or registry arguments that were not applied.
    command: Command,
    /// Complete native callback failure, including any partial preparation it retained.
    source:  Box<PreparationError>,
  },
  /// Warning output or command dispatch failed after analysis completed.
  #[error("{source}")]
  Analyzed {
    /// Original root supplied to command dispatch.
    root:     PathBuf,
    /// Requested action, including its explicit thresholds or registry arguments.
    command:  Command,
    /// Complete analysis, configuration, source scans, and selected renderer.
    analysis: Box<AnalysisOutput<Renderer, ParseError>>,
    /// Native command failure, including any completed action or persistence.
    source:   Box<CliError<ParseError>>,
  },
  /// Registry listing failed without invoking analysis or constructing a renderer.
  #[error("{source}")]
  Ignored {
    /// Original registry root supplied to the command runner.
    root:   PathBuf,
    /// Complete registry-loading or listing failure.
    source: Box<CliError<ParseError>>,
  },
}

/// Shared command outcome retaining preparation and action evidence on either branch.
pub type CommandResult<Renderer, ParseError = Infallible, PreparationError = CliError<ParseError>> =
  Result<CommandOutput<Renderer, ParseError>, CommandFailure<Renderer, ParseError, PreparationError>>;

impl<Renderer, ParseError: Debug, PreparationError> CommandFailure<Renderer, ParseError, PreparationError> {
  /// Preserve check rejection as status `1` and operational failures as status `2`.
  #[must_use]
  pub const fn exit_code(&self) -> u8 {
    match *self {
      Self::Preparation {
        ..
      } => 2,
      Self::Analyzed {
        ref source, ..
      }
      | Self::Ignored {
        ref source, ..
      } => source.exit_code(),
    }
  }
}

// ---------------------------------------------------------------------------
// Command orchestration
// ---------------------------------------------------------------------------

/// Run a CLI command, invoking `analyze` only for commands that need analysis.
///
/// # Errors
///
/// Retains the request and original callback failure if preparation fails, or
/// the complete prepared analysis and native cause if warning output or dispatch
/// fails. Registry listing never invokes the callback.
pub fn run_command_with_analysis<Renderer: Reporter, ParseError: Debug + Display, PreparationError>(
  root: &Path,
  command: &Command,
  writer: &mut impl Write,
  analyze: impl FnOnce() -> Result<AnalysisOutput<Renderer, ParseError>, PreparationError>,
) -> CommandResult<Renderer, ParseError, PreparationError> {
  if matches!(*command, Command::Ignored) {
    return cmd_ignored::<ParseError>(root, writer)
      .map(CommandOutput::Ignored)
      .map_err(|source| CommandFailure::Ignored {
        root:   root.to_path_buf(),
        source: Box::new(source),
      });
  }
  let output = analyze().map_err(|source| CommandFailure::Preparation {
    root:    root.to_path_buf(),
    command: command.clone(),
    source:  Box::new(source),
  })?;
  let warning_result = emit_warnings(&output.result, &output.scans, &mut io::stderr().lock());
  let outcome = warning_result
    .map_err(CliError::Io)
    .and_then(|()| dispatch_analysis_command(root, command, &output, writer));
  match outcome {
    Ok(completed) => Ok(CommandOutput::Analyzed {
      command:  command.clone(),
      analysis: Box::new(output),
      outcome:  completed,
    }),
    Err(source) => Err(CommandFailure::Analyzed {
      root:     root.to_path_buf(),
      command:  command.clone(),
      analysis: Box::new(output),
      source:   Box::new(source),
    }),
  }
}

/// Dispatch a command after analysis has completed.
///
/// # Errors
///
/// Returns the selected command's output, registry, or threshold failure.
#[allow(
  clippy::single_call_fn,
  reason = "Prepared-command dispatch is separate from analysis so callers can execute against existing complete findings."
)]
pub fn dispatch_analysis_command<Renderer: Reporter, ParseError: Debug + Display>(
  root: &Path,
  command: &Command,
  output: &AnalysisOutput<Renderer, ParseError>,
  writer: &mut impl Write,
) -> CliResult<AnalysisCommandOutcome, ParseError> {
  let reporter = &output.reporter;

  match *command {
    Command::Stats => cmd_stats(&output.result, reporter, writer).map(|()| AnalysisCommandOutcome::Stats),
    Command::Report => cmd_report(&output.result, reporter, writer).map(|()| AnalysisCommandOutcome::Report),
    Command::Check {
      ref thresholds,
    } => cmd_check(&output.config, &output.result, reporter, writer, thresholds).map(AnalysisCommandOutcome::Check),
    Command::Cleanup {
      dry_run,
    } => cmd_cleanup(root, &output.result, writer, dry_run).map(|outcome| AnalysisCommandOutcome::Cleanup(Box::new(outcome))),
    Command::Ignore {
      ref fingerprint,
      ref reason,
    } => {
      cmd_ignore(root, fingerprint, reason.clone(), &output.result, writer).map(|outcome| AnalysisCommandOutcome::Ignore(Box::new(outcome)))
    }
    Command::Ignored => cmd_ignored(root, writer).map(AnalysisCommandOutcome::Ignored),
  }
}

/// Write analysis and source-discovery warnings using the shared CLI format.
///
/// # Errors
///
/// Returns the native diagnostic-output failure. Borrowed observations remain
/// available to the caller after either success or failure.
#[allow(
  clippy::single_call_fn,
  reason = "Warning emission owns the diagnostic stream independently from the selected report payload."
)]
pub fn emit_warnings<ParseError: Display>(
  result: &AnalysisResult<ParseError>,
  scans: &[SourceScan],
  writer: &mut impl Write,
) -> io::Result<()> {
  for warning in warning_messages(result) {
    writeln!(writer, "Warning: {warning}")?;
  }
  for scan in scans {
    for observed in &scan.entries {
      if let Some(source) = observed.entry.error() {
        writeln!(writer, "Warning: {source}")?;
      }
    }
  }
  Ok(())
}

/// Render a terminal failure and return the selected process status normally.
///
/// Status `1` denotes an already-rendered check failure. Other failures receive
/// the shared diagnostic prefix. The caller returns the status from `main`,
/// allowing live resource guards to leave scope normally.
///
/// # Errors
///
/// Returns both the complete operation failure and the native writing error if
/// the diagnostic could not be written.
#[allow(
  clippy::single_call_fn,
  reason = "Terminal operation reporting owns the status-one rendering rule and preserves failures from the diagnostic stream."
)]
pub fn report_error<Failure: Debug + Display>(
  failure: Failure,
  exit_code: u8,
  writer: &mut impl Write,
) -> Result<ExitCode, ErrorReportFailure<Failure>> {
  if exit_code != 1 {
    writeln!(writer, "Error: {failure}").map_err(|source| ErrorReportFailure::Operation {
      failure: Box::new(failure),
      source,
    })?;
  }
  Ok(ExitCode::from(exit_code))
}

/// Complete a command-line process through the shared diagnostic and exit-status policy.
///
/// Frontends supply their native parsed arguments, operation, and error-status mapping.
/// A parser diagnostic prevents operation execution. Successful commands return status
/// zero; failed commands use [`report_error`], preserving both failures if writing fails.
/// This is the terminal adapter for `main`; reusable callers consume the complete
/// results returned by their operation before choosing application-specific handling.
///
/// # Errors
///
/// Returns the original parser or command failure together with the native error
/// from writing its diagnostic. The process returns normally on every path.
#[cfg(feature = "cli")]
pub fn finish_command_line<Arguments, Outcome, Failure: Debug + Display>(
  parsed: Result<Arguments, clap::Error>,
  run: impl FnOnce(&Arguments) -> Result<Outcome, Failure>,
  failure_status: impl FnOnce(&Failure) -> u8,
  writer: &mut impl Write,
) -> Result<ExitCode, ErrorReportFailure<Failure>> {
  let arguments = match parsed {
    Ok(arguments) => arguments,
    Err(diagnostic) => return report_parse_error(diagnostic),
  };
  match run(&arguments) {
    Ok(_) => Ok(ExitCode::SUCCESS),
    Err(failure) => {
      let status = failure_status(&failure);
      report_error(failure, status, writer)
    }
  }
}

/// Print a native parser diagnostic and return its documented exit status.
///
/// Clap selects the stream, formatting, and color policy. Help and version
/// requests return success; rejected arguments return status `2`. Returning
/// normally lets the caller's resource guards leave scope.
///
/// # Errors
///
/// Returns the complete parser diagnostic and native writing error together
/// when printing fails, including for an otherwise successful help request.
#[cfg(feature = "cli")]
#[allow(
  clippy::single_call_fn,
  reason = "Native argument reporting preserves Clap's stream selection, formatting, exit status, and writing failure as one operation."
)]
pub fn report_parse_error<Failure: Debug + Display>(diagnostic: clap::Error) -> Result<ExitCode, ErrorReportFailure<Failure>> {
  let exit_code = if diagnostic.use_stderr() {
    ExitCode::from(2)
  } else {
    ExitCode::SUCCESS
  };
  diagnostic.print().map_err(|source| ErrorReportFailure::Arguments {
    diagnostic,
    source,
  })?;
  Ok(exit_code)
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

/// Apply CLI overrides to a loaded `Config`.
///
/// CLI `--exclude` patterns are *appended* to config-file excludes (not replaced).
#[allow(
  clippy::single_call_fn,
  reason = "CLI override precedence and additive exclusions form one shared configuration operation for both frontends."
)]
pub fn apply_overrides(config: &mut Config, overrides: &CliOverrides) {
  override_with(&mut config.min_nodes, overrides.min_nodes);
  override_with(&mut config.min_lines, overrides.min_lines);
  override_with(&mut config.similarity_threshold, overrides.threshold);
  if !overrides.exclude.is_empty() {
    config.exclude.extend(overrides.exclude.iter().cloned());
  }
  override_with(&mut config.exclude_tests, overrides.exclude_tests);
  override_with(&mut config.sub_function, overrides.sub_function);
  override_with(&mut config.min_sub_nodes, overrides.min_sub_nodes);
  if !overrides.enabled_dimensions.is_empty() {
    config.enable_only_dimensions(overrides.enabled_dimensions.iter().copied());
  }
  for &dimension in &overrides.disabled_dimensions {
    config.disable_dimension(dimension);
  }
  let rule_warnings = config
    .suppression
    .apply_toggles(&overrides.disable_rule, &overrides.enable_rule);
  config.load_warnings.extend(rule_warnings);
  override_with(&mut config.token_min_tokens, overrides.token_min_tokens);
  override_with(&mut config.token_min_lines, overrides.token_min_lines);
  override_with(&mut config.token_similarity_threshold, overrides.token_threshold);
  override_with(&mut config.line_min_lines, overrides.line_min_lines);
}

/// Create a reporter for the given output format.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Reporter selection centralizes format and path presentation for both command-line frontends."
)]
pub fn create_reporter(format: OutputFormat, root: Option<&Path>, options: ReportOptions) -> ReportRenderer {
  match format {
    OutputFormat::Text => ReportRenderer::Text(TextReporter::with_options(root.map(Path::to_path_buf), options)),
    OutputFormat::Json => ReportRenderer::Json(JsonReporter::with_options(root.map(Path::to_path_buf), options)),
  }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Scan files, run the analysis pipeline, and return the output.
///
/// Warnings are stored in [`AnalysisOutput::result`] but **not** printed;
/// the caller is responsible for writing them to stderr.
///
/// # Errors
///
/// Returns an analysis failure or [`CliError::NoSourceFiles`] when neither
/// selected source scan finds a supported file.
pub fn run_analysis<Analyzer: LanguageAnalyzer>(
  analyzer: &Analyzer,
  root: &Path,
  format: OutputFormat,
  overrides: &CliOverrides,
) -> CliAnalysisResult<Analyzer::Error> {
  let mut config = Config::load(root)?;
  apply_overrides(&mut config, overrides);

  let language_extensions: Vec<String> = analyzer
    .file_extensions()
    .iter()
    .map(|&extension| extension.to_owned())
    .collect();
  let scan_config = ScanConfig::new(config.root.clone())
    .with_excludes(config.exclude.clone())
    .with_extensions(language_extensions.clone());
  let ast_scan = scan_files(&scan_config).map_err(|source| CliError::Preparation {
    config: Box::new(config.clone()),
    scans:  Vec::new(),
    source: Box::new(source),
  })?;
  let ast_files: Vec<PathBuf> = ast_scan.files().map(Path::to_path_buf).collect();
  let mut scans = vec![ast_scan];

  let generic_files = if config.dimension_enabled(DetectionDimension::TokenNormalized)
    || config.dimension_enabled(DetectionDimension::TokenRaw)
    || config.dimension_enabled(DetectionDimension::Line)
  {
    let generic_extensions = if overrides.generic_extensions.is_empty() {
      language_extensions
    } else {
      overrides.generic_extensions.clone()
    };
    let generic_scan_config = ScanConfig::new(config.root.clone())
      .with_excludes(config.exclude.clone())
      .with_extensions(generic_extensions);
    match scan_files(&generic_scan_config) {
      Ok(generic_scan) => {
        let paths = generic_scan.files().map(Path::to_path_buf).collect();
        scans.push(generic_scan);
        paths
      }
      Err(source) => {
        return Err(CliError::Preparation {
          config: Box::new(config),
          scans,
          source: Box::new(source),
        });
      }
    }
  } else {
    Vec::new()
  };

  if ast_files.is_empty() && generic_files.is_empty() {
    return Err(CliError::NoSourceFiles {
      config: Box::new(config),
      scans,
    });
  }

  let result = match analyze_with_generic(analyzer, &ast_files, &generic_files, &config) {
    Ok(result) => result,
    Err(source) => {
      return Err(CliError::Analysis {
        config: Box::new(config),
        scans,
        source: Box::new(source),
      });
    }
  };
  let reporter = create_reporter(format, Some(root), ReportOptions {
    show_suppressed: overrides.show_suppressed,
    verbose:         overrides.verbose,
  });

  Ok(AnalysisOutput {
    config,
    result,
    scans,
    reporter,
  })
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

/// Show duplication statistics only.
///
/// # Errors
///
/// Returns the renderer's native encoding or output-write failure.
#[allow(
  clippy::single_call_fn,
  reason = "The statistics command exposes the shared analysis-to-reporter boundary independently from CLI dispatch."
)]
pub fn cmd_stats<ParseError: Debug>(
  result: &AnalysisResult<ParseError>,
  reporter: &impl Reporter,
  writer: &mut impl Write,
) -> CliResult<(), ParseError> {
  reporter.report_stats(&result.stats, writer)?;
  Ok(())
}

/// Show a full duplication report (stats + groups).
///
/// # Errors
///
/// Returns the renderer's native encoding or output-write failure.
#[allow(
  clippy::single_call_fn,
  reason = "The report command preserves one shared full-report operation for prepared analyses."
)]
pub fn cmd_report<ParseError: Debug + Display>(
  result: &AnalysisResult<ParseError>,
  reporter: &impl Reporter,
  writer: &mut impl Write,
) -> CliResult<(), ParseError> {
  reporter.report_full(result, writer)?;
  Ok(())
}

/// Check thresholds and preserve every measurement and threshold decision.
///
/// # Errors
///
/// Returns a rendering or output-write failure, or [`CliError::CheckFailed`]
/// after reporting every exceeded threshold. Measurement failures preserve
/// earlier decisions; unordered comparisons return [`CliError::CheckUnordered`]
/// before rendering a verdict. Output failures retain the complete evaluation.
#[allow(
  clippy::single_call_fn,
  reason = "Check execution owns configured precedence, measurement, reporting, and the resulting typed verdict."
)]
pub fn cmd_check<ParseError: Debug + Display>(
  config: &Config,
  result: &AnalysisResult<ParseError>,
  reporter: &impl Reporter,
  writer: &mut impl Write,
  thresholds: &CheckThresholds,
) -> CliResult<CheckOutcome, ParseError> {
  let resolved = CheckThresholds {
    exact_groups:  thresholds.exact_groups.or(config.max_exact_duplicates),
    near_groups:   thresholds.near_groups.or(config.max_near_duplicates),
    exact_percent: thresholds.exact_percent.or(config.max_exact_percent),
    near_percent:  thresholds.near_percent.or(config.max_near_percent),
  };
  let outcome = evaluate_check(&resolved, &result.stats)?;
  if outcome.gates.iter().any(GateDecision::is_unordered) {
    return Err(CliError::CheckUnordered(Box::new(outcome)));
  }
  let reporting = render_check(result, reporter, writer, &outcome);
  let verdict = retain_report_outcome(outcome, reporting, |completed, source| CliError::CheckReporting {
    outcome: Box::new(completed),
    source,
  })?;
  if verdict.gates.iter().any(GateDecision::is_exceeded) {
    Err(CliError::CheckFailed(Box::new(verdict)))
  } else {
    Ok(verdict)
  }
}

/// Return the completed operation or attach it to the native reporting failure.
fn retain_report_outcome<Outcome, Source, Failure>(
  outcome: Outcome,
  reporting: Result<(), Source>,
  failure: impl FnOnce(Outcome, Source) -> Failure,
) -> Result<Outcome, Failure> {
  match reporting {
    Ok(()) => Ok(outcome),
    Err(source) => Err(failure(outcome, source)),
  }
}

/// Render one completed check without consuming decisions needed by a later output failure.
#[allow(
  clippy::single_call_fn,
  reason = "Check rendering is one operation so every native output failure can retain the already-computed threshold decisions."
)]
fn render_check<ParseError: Display>(
  result: &AnalysisResult<ParseError>,
  reporter: &impl Reporter,
  writer: &mut impl Write,
  outcome: &CheckOutcome,
) -> Result<(), ReportError> {
  if outcome.gates.iter().any(GateDecision::is_exceeded) {
    reporter.report_full(result, writer)?;
    for summary in outcome.gates.iter().filter_map(GateDecision::failure_summary) {
      writeln!(writer, "\nCheck FAILED: {summary}")?;
    }
  } else {
    reporter.report_stats(&result.stats, writer)?;
    writeln!(writer, "\nCheck passed.")?;
  }
  Ok(())
}

/// Register a fingerprint and preserve the original registry, decision, and persisted document.
///
/// # Errors
///
/// Returns an invalid fingerprint or native registry-load failure before registration.
/// Persistence failures retain the complete registration and proposed registry;
/// reporting failures retain the successful persistence as well.
#[allow(
  clippy::single_call_fn,
  reason = "Ignore registration owns its validation, persistence, and reporting sequence as a reusable command operation."
)]
pub fn cmd_ignore<ParseError: Debug>(
  root: &Path,
  fingerprint: &str,
  reason: Option<String>,
  result: &AnalysisResult<ParseError>,
  writer: &mut impl Write,
) -> CliResult<IgnoreCommandOutcome, ParseError> {
  let parsed_fingerprint = Fingerprint::from_hex(fingerprint).map_err(|source| CliError::InvalidFingerprint {
    root: root.to_path_buf(),
    reason: reason.clone(),
    source,
  })?;
  let loaded_registry = ignore::load_ignore_file(root)?;
  // Rule-suppressed groups can be registered too, so a project can pin a
  // finding before disabling the rule that hides it.
  let group = result
    .groups_with_suppressed()
    .find(|candidate| candidate.fingerprint == parsed_fingerprint)
    .cloned();
  let (members, member_fingerprints) = group.as_ref().map_or_else(Default::default, |matched| {
    (
      matched.members.iter().map(|member| display_member(root, member)).collect(),
      record_member_fingerprints(matched),
    )
  });
  let mut proposed_registry = loaded_registry.registry.clone();
  let change =
    ignore::add_ignore_with_member_fingerprints(&mut proposed_registry, parsed_fingerprint, reason, members, member_fingerprints);
  let registration = IgnoreRegistration {
    registry: loaded_registry,
    group,
    change,
  };
  let write = match ignore::save_ignore_file(root, &proposed_registry) {
    Ok(completed) => completed,
    Err(source) => {
      return Err(CliError::IgnorePersistence {
        registration: Box::new(registration),
        source,
      });
    }
  };
  let outcome = IgnoreCommandOutcome {
    registration,
    write,
  };
  let reported = match outcome.registration.change {
    IgnoreEntryRegistration::Added {
      ..
    } => writeln!(writer, "Added {fingerprint} to ignore list.").and_then(|()| {
      if outcome.registration.group.is_none() {
        writeln!(
          writer,
          "Note: no current duplicate group matches this fingerprint; the entry was recorded without member details."
        )
      } else {
        Ok(())
      }
    }),
    IgnoreEntryRegistration::AlreadyRegistered {
      ..
    } => writeln!(writer, "{fingerprint} is already in the ignore list."),
  };
  retain_report_outcome(outcome, reported, |completed, source| CliError::IgnoreReporting {
    outcome: Box::new(completed),
    source,
  })
}

/// Format one group member for ignore-entry documentation.
#[allow(
  clippy::single_call_fn,
  reason = "The member-location grammar must remain consistent with registry parsing and successor matching."
)]
fn display_member(root: &Path, member: &CodeUnit) -> String {
  format!(
    "{} ({}:{}-{})",
    member.name,
    display_path(Some(root), &member.file),
    member.line_start,
    member.line_end
  )
}

/// Record sorted, distinct native member identities using canonical hexadecimal spellings.
#[allow(
  clippy::single_call_fn,
  reason = "Canonical member identity sets own near-group registry stability independently from location formatting."
)]
fn record_member_fingerprints(group: &DuplicateGroup) -> Vec<RecordedFingerprint> {
  group
    .members
    .iter()
    .map(|member| member.fingerprint)
    .collect::<BTreeSet<_>>()
    .into_iter()
    .map(RecordedFingerprint::from)
    .collect()
}

/// List all ignored fingerprints.
///
/// # Errors
///
/// Returns a native registry-load failure, or preserves the loaded registry
/// with the native failure from writing its listing.
pub fn cmd_ignored<ParseError: Debug>(root: &Path, writer: &mut impl Write) -> CliResult<IgnoreFileLoad, ParseError> {
  let loaded_registry = ignore::load_ignore_file(root)?;
  let listing = if loaded_registry.registry.ignore.is_empty() {
    writeln!(writer, "No ignored fingerprints.")
  } else {
    write_ignore_entries(writer, "Ignored fingerprints:", &loaded_registry.registry.ignore)
  };
  if let Err(source) = listing {
    return Err(CliError::RegistryListing {
      registry: Box::new(loaded_registry),
      source,
    });
  }
  Ok(loaded_registry)
}

/// Preview or remove stale entries while retaining the original registry and every removed entry.
///
/// Member descriptions supply advisory successor hints during a preview. Unusable
/// locations remain typed observations and diagnostics without failing cleanup.
///
/// # Errors
///
/// Returns a native registry-load failure before cleanup. Persistence failures
/// retain the original registry, removed entries, and proposed write; reporting
/// failures retain the complete cleanup outcome. A dry run never saves the registry.
#[allow(
  clippy::single_call_fn,
  reason = "Registry cleanup owns stale-entry selection, dry-run behavior, persistence, and complete failure evidence."
)]
pub fn cmd_cleanup<ParseError: Debug>(
  root: &Path,
  result: &AnalysisResult<ParseError>,
  writer: &mut impl Write,
  dry_run: bool,
) -> CliResult<CleanupOutcome, ParseError> {
  let loaded_registry = ignore::load_ignore_file(root)?;
  let mut outcome = if dry_run {
    let stale = ignore::find_stale_entries(
      &loaded_registry.registry,
      &result.all_fingerprints,
      &result.all_member_fingerprint_sets,
    )
    .into_iter()
    .cloned()
    .collect();
    CleanupOutcome::Preview {
      registry: loaded_registry,
      stale,
      successors: Vec::new(),
    }
  } else {
    let mut proposed_registry = loaded_registry.registry.clone();
    let removed = ignore::remove_stale_entries(
      &mut proposed_registry,
      &result.all_fingerprints,
      &result.all_member_fingerprint_sets,
    );
    if removed.is_empty() {
      CleanupOutcome::Unchanged(loaded_registry)
    } else {
      let write = match ignore::save_ignore_file(root, &proposed_registry) {
        Ok(completed) => completed,
        Err(source) => {
          return Err(CliError::CleanupPersistence {
            registry: Box::new(loaded_registry),
            removed,
            source,
          });
        }
      };
      CleanupOutcome::Removed {
        registry: loaded_registry,
        removed,
        write,
      }
    }
  };
  let reporting = render_cleanup(writer, result, &mut outcome);
  retain_report_outcome(outcome, reporting, |completed, source| CliError::CleanupReporting {
    outcome: Box::new(completed),
    source,
  })
}

/// Render cleanup and retain advisory searches reached before any output failure.
#[allow(
  clippy::single_call_fn,
  reason = "Cleanup rendering retains registry decisions, persistence, and every advisory search reached before an output failure."
)]
fn render_cleanup<ParseError>(
  writer: &mut impl Write,
  result: &AnalysisResult<ParseError>,
  outcome: &mut CleanupOutcome,
) -> io::Result<()> {
  match *outcome {
    CleanupOutcome::Unchanged(_) => writeln!(writer, "No stale entries found."),
    CleanupOutcome::Preview {
      ref stale,
      ref mut successors,
      ..
    } => {
      if stale.is_empty() {
        return writeln!(writer, "No stale entries found.");
      }
      writeln!(writer, "Stale entries (dry run):")?;
      for entry in stale {
        write_ignore_entry(writer, entry)?;
        write_successor_hints(writer, entry, result, successors)?;
      }
      writeln!(writer, "\n{} stale entries would be removed.", stale.len())
    }
    CleanupOutcome::Removed {
      ref removed, ..
    } => {
      write_ignore_entries(writer, "Removed stale entries:", removed)?;
      writeln!(writer, "\nRemoved {} stale entries.", removed.len())
    }
  }
}

/// Suggest live groups that overlap a stale entry's recorded members.
///
/// When registered content is edited, the duplicate family usually survives
/// with a new fingerprint over shifted content. Pointing at live groups that
/// overlap the entry's recorded locations turns registry repair into a
/// guided rewrite instead of a search.
#[allow(
  clippy::single_call_fn,
  reason = "Advisory successor reporting retains completed searches even if the diagnostic stream fails."
)]
fn write_successor_hints<ParseError>(
  writer: &mut impl Write,
  entry: &IgnoreEntry,
  result: &AnalysisResult<ParseError>,
  successors: &mut Vec<IgnoreEntrySuccessors>,
) -> io::Result<()> {
  let members = entry.member_locations();
  // Suppressed groups count as successors: a stale entry can be re-paired
  // to a finding the rules hide from the default report.
  let candidates = members.iter().any(|recorded| recorded.location.is_ok()).then(|| {
    result
      .groups_with_suppressed()
      .map(|group| successor_candidate(group, &members))
      .collect()
  });
  let observation = IgnoreEntrySuccessors {
    entry: entry.clone(),
    members,
    candidates,
  };
  let reported = (|| {
    for recorded in &observation.members {
      if let Err(ref source) = recorded.location {
        writeln!(writer, "    unusable member location: {}: {source}", recorded.description)?;
      }
    }
    for candidate in observation.candidates.iter().flatten() {
      if let SuccessorCandidate::Overlapping(ref group) = *candidate {
        writeln!(
          writer,
          "    possible successor: {} ({}/{}, {} members)",
          group.fingerprint,
          group.dimension,
          group.match_kind,
          group.members.len()
        )?;
      }
    }
    Ok(())
  })();
  successors.push(observation);
  reported
}

/// Evaluate one complete group against usable recorded paths and source spans.
#[allow(
  clippy::single_call_fn,
  reason = "Successor classification owns location overlap and line-drift tolerance while retaining each candidate group."
)]
fn successor_candidate(group: &DuplicateGroup, members: &[IgnoreMemberObservation]) -> SuccessorCandidate {
  let overlapping = group.members.iter().any(|member| {
    members.iter().any(|recorded| {
      recorded.location.as_ref().is_ok_and(|location| {
        member.file.ends_with(&location.path)
          && member.line_start <= location.end.saturating_add(SUCCESSOR_LINE_SLACK)
          && location.start <= member.line_end.saturating_add(SUCCESSOR_LINE_SLACK)
      })
    })
  });
  if overlapping {
    SuccessorCandidate::Overlapping(group.clone())
  } else {
    SuccessorCandidate::NoOverlap(group.clone())
  }
}

/// Lines of drift tolerated when pairing stale entries with successors.
const SUCCESSOR_LINE_SLACK: usize = 5;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a titled list of ignore entries.
fn write_ignore_entries<'a>(writer: &mut impl Write, title: &str, entries: impl IntoIterator<Item = &'a IgnoreEntry>) -> io::Result<()> {
  writeln!(writer, "{title}")?;
  for entry in entries {
    write_ignore_entry(writer, entry)?;
  }
  Ok(())
}

/// An optional threshold and the native comparison made against one measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdDecision<Measurement> {
  /// The measurement was computed, but no threshold was configured.
  Unconfigured {
    /// Original measured count or percentage.
    observed: Measurement,
  },
  /// The configured threshold was compared with the original measurement.
  Compared {
    /// Original measured count or percentage.
    observed: Measurement,
    /// Maximum configured for this measurement.
    limit:    Measurement,
    /// Native partial ordering; `None` records an unordered comparison.
    ordering: Option<Ordering>,
  },
}

impl<Measurement: Copy + PartialOrd> ThresholdDecision<Measurement> {
  /// Preserve the measurement even when the threshold is absent or comparison is unordered.
  fn compare(limit: Option<Measurement>, observed: Measurement) -> Self {
    limit.map_or(
      Self::Unconfigured {
        observed,
      },
      |maximum| Self::Compared {
        observed,
        limit: maximum,
        ordering: observed.partial_cmp(&maximum),
      },
    )
  }

  /// Whether the native comparison established that the configured maximum was exceeded.
  const fn is_exceeded(&self) -> bool {
    matches!(*self, Self::Compared {
      ordering: Some(Ordering::Greater),
      ..
    })
  }

  /// Whether a configured threshold could not be ordered against its measurement.
  const fn is_unordered(&self) -> bool {
    matches!(*self, Self::Compared {
      ordering: None,
      ..
    })
  }
}

/// One check decision, retaining its match kind and native measurement type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GateDecision {
  /// A cross-dimension duplicate-group count and its optional threshold.
  Count {
    /// Exact or near duplicates being checked.
    match_kind: MatchKind,
    /// Complete count measurement and threshold comparison.
    decision:   ThresholdDecision<usize>,
  },
  /// A duplicate-line percentage and its optional threshold.
  Percent {
    /// Exact or near duplicates being checked.
    match_kind: MatchKind,
    /// Complete percentage measurement and threshold comparison.
    decision:   ThresholdDecision<f64>,
  },
}

impl GateDecision {
  /// Whether this decision establishes a threshold breach.
  const fn is_exceeded(&self) -> bool {
    match *self {
      Self::Count {
        ref decision, ..
      } => decision.is_exceeded(),
      Self::Percent {
        ref decision, ..
      } => decision.is_exceeded(),
    }
  }

  /// Whether this decision lacks an ordering for a configured threshold.
  #[allow(
    clippy::single_call_fn,
    reason = "Typed gate decisions own unordered-comparison detection across count and percentage measurements."
  )]
  const fn is_unordered(&self) -> bool {
    match *self {
      Self::Count {
        ref decision, ..
      } => decision.is_unordered(),
      Self::Percent {
        ref decision, ..
      } => decision.is_unordered(),
    }
  }

  /// Render an established breach without inventing one for an unset or unordered threshold.
  #[allow(
    clippy::single_call_fn,
    reason = "Threshold breach formatting depends on the complete typed comparison and its measurement unit."
  )]
  fn failure_summary(&self) -> Option<String> {
    match *self {
      Self::Count {
        match_kind,
        decision: ThresholdDecision::Compared {
          observed,
          limit,
          ordering: Some(Ordering::Greater),
        },
      } => Some(format!("{observed} {match_kind} duplicate groups (max: {limit})")),
      Self::Percent {
        match_kind,
        decision: ThresholdDecision::Compared {
          observed,
          limit,
          ordering: Some(Ordering::Greater),
        },
      } => Some(format!("{observed:.1}% {match_kind} duplicate lines (max: {limit:.1}%)")),
      Self::Count {
        ..
      }
      | Self::Percent {
        ..
      } => None,
    }
  }
}

/// A completed check evaluation, including passing, failing, unset, and unordered decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckOutcome {
  /// Complete statistics from which the measurements were calculated.
  pub stats:      Box<DuplicationStats>,
  /// Resolved thresholds after CLI overrides and configured defaults were combined.
  pub thresholds: CheckThresholds,
  /// Count decisions followed by percentage decisions, exact then near within each pair.
  pub gates:      Vec<GateDecision>,
}

/// Native count or percentage failure encountered while evaluating a check.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum CheckMeasurementFailure {
  /// Combining per-dimension group counts overflowed.
  #[error(transparent)]
  Count(#[from] GroupCountOverflow),
  /// A duplicate-line percentage could not be calculated.
  #[error(transparent)]
  Percentage(#[from] PercentageFailure),
}

/// Measurement failure with the complete decisions reached before it.
#[derive(Debug, Clone, PartialEq, Error)]
#[error("check measurement failed: {source}")]
pub struct CheckEvaluationFailure {
  /// Resolved thresholds selected for the interrupted evaluation.
  pub thresholds: CheckThresholds,
  /// Complete gate decisions produced before the failed measurement.
  pub completed:  Vec<GateDecision>,
  /// Original calculation failure, including its complete integer statistics and operands.
  pub source:     Box<CheckMeasurementFailure>,
}

/// Evaluate each gate before reporting, retaining completed decisions on a measurement failure.
#[allow(
  clippy::single_call_fn,
  reason = "Check evaluation is separate from rendering so calculation failures preserve all previously completed decisions."
)]
fn evaluate_check(thresholds: &CheckThresholds, stats: &DuplicationStats) -> Result<CheckOutcome, CheckEvaluationFailure> {
  let mut gates = Vec::with_capacity(4);
  for (match_kind, limit) in [
    (MatchKind::Exact, thresholds.exact_groups),
    (MatchKind::Near, thresholds.near_groups),
  ] {
    let observed = match stats.group_count(match_kind) {
      Ok(count) => count,
      Err(source) => {
        return Err(CheckEvaluationFailure {
          thresholds: *thresholds,
          completed:  gates,
          source:     Box::new(CheckMeasurementFailure::Count(source)),
        });
      }
    };
    gates.push(GateDecision::Count {
      match_kind,
      decision: ThresholdDecision::compare(limit, observed),
    });
  }
  for (match_kind, limit) in [
    (MatchKind::Exact, thresholds.exact_percent),
    (MatchKind::Near, thresholds.near_percent),
  ] {
    let measured = match match_kind {
      MatchKind::Exact => stats.exact_duplicate_percent(),
      MatchKind::Near => stats.near_duplicate_percent(),
    };
    let observed = match measured {
      Ok(percentage) => percentage,
      Err(source) => {
        return Err(CheckEvaluationFailure {
          thresholds: *thresholds,
          completed:  gates,
          source:     Box::new(CheckMeasurementFailure::Percentage(source)),
        });
      }
    };
    gates.push(GateDecision::Percent {
      match_kind,
      decision: ThresholdDecision::compare(limit, observed),
    });
  }
  Ok(CheckOutcome {
    stats: Box::new(stats.clone()),
    thresholds: *thresholds,
    gates,
  })
}

/// Render the fingerprint, optional reason, and member descriptions of one entry.
fn write_ignore_entry(writer: &mut impl Write, entry: &IgnoreEntry) -> io::Result<()> {
  write!(writer, "  {}", entry.fingerprint)?;
  if let Some(ref reason) = entry.reason {
    write!(writer, " (reason: {reason})")?;
  }
  if !entry.members.is_empty() {
    write!(writer, " [{}]", entry.members.join(", "))?;
  }
  writeln!(writer)
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;
  use std::cmp::Ordering;
  use std::collections::HashSet;
  use std::convert::Infallible;
  use std::env;
  use std::fmt;
  use std::fmt::Display;
  use std::fs;
  use std::io;
  use std::io::ErrorKind;
  use std::io::Write;
  use std::num::IntErrorKind;
  use std::path::Path;
  use std::path::PathBuf;
  use std::process::ExitCode;
  use std::string::FromUtf8Error;

  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;
  use thiserror::Error;

  use super::AnalysisCommandOutcome;
  use super::AnalysisOutput;
  use super::CheckEvaluationFailure;
  use super::CheckMeasurementFailure;
  use super::CheckOutcome;
  use super::CheckThresholds;
  use super::CleanupOutcome;
  use super::CliError;
  use super::CliResult;
  use super::Command;
  use super::CommandFailure;
  use super::CommandOutput;
  use super::CommonCliArgs;
  use super::ErrorReportFailure;
  use super::GateDecision;
  use super::IgnoreCommandOutcome;
  use super::IgnoreEntrySuccessors;
  use super::OutputFormat;
  use super::SuccessorCandidate;
  use super::ThresholdDecision;
  use super::cmd_check;
  use super::cmd_cleanup;
  use super::cmd_ignore;
  use super::create_reporter;
  use super::dispatch_analysis_command;
  use super::evaluate_check;
  use super::report_error;
  use super::run_command_with_analysis;
  use super::successor_candidate;
  use crate::AnalysisResult;
  use crate::analysis_result;
  use crate::code_unit::CodeUnit;
  use crate::code_unit::CodeUnitKind;
  use crate::code_unit::DetectionDimension;
  use crate::config::Config;
  use crate::duplicate_group;
  use crate::fingerprint::Fingerprint;
  use crate::fingerprint::RecordedFingerprint;
  use crate::grouper::DuplicateGroup;
  use crate::grouper::DuplicationStats;
  use crate::grouper::GroupCountOverflow;
  use crate::grouper::MatchKind;
  use crate::ignore;
  use crate::ignore::IgnoreEntry;
  use crate::ignore::IgnoreEntryRegistration;
  use crate::ignore::IgnoreFile;
  use crate::ignore::IgnoreFileError;
  use crate::ignore::IgnoreFileObservation;
  use crate::ignore::IgnoreMemberLocation;
  use crate::ignore::IgnoreMemberLocationError;
  use crate::ignore::IgnoreMemberObservation;
  use crate::output::ReportError;
  use crate::output::ReportOptions;
  use crate::output::ReportRenderer;
  use crate::output::ReportSection;
  use crate::output::Reporter;
  use crate::scanner::ScanConfig;
  use crate::scanner::scan_files;
  use crate::text_units::window_unit;

  /// Native command, fixture, and assertion failures observed by command tests.
  #[derive(Debug, Error)]
  enum CommandTestFailure {
    /// Fixture I/O failed with its native cause.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A command returned its typed failure.
    #[error(transparent)]
    Command(#[from] CliError),
    /// A registry operation returned its original typed failure.
    #[error(transparent)]
    Registry(#[from] IgnoreFileError),
    /// Output decoding retained the complete undecodable byte buffer.
    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),
    /// A behavioral assertion failed.
    #[error(transparent)]
    Assertion(#[from] ConditionFailure),
    /// A malformed fingerprint unexpectedly completed registration instead of yielding a native
    /// failure.
    #[error("invalid fingerprint registration unexpectedly succeeded: {outcome:?}; output: {output:?}")]
    UnexpectedRegistration {
      /// Complete registration and persistence returned by the unexpected success.
      outcome: Box<IgnoreCommandOutcome>,
      /// Every byte emitted by the unexpected operation.
      output:  Vec<u8>,
    },
    /// A check returned an unexpected result, with all emitted bytes retained.
    #[error("unexpected check result {outcome:?} after writing {output:?}: {source}")]
    Check {
      /// The complete result returned by the command.
      outcome: Box<CliResult<CheckOutcome>>,
      /// Bytes observed in the output destination after the command returned.
      output:  Vec<u8>,
      /// Failed behavioral expectation.
      source:  ConditionFailure,
    },
    /// Registration lost its decision, native failure, persisted document, or output.
    #[error("registry preservation failed: {source}; outcome: {outcome:?}; output: {output:?}; contents: {contents:?}")]
    RegistryPreservation {
      /// Complete command result observed by the test.
      outcome:  Box<CliResult<IgnoreCommandOutcome>>,
      /// Bytes emitted before the command returned.
      output:   Vec<u8>,
      /// Registry bytes observed after the command returned.
      contents: Vec<u8>,
      /// Assertion explaining the violated contract.
      source:   ConditionFailure,
    },
    /// Cleanup lost its original registry, selected entries, persisted document, or output.
    #[error("cleanup expectation failed: {source}; outcome: {outcome:?}; output: {output:?}; contents: {contents:?}")]
    CleanupExpectation {
      /// Complete cleanup result, including native persistence or reporting failures.
      outcome:  Box<CliResult<CleanupOutcome>>,
      /// Bytes observed in the output destination after cleanup returned.
      output:   Vec<u8>,
      /// Registry bytes observed after cleanup returned.
      contents: Vec<u8>,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
    /// A command lost its completed analysis, source observations, or report output.
    #[error("command outcome expectation failed: {source}; outcome: {outcome:?}; output: {output:?}")]
    CommandExpectation {
      /// Complete command outcome, including partial successes and its native cause.
      outcome: Box<RenderedCommandResult>,
      /// Bytes observed in the output destination after the command returned.
      output:  Vec<u8>,
      /// Assertion explaining the violated contract.
      source:  ConditionFailure,
    },
    /// Dispatch lost its native action result or emitted incorrect output.
    #[error("dispatch expectation failed: {source}; outcome: {outcome:?}; output: {output:?}")]
    DispatchExpectation {
      /// Complete result returned by the public dispatch boundary.
      outcome: Box<CliResult<AnalysisCommandOutcome>>,
      /// Complete bytes emitted by the dispatched action.
      output:  Vec<u8>,
      /// Failed behavioral expectation.
      source:  ConditionFailure,
    },
    /// Gate evaluation returned an unexpected complete result.
    #[error("check evaluation expectation failed: {source}; outcome: {outcome:?}")]
    Evaluation {
      /// Complete gate result or native count failure observed by the test.
      outcome: Box<Result<CheckOutcome, CheckEvaluationFailure>>,
      /// Failed behavioral expectation.
      source:  ConditionFailure,
    },
    /// Successor classification changed a complete group or its line-drift decision.
    #[error("successor boundary expectation failed: {source}; recorded: {recorded:?}; observed: {observed:?}; expected: {expected:?}")]
    SuccessorExpectation {
      /// Complete recorded locations supplied to successor matching.
      recorded: Vec<IgnoreMemberObservation>,
      /// Both candidates with their observed classifications and complete groups.
      observed: Box<[SuccessorCandidate; 2]>,
      /// Independently expected classifications and complete groups.
      expected: Box<[SuccessorCandidate; 2]>,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
    /// A count failure lost its native evidence or rendered a misleading check report.
    #[error("count-check expectation failed: {source}; outcome: {outcome:?}; output: {output:?}")]
    CountCheck {
      /// Complete command result, including the original statistics on overflow.
      outcome: Box<CliResult<CheckOutcome>>,
      /// Complete report bytes emitted before the command returned.
      output:  Vec<u8>,
      /// Failed behavioral expectation.
      source:  ConditionFailure,
    },
    /// Error rendering failed with its original operation failure retained.
    #[error(transparent)]
    Reporting(#[from] ErrorReportFailure<CliError>),
    /// Terminal reporting lost its status, original error, or writing failure.
    #[error("terminal reporting expectation failed: {source}; outcome: {outcome:?}; file contents: {contents:?}")]
    ReportingExpectation {
      /// Complete rendering result, including both failures when writing fails.
      outcome:  Box<Result<ExitCode, ErrorReportFailure<CliError>>>,
      /// File contents observed after the attempted write.
      contents: Vec<u8>,
      /// Failed semantic expectation.
      source:   ConditionFailure,
    },
    /// Lazy preparation changed callback execution or the caller's error family.
    #[error("preparation callback expectation failed: {source}; outcome: {outcome:?}; invoked: {invoked}; output: {output:?}")]
    CallbackExpectation {
      /// Complete request, command result, and original native preparation failure.
      outcome: Box<PreparedCommandResult>,
      /// Whether the analysis callback actually ran.
      invoked: bool,
      /// Bytes observed in the command's output destination after it returned.
      output:  Vec<u8>,
      /// Failed semantic expectation.
      source:  ConditionFailure,
    },
  }

  /// Complete rendered command result observed by CLI behavior tests.
  type RenderedCommandResult = Result<CommandOutput<ReportRenderer>, CommandFailure<ReportRenderer>>;

  /// Complete lazy-preparation result, including the native callback failure.
  type PreparedCommandResult = Result<CommandOutput<CountingReporter>, CommandFailure<CountingReporter, Infallible, FromUtf8Error>>;

  /// Attach the complete command, callback observation, and output to a preparation assertion.
  fn retain_preparation_evidence(
    outcome: PreparedCommandResult,
    invoked: bool,
    output: Vec<u8>,
    assertion: &Result<(), ConditionFailure>,
  ) -> Result<(), CommandTestFailure> {
    assertion.map_err(|source| CommandTestFailure::CallbackExpectation {
      outcome: Box::new(outcome),
      invoked,
      output,
      source,
    })
  }

  /// Build a content-addressed line window at the requested source location.
  fn window_member(seed: &str, file: &str, line_start: usize, line_end: usize) -> CodeUnit {
    window_unit(Path::new(file), "line window", CodeUnitKind::LineWindow, line_start, line_end, &[
      seed.to_owned(),
    ])
  }

  /// Pair a complete line group with the independently expected registry metadata.
  fn line_registration_fixture() -> (DuplicateGroup, IgnoreEntry) {
    let members = vec![
      window_member("alpha", "src/a.rs", 10, 14),
      window_member("beta", "src/b.rs", 20, 24),
    ];
    let mut member_fingerprints: Vec<_> = members
      .iter()
      .map(|member| RecordedFingerprint::from(member.fingerprint))
      .collect();
    member_fingerprints.sort_unstable_by(|first, second| first.input().cmp(second.input()));
    let fingerprint = Fingerprint::from_bytes(b"group");
    let entry = IgnoreEntry {
      fingerprint: RecordedFingerprint::from(fingerprint),
      reason: Some("intentional family".to_owned()),
      members: vec![
        "line window (src/a.rs:10-14)".to_owned(),
        "line window (src/b.rs:20-24)".to_owned(),
      ],
      member_fingerprints,
    };
    (
      duplicate_group(DetectionDimension::Line, MatchKind::Exact, fingerprint, 1.0, members),
      entry,
    )
  }

  /// Explicit native roots remain unchanged while an omitted root observes the working directory.
  #[test]
  fn root_resolution_preserves_explicit_paths_and_observes_the_default_directory() -> Result<(), CommandTestFailure> {
    let explicit_path = PathBuf::from("requested/root");
    let explicit = CommonCliArgs {
      path: Some(explicit_path.clone()),
      ..Default::default()
    };
    let current_directory = env::current_dir()?;
    ensure(
      explicit.root()? == explicit_path && CommonCliArgs::default().root()? == current_directory,
      "explicit roots retain their native spelling while an omitted root uses the observed working directory",
    )
    .map(drop)?;
    Ok(())
  }

  /// Start with a result containing no observed groups or statistics.
  fn empty_result() -> AnalysisResult {
    analysis_result(DuplicationStats::default(), Vec::new(), Vec::new(), Vec::new())
  }

  /// Prepare empty findings with a reporter that records every requested rendering operation.
  fn counting_analysis(config: Config) -> AnalysisOutput<CountingReporter> {
    AnalysisOutput {
      config,
      result: empty_result(),
      scans: Vec::new(),
      reporter: CountingReporter::default(),
    }
  }

  /// Initialization remains lazy and its native caller-owned failure is unchanged.
  #[test]
  fn preparation_preserves_caller_errors_and_skips_unused_initialization() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    for (command, should_invoke) in [
      (Command::Ignored, false),
      (
        Command::Ignore {
          fingerprint: "unapplied fingerprint".to_owned(),
          reason:      Some("unapplied reason".to_owned()),
        },
        true,
      ),
    ] {
      let invoked = Cell::new(false);
      let mut output = Vec::new();
      let outcome = run_command_with_analysis(workspace.path(), &command, &mut output, || {
        invoked.set(true);
        String::from_utf8(vec![0xff])
          .map(|decoded_root| Config {
            root: PathBuf::from(decoded_root),
            ..Config::default()
          })
          .map(counting_analysis)
      });
      let expected_outcome = if should_invoke {
        matches!(outcome, Err(CommandFailure::Preparation {
          ref root, command: Command::Ignore { ref fingerprint, ref reason }, ref source,
        }) if root == workspace.path() && fingerprint == "unapplied fingerprint"
          && reason.as_deref() == Some("unapplied reason") && source.as_bytes() == [0xff])
          && output.is_empty()
      } else {
        matches!(outcome, Ok(CommandOutput::Ignored(ref loaded))
          if loaded.path == ignore::ignore_file_path(workspace.path())
            && loaded.registry == IgnoreFile::default()
            && matches!(loaded.observation, IgnoreFileObservation::Absent { ref source }
              if source.kind() == ErrorKind::NotFound))
          && output == b"No ignored fingerprints.\n"
      };
      let assertion = ensure(
        expected_outcome && invoked.get() == should_invoke,
        "preparation failure retains the full unapplied request and native error while ignored listings do not initialize",
      )
      .map(drop);
      retain_preparation_evidence(outcome, invoked.get(), output, &assertion)?;
    }
    Ok(())
  }

  /// Listing preserves the loaded document across successful output and native write failure.
  #[test]
  fn ignored_listing_preserves_registry_and_output_failures() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let registry_path = ignore::ignore_file_path(workspace.path());
    let document = "# retained source\n[[ignore]]\nfingerprint = \"deadbeefdeadbeef\"\nreason = \"intentional\"\nmembers = [\"first\", \
                    \"second\"]\nmember_fingerprints = [\"aaaa\", \"bbbb\"]\n";
    fs::write(&registry_path, document)?;
    let expected_registry = IgnoreFile {
      ignore: vec![IgnoreEntry {
        fingerprint:         RecordedFingerprint::parse("deadbeefdeadbeef".to_owned()),
        reason:              Some("intentional".to_owned()),
        members:             vec!["first".to_owned(), "second".to_owned()],
        member_fingerprints: vec![
          RecordedFingerprint::parse("aaaa".to_owned()),
          RecordedFingerprint::parse("bbbb".to_owned()),
        ],
      }],
    };
    let output_path = workspace.path().join("listing.txt");
    for reject_write in [false, true] {
      fs::write(&output_path, b"existing contents")?;
      let mut writer = fs::OpenOptions::new().read(true).write(!reject_write).open(&output_path)?;
      let invoked = Cell::new(false);
      let outcome = run_command_with_analysis(workspace.path(), &Command::Ignored, &mut writer, || {
        invoked.set(true);
        Ok::<_, FromUtf8Error>(counting_analysis(Config::default()))
      });
      let output = fs::read(&output_path)?;
      let retained = match outcome {
        Ok(CommandOutput::Ignored(ref loaded)) if !reject_write => {
          loaded.path == registry_path
            && loaded.registry == expected_registry
            && matches!(loaded.observation, IgnoreFileObservation::Read { ref contents } if contents == document)
        }
        Err(CommandFailure::Ignored {
          ref root,
          ref source,
        }) if reject_write && root == workspace.path() => matches!(**source,
          CliError::RegistryListing {
            ref registry,
            source: ref native,
          } if native.raw_os_error().is_some()
            && registry.path == registry_path
            && registry.registry == expected_registry
            && matches!(registry.observation, IgnoreFileObservation::Read { ref contents } if contents == document)
        ),
        Ok(
          CommandOutput::Ignored(_)
          | CommandOutput::Analyzed {
            ..
          },
        )
        | Err(_) => false,
      };
      let expected_output: &[u8] = if reject_write {
        b"existing contents"
      } else {
        b"Ignored fingerprints:\n  deadbeefdeadbeef (reason: intentional) [first, second]\n"
      };
      let assertion = ensure(
        retained && !invoked.get() && output == expected_output,
        "listing preserves native registry evidence and output status without invoking analysis",
      )
      .map(drop);
      retain_preparation_evidence(outcome, invoked.get(), output, &assertion)?;
    }
    Ok(())
  }

  /// Invalid registry input fails with the original request before preparation is invoked.
  #[test]
  fn ignored_loading_failure_retains_request_and_skips_preparation() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = ignore::ignore_file_path(workspace.path());
    let document = "[[ignore]\nfingerprint = \"unreadable registry\"\n";
    fs::write(&path, document)?;
    let invoked = Cell::new(false);
    let mut output = Vec::new();
    let outcome = run_command_with_analysis(workspace.path(), &Command::Ignored, &mut output, || {
      invoked.set(true);
      Ok::<_, FromUtf8Error>(counting_analysis(Config::default()))
    });
    let assertion = ensure(
      matches!(outcome, Err(CommandFailure::Ignored { ref root, ref source })
        if root == workspace.path()
          && matches!(**source, CliError::Registry(IgnoreFileError::Decode { path: ref observed, ref contents, .. })
            if *observed == path && contents == document))
        && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2)
        && !invoked.get()
        && output.is_empty(),
      "registry loading retains the requested root, original document, and native decoding failure before analysis or output",
    )
    .map(drop);
    retain_preparation_evidence(outcome, invoked.get(), output, &assertion)
  }

  /// Direct dispatch performs registry listing without using the supplied analysis renderer.
  #[test]
  fn dispatch_ignored_lists_registry_without_rendering_analysis() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let prepared = counting_analysis(Config::default());
    let mut output = Vec::new();
    let outcome = dispatch_analysis_command(workspace.path(), &Command::Ignored, &prepared, &mut output);
    ensure(
      matches!(outcome, Ok(AnalysisCommandOutcome::Ignored(ref loaded))
        if loaded.path == ignore::ignore_file_path(workspace.path())
          && loaded.registry == IgnoreFile::default()
          && matches!(loaded.observation, IgnoreFileObservation::Absent { ref source }
            if source.kind() == ErrorKind::NotFound))
        && output == b"No ignored fingerprints.\n"
        && (
          prepared.reporter.full_renders.get(),
          prepared.reporter.stats_renders.get(),
          prepared.reporter.sections.take(),
        ) == (0, 0, Vec::new()),
      "direct ignored dispatch returns the native registry load and listing without rendering analysis",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::DispatchExpectation {
      outcome: Box::new(outcome),
      output,
      source,
    })
  }

  /// Obtain a real registration rejection without manufacturing a native parser error.
  fn rejected_fingerprint_registration(root: &Path) -> Result<CliError, CommandTestFailure> {
    let mut output = Vec::new();
    match cmd_ignore(root, "invalid", None, &empty_result(), &mut output) {
      Err(failure) => Ok(failure),
      Ok(outcome) => Err(CommandTestFailure::UnexpectedRegistration {
        outcome: Box::new(outcome),
        output,
      }),
    }
  }

  /// Error rendering preserves operational status and avoids repeating check output.
  #[test]
  fn terminal_error_reporting_preserves_status_and_existing_check_output() -> Result<(), CommandTestFailure> {
    let mut output = Vec::new();
    let workspace = TempDir::new()?;
    let failure = rejected_fingerprint_registration(workspace.path())?;
    let exit_code = failure.exit_code();
    let status = report_error(failure, exit_code, &mut output)?;
    ensure(
      status == ExitCode::from(2) && output == b"Error: Invalid fingerprint: invalid: invalid digit found in string\n",
      "operational errors retain status two and their complete shared diagnostic",
    )
    .map(drop)?;

    let before = output.clone();
    let thresholds = CheckThresholds {
      exact_groups: Some(0),
      ..CheckThresholds::default()
    };
    let check = evaluate_check(&thresholds, &stats_with_groups(1, 0)).map_err(CliError::CheckEvaluation)?;
    let check_failure = CliError::CheckFailed(Box::new(check));
    let check_exit_code = check_failure.exit_code();
    let check_status = report_error(check_failure, check_exit_code, &mut output)?;
    ensure(
      check_status == ExitCode::from(1) && output == before,
      "check failure retains status one without repeating its already-rendered diagnostic",
    )
    .map(drop)?;
    Ok(())
  }

  /// A failed diagnostic write retains both the original operation error and native I/O error.
  #[test]
  fn terminal_error_reporting_retains_both_failures() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("diagnostic.txt");
    fs::write(&path, b"existing contents")?;
    let mut read_only = fs::File::open(&path)?;
    let failure = rejected_fingerprint_registration(workspace.path())?;
    let exit_code = failure.exit_code();
    let outcome = report_error(failure, exit_code, &mut read_only);
    let contents = fs::read(&path)?;
    ensure(
      matches!(outcome, Err(ErrorReportFailure::Operation { failure: ref original_failure, ref source })
        if matches!(**original_failure, CliError::InvalidFingerprint { ref root, reason: None, source: ref rejected }
          if root == workspace.path() && rejected.input == "invalid" && *rejected.source.kind() == IntErrorKind::InvalidDigit)
          && source.raw_os_error().is_some())
        && contents == b"existing contents",
      "failed reporting preserves the original typed failure and native writing error without changing the file",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::ReportingExpectation {
      outcome: Box::new(outcome),
      contents,
      source,
    })
  }

  /// Place the supplied duplicate family in the line-detection result.
  fn result_with_line_group(group: DuplicateGroup) -> AnalysisResult {
    let mut result = empty_result();
    result.line_exact_groups = vec![group];
    result
  }

  /// Set the two AST group counts independently of other dimensions.
  fn stats_with_groups(exact_groups: usize, near_groups: usize) -> DuplicationStats {
    DuplicationStats {
      exact_duplicate_groups: exact_groups,
      near_duplicate_groups: near_groups,
      ..Default::default()
    }
  }

  /// Construct independent count decisions with unconfigured zero-line percentages.
  fn zero_line_check_expectation(
    statistics: DuplicationStats,
    thresholds: &CheckThresholds,
    [exact, near]: [ThresholdDecision<usize>; 2],
  ) -> CheckOutcome {
    CheckOutcome {
      stats:      Box::new(statistics),
      thresholds: *thresholds,
      gates:      vec![
        GateDecision::Count {
          match_kind: MatchKind::Exact,
          decision:   exact,
        },
        GateDecision::Count {
          match_kind: MatchKind::Near,
          decision:   near,
        },
        GateDecision::Percent {
          match_kind: MatchKind::Exact,
          decision:   ThresholdDecision::Unconfigured {
            observed: 0.0
          },
        },
        GateDecision::Percent {
          match_kind: MatchKind::Near,
          decision:   ThresholdDecision::Unconfigured {
            observed: 0.0
          },
        },
      ],
    }
  }

  /// Prepare native configuration and scans around supplied findings for command handoff tests.
  fn command_analysis_output(root: &Path, statistics: DuplicationStats) -> Result<AnalysisOutput<ReportRenderer>, CommandTestFailure> {
    let config = Config::load(root).map_err(CliError::Config)?;
    let scan = scan_files(&ScanConfig::new(root.to_path_buf())).map_err(|source| CliError::Preparation {
      config: Box::new(config.clone()),
      scans:  Vec::new(),
      source: Box::new(source),
    })?;
    Ok(AnalysisOutput {
      config,
      result: analysis_result(statistics, Vec::new(), Vec::new(), Vec::new()),
      scans: vec![scan],
      reporter: create_reporter(OutputFormat::Json, Some(root), ReportOptions::default()),
    })
  }

  /// Exercise a prepared check and retain its complete command outcome and emitted document.
  fn check_prepared_thresholds(
    root: &Path,
    statistics: DuplicationStats,
    thresholds: &CheckThresholds,
    check: impl FnOnce(&RenderedCommandResult, &[u8]) -> Result<(), ConditionFailure>,
  ) -> Result<(), CommandTestFailure> {
    let prepared = command_analysis_output(root, statistics)?;
    let mut output = Vec::new();
    let outcome = run_command_with_analysis(
      root,
      &Command::Check {
        thresholds: *thresholds
      },
      &mut output,
      || Ok(prepared),
    );
    check(&outcome, &output).map_err(|source| CommandTestFailure::CommandExpectation {
      outcome: Box::new(outcome),
      output,
      source,
    })
  }

  /// Record every rendering path without interrupting command execution.
  #[derive(Default)]
  struct CountingReporter {
    /// Number of complete reports requested.
    full_renders:  Cell<usize>,
    /// Number of statistics-only reports requested.
    stats_renders: Cell<usize>,
    /// Individual group sections requested, in call order.
    sections:      Cell<Vec<ReportSection>>,
  }

  impl fmt::Debug for CountingReporter {
    /// Render every recorded call without consuming the section observations.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      let sections = self.sections.take();
      let rendered = formatter
        .debug_struct("CountingReporter")
        .field("full_renders", &self.full_renders.get())
        .field("stats_renders", &self.stats_renders.get())
        .field("sections", &sections)
        .finish();
      self.sections.set(sections);
      rendered
    }
  }

  impl Reporter for CountingReporter {
    fn report_full<ParseError: Display>(&self, _result: &AnalysisResult<ParseError>, _writer: &mut impl Write) -> Result<(), ReportError> {
      self.full_renders.set(self.full_renders.get().saturating_add(1));
      Ok(())
    }

    fn report_stats(&self, _stats: &DuplicationStats, _writer: &mut impl Write) -> Result<(), ReportError> {
      self.stats_renders.set(self.stats_renders.get().saturating_add(1));
      Ok(())
    }

    fn report_groups(&self, _groups: &[DuplicateGroup], _writer: &mut impl Write, section: ReportSection) -> Result<(), ReportError> {
      let mut sections = self.sections.take();
      sections.push(section);
      self.sections.set(sections);
      Ok(())
    }
  }

  /// Evaluation retains both breached count comparisons and explicitly unconfigured measurements.
  #[test]
  fn evaluate_check_preserves_configured_and_unconfigured_counts() -> Result<(), CommandTestFailure> {
    for (thresholds, decisions) in [
      (
        CheckThresholds {
          exact_groups: Some(0),
          near_groups: Some(0),
          ..Default::default()
        },
        [ThresholdDecision::Compared {
          observed: 1,
          limit:    0,
          ordering: Some(Ordering::Greater),
        }; 2],
      ),
      (
        CheckThresholds::default(),
        [ThresholdDecision::Unconfigured {
          observed: 1
        }; 2],
      ),
    ] {
      let outcome = evaluate_check(&thresholds, &stats_with_groups(1, 1));
      let expected = zero_line_check_expectation(stats_with_groups(1, 1), &thresholds, decisions);
      ensure(
        outcome == Ok(expected),
        "the check retains both count decisions and both measurements with no percentage threshold",
      )
      .map(drop)
      .map_err(|source| CommandTestFailure::Evaluation {
        outcome: Box::new(outcome),
        source,
      })?;
    }
    Ok(())
  }

  /// A later count failure preserves the exact-count decision already completed.
  #[test]
  fn evaluate_check_retains_completed_decisions_before_count_overflow() -> Result<(), CommandTestFailure> {
    let statistics = DuplicationStats {
      exact_duplicate_groups: 2,
      near_duplicate_groups: usize::MAX,
      sub_near_groups: 1,
      ..DuplicationStats::default()
    };
    let thresholds = CheckThresholds {
      exact_groups: Some(1),
      ..CheckThresholds::default()
    };
    let outcome = evaluate_check(&thresholds, &statistics);
    let expected = CheckEvaluationFailure {
      thresholds,
      completed: vec![GateDecision::Count {
        match_kind: MatchKind::Exact,
        decision:   ThresholdDecision::Compared {
          observed: 2,
          limit:    1,
          ordering: Some(Ordering::Greater),
        },
      }],
      source: Box::new(CheckMeasurementFailure::Count(GroupCountOverflow {
        stats:      Box::new(statistics),
        match_kind: MatchKind::Near,
        dimension:  DetectionDimension::SubAst,
        completed:  usize::MAX,
        incoming:   1,
      })),
    };
    ensure(
      outcome == Err(expected),
      "a near-count overflow retains the completed exact-count comparison and complete native overflow evidence",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::Evaluation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Passing checks return the native equal and less-than comparisons used for their verdict.
  #[test]
  fn cmd_check_returns_complete_passing_decisions() -> Result<(), CommandTestFailure> {
    let statistics = DuplicationStats {
      total_lines: 100,
      exact_duplicate_groups: 1,
      near_duplicate_groups: 2,
      exact_duplicate_lines: 10,
      near_duplicate_lines: 20,
      ..DuplicationStats::default()
    };
    let thresholds = CheckThresholds {
      exact_groups:  Some(1),
      near_groups:   Some(3),
      exact_percent: Some(20.0),
      near_percent:  Some(20.0),
    };
    let expected = CheckOutcome {
      stats: Box::new(statistics.clone()),
      thresholds,
      gates: vec![
        GateDecision::Count {
          match_kind: MatchKind::Exact,
          decision:   ThresholdDecision::Compared {
            observed: 1,
            limit:    1,
            ordering: Some(Ordering::Equal),
          },
        },
        GateDecision::Count {
          match_kind: MatchKind::Near,
          decision:   ThresholdDecision::Compared {
            observed: 2,
            limit:    3,
            ordering: Some(Ordering::Less),
          },
        },
        GateDecision::Percent {
          match_kind: MatchKind::Exact,
          decision:   ThresholdDecision::Compared {
            observed: 10.0,
            limit:    20.0,
            ordering: Some(Ordering::Less),
          },
        },
        GateDecision::Percent {
          match_kind: MatchKind::Near,
          decision:   ThresholdDecision::Compared {
            observed: 20.0,
            limit:    20.0,
            ordering: Some(Ordering::Equal),
          },
        },
      ],
    };
    let result = analysis_result(statistics, Vec::new(), Vec::new(), Vec::new());
    let reporter = CountingReporter::default();
    let mut output = Vec::new();
    let outcome = cmd_check(&Config::default(), &result, &reporter, &mut output, &thresholds);
    ensure(
      matches!(outcome, Ok(ref observed) if *observed == expected)
        && (reporter.stats_renders.get(), reporter.full_renders.get(), reporter.sections.take()) == (1, 0, Vec::new())
        && output == b"\nCheck passed.\n",
      "passing checks retain all measurements, native comparisons, and thresholds after one statistics report",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::Check {
      outcome: Box::new(outcome),
      output,
      source,
    })
  }

  /// An unordered configured comparison cannot produce a passing verdict.
  #[test]
  fn cmd_check_retains_unordered_comparisons_without_reporting_success() -> Result<(), CommandTestFailure> {
    let result = empty_result();
    let thresholds = CheckThresholds {
      exact_percent: Some(f64::NAN),
      ..CheckThresholds::default()
    };
    let reporter = CountingReporter::default();
    let mut output = Vec::new();
    let outcome = cmd_check(&Config::default(), &result, &reporter, &mut output, &thresholds);
    ensure(
      matches!(outcome, Err(CliError::CheckUnordered(ref check))
        if *check.stats == result.stats && check.gates.len() == 4
          && check.thresholds.exact_percent.is_some_and(f64::is_nan)
          && check.gates.iter().any(|decision| matches!(*decision, GateDecision::Percent {
            match_kind: MatchKind::Exact,
            decision: ThresholdDecision::Compared { observed, limit, ordering: None },
          } if observed.total_cmp(&0.0) == Ordering::Equal && limit.is_nan())))
        && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2)
        && (reporter.stats_renders.get(), reporter.full_renders.get()) == (0, 0)
        && output.is_empty(),
      "an unordered threshold retains its native values and comparison result before any verdict is rendered",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::Check {
      outcome: Box::new(outcome),
      output,
      source,
    })
  }

  /// A failed check report preserves the complete evaluation for either passing or failing
  /// thresholds.
  #[test]
  fn cmd_check_preserves_decisions_when_report_output_fails() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("read-only-output.txt");
    fs::write(&path, b"existing contents")?;
    let result = analysis_result(stats_with_groups(1, 1), Vec::new(), Vec::new(), Vec::new());
    let reporter = create_reporter(OutputFormat::Json, None, ReportOptions::default());
    for thresholds in [CheckThresholds::default(), CheckThresholds {
      exact_groups: Some(0),
      ..CheckThresholds::default()
    }] {
      let expected = evaluate_check(&thresholds, &result.stats).map_err(CliError::CheckEvaluation)?;
      let mut writer = fs::File::open(&path)?;
      let outcome = cmd_check(&Config::default(), &result, &reporter, &mut writer, &thresholds);
      let output = fs::read(&path)?;
      ensure(
        matches!(outcome, Err(CliError::CheckReporting {
          outcome: ref check, source: ReportError::Write(ref native),
        }) if **check == expected && native.raw_os_error().is_some())
          && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2)
          && output == b"existing contents",
        "an output-write failure retains the complete prior check and native I/O cause without altering the destination",
      )
      .map(drop)
      .map_err(|source| CommandTestFailure::Check {
        outcome: Box::new(outcome),
        output,
        source,
      })?;
    }
    Ok(())
  }

  /// Unrepresentable group totals return an operational failure before rendering a check verdict.
  #[test]
  fn cmd_check_preserves_count_failure_without_rendering() -> Result<(), CommandTestFailure> {
    let result = analysis_result(
      DuplicationStats {
        exact_duplicate_groups: usize::MAX,
        sub_exact_groups: 1,
        ..DuplicationStats::default()
      },
      Vec::new(),
      Vec::new(),
      Vec::new(),
    );
    let reporter = create_reporter(OutputFormat::Text, None, ReportOptions::default());
    let mut output = Vec::new();
    let outcome = cmd_check(&Config::default(), &result, &reporter, &mut output, &CheckThresholds::default());
    ensure(
      matches!(outcome, Err(CliError::CheckEvaluation(ref failure))
        if matches!(*failure.source, CheckMeasurementFailure::Count(ref source)
          if *source.stats == result.stats && source.match_kind == MatchKind::Exact
            && source.dimension == DetectionDimension::SubAst && source.completed == usize::MAX && source.incoming == 1)
          && failure.completed.is_empty() && failure.thresholds == CheckThresholds::default())
        && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2)
        && output.is_empty(),
      "count overflow preserves its native calculation evidence and status two without printing a check verdict",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::CountCheck {
      outcome: Box::new(outcome),
      output,
      source,
    })
  }

  /// Multiple breached gates retain every decision while rendering one full report and one summary
  /// per breach.
  #[test]
  fn cmd_check_renders_once_on_multi_gate_failure() -> Result<(), CommandTestFailure> {
    let result = analysis_result(stats_with_groups(1, 1), Vec::new(), Vec::new(), Vec::new());
    let reporter = CountingReporter::default();
    let mut sink = Vec::new();
    let thresholds = CheckThresholds {
      exact_groups: Some(0),
      near_groups: Some(0),
      ..Default::default()
    };

    let expected = evaluate_check(&thresholds, &result.stats).map_err(CliError::CheckEvaluation)?;
    let outcome = cmd_check(&Config::default(), &result, &reporter, &mut sink, &thresholds);
    ensure(
      matches!(outcome, Err(CliError::CheckFailed(ref observed)) if **observed == expected)
        && (reporter.full_renders.get(), reporter.stats_renders.get(), reporter.sections.take()) == (1, 0, Vec::new())
        && sink == b"\nCheck FAILED: 1 exact duplicate groups (max: 0)\n\nCheck FAILED: 1 near duplicate groups (max: 0)\n",
      "the complete failed check survives one full report and exactly one summary for each breached gate",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::Check {
      outcome: Box::new(outcome),
      output: sink,
      source,
    })
  }

  /// Registration retains the matched group, native absence, added entry, and persisted document.
  #[test]
  fn cmd_ignore_records_member_fingerprints_from_the_live_group() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (group, expected_entry) = line_registration_fixture();
    let result = result_with_line_group(group.clone());
    let registry_path = ignore::ignore_file_path(workspace.path());
    let mut output = Vec::new();
    let outcome = cmd_ignore(
      workspace.path(),
      expected_entry.fingerprint.input(),
      expected_entry.reason.clone(),
      &result,
      &mut output,
    );
    let contents = fs::read(&registry_path)?;
    let expected_change = IgnoreEntryRegistration::Added {
      fingerprint: group.fingerprint,
      entry:       expected_entry.clone(),
    };
    ensure(
      matches!(outcome, Ok(ref completed)
        if completed.registration.registry.path == registry_path
          && completed.registration.registry.registry == IgnoreFile::default()
          && matches!(completed.registration.registry.observation, IgnoreFileObservation::Absent { source: ref absence }
            if absence.kind() == ErrorKind::NotFound)
          && completed.registration.group.as_ref() == Some(&group)
          && completed.registration.change == expected_change
          && completed.write.path == registry_path && completed.write.registry.ignore == vec![expected_entry]
          && completed.write.contents.as_bytes() == contents)
        && output == format!("Added {} to ignore list.\n", group.fingerprint).as_bytes(),
      "registration preserves the complete matched group, native absence, insertion decision, write input, and success diagnostic",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::RegistryPreservation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// An unmatched registration preserves previous entries and explicitly retains the missing group.
  #[test]
  fn cmd_ignore_retains_unmatched_registration_and_existing_entries() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (group, existing_entry) = line_registration_fixture();
    let result = result_with_line_group(group);
    let original = IgnoreFile {
      ignore: vec![existing_entry],
    };
    let previous_write = ignore::save_ignore_file(workspace.path(), &original)?;
    let unmatched = Fingerprint::from_bytes(b"unmatched");
    let expected_entry = IgnoreEntry {
      fingerprint:         RecordedFingerprint::from(unmatched),
      reason:              None,
      members:             Vec::new(),
      member_fingerprints: Vec::new(),
    };
    let mut expected_registry = original.clone();
    expected_registry.ignore.push(expected_entry.clone());
    let mut output = Vec::new();
    let outcome = cmd_ignore(workspace.path(), &unmatched.to_hex(), None, &result, &mut output);
    let contents = fs::read(&previous_write.path)?;
    let expected_change = IgnoreEntryRegistration::Added {
      fingerprint: unmatched,
      entry:       expected_entry,
    };
    ensure(
      matches!(outcome, Ok(ref completed)
        if completed.registration.registry.path == previous_write.path
          && completed.registration.registry.registry == original
          && matches!(completed.registration.registry.observation, IgnoreFileObservation::Read { contents: ref observed }
            if *observed == previous_write.contents)
          && completed.registration.group.is_none() && completed.registration.change == expected_change
          && completed.write.path == previous_write.path && completed.write.registry == expected_registry
          && completed.write.contents.as_bytes() == contents)
        && output
          == format!(
            "Added {unmatched} to ignore list.\nNote: no current duplicate group matches this fingerprint; the entry was recorded without \
             member details.\n"
          )
          .as_bytes(),
      "an unmatched registration retains the original registry and adds an identity-only entry with an explicit missing-group diagnostic",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::RegistryPreservation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// Repeated registration preserves original metadata and returns the unapplied request
  /// accurately.
  #[test]
  fn cmd_ignore_retains_existing_metadata_and_unapplied_request() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (group, registered) = line_registration_fixture();
    let original = IgnoreFile {
      ignore: vec![registered.clone()],
    };
    let previous_write = ignore::save_ignore_file(workspace.path(), &original)?;
    let requested = IgnoreEntry {
      fingerprint:         registered.fingerprint.clone(),
      reason:              Some("replacement reason".to_owned()),
      members:             Vec::new(),
      member_fingerprints: Vec::new(),
    };
    let mut output = Vec::new();
    let outcome = cmd_ignore(
      workspace.path(),
      registered.fingerprint.input(),
      requested.reason.clone(),
      &empty_result(),
      &mut output,
    );
    let contents = fs::read(&previous_write.path)?;
    let expected_change = IgnoreEntryRegistration::AlreadyRegistered {
      fingerprint: group.fingerprint,
      requested,
      registered,
    };
    ensure(
      matches!(outcome, Ok(ref completed)
        if completed.registration.registry.path == previous_write.path
          && completed.registration.registry.registry == original
          && matches!(completed.registration.registry.observation, IgnoreFileObservation::Read { contents: ref observed }
            if *observed == previous_write.contents)
          && completed.registration.group.is_none() && completed.registration.change == expected_change
          && completed.write == previous_write && completed.write.contents.as_bytes() == contents)
        && output == format!("{} is already in the ignore list.\n", group.fingerprint).as_bytes(),
      "repeated registration retains the original metadata and full unapplied request without claiming that an entry was added",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::RegistryPreservation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// A native output failure retains the successful registration and persisted registry.
  #[test]
  fn cmd_ignore_preserves_persistence_when_reporting_fails() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (group, expected_entry) = line_registration_fixture();
    let result = result_with_line_group(group.clone());
    let registry_path = ignore::ignore_file_path(workspace.path());
    let output_path = workspace.path().join("registration-output.txt");
    fs::write(&output_path, b"existing output")?;
    let mut writer = fs::File::open(&output_path)?;
    let outcome = cmd_ignore(
      workspace.path(),
      expected_entry.fingerprint.input(),
      expected_entry.reason.clone(),
      &result,
      &mut writer,
    );
    let contents = fs::read(&registry_path)?;
    let output = fs::read(&output_path)?;
    let expected_change = IgnoreEntryRegistration::Added {
      fingerprint: group.fingerprint,
      entry:       expected_entry.clone(),
    };
    ensure(
      matches!(outcome, Err(CliError::IgnoreReporting { outcome: ref completed, ref source })
        if source.raw_os_error().is_some()
          && completed.registration.registry.path == registry_path
          && completed.registration.registry.registry == IgnoreFile::default()
          && matches!(completed.registration.registry.observation, IgnoreFileObservation::Absent { source: ref absence }
            if absence.kind() == ErrorKind::NotFound)
          && completed.registration.group.as_ref() == Some(&group)
          && completed.registration.change == expected_change
          && completed.write.path == registry_path && completed.write.registry.ignore == vec![expected_entry]
          && completed.write.contents.as_bytes() == contents)
        && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2)
        && output == b"existing output",
      "reporting failure retains the completed registration, successful write, and native output error",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::RegistryPreservation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// Invalid identity input retains the complete request and fails before reading or writing the
  /// registry.
  #[test]
  fn invalid_fingerprint_retains_request_and_native_failure_before_registry_access() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = ignore::ignore_file_path(workspace.path());
    let original = b"this document is deliberately not valid TOML\n";
    fs::write(&path, original)?;
    for (input, kind) in [
      ("", IntErrorKind::Empty),
      ("not_hex", IntErrorKind::InvalidDigit),
      ("10000000000000000", IntErrorKind::PosOverflow),
    ] {
      let reason = Some("unapplied registration reason".to_owned());
      let mut output = Vec::new();
      let outcome = cmd_ignore(workspace.path(), input, reason.clone(), &empty_result(), &mut output);
      let contents = fs::read(&path)?;
      ensure(
        matches!(outcome, Err(CliError::InvalidFingerprint { ref root, reason: ref retained_reason, ref source })
          if root == workspace.path() && *retained_reason == reason
            && source.input == input && *source.source.kind() == kind)
          && contents == original
          && output.is_empty(),
        "invalid identity input preserves the root, reason, original spelling, native error, and untouched registry",
      )
      .map(drop)
      .map_err(|source| CommandTestFailure::RegistryPreservation {
        outcome: Box::new(outcome),
        output,
        contents,
        source,
      })?;
    }
    Ok(())
  }

  /// Invalid registry syntax prevents registration before either mutation or success output.
  #[test]
  fn malformed_registry_stops_registration_before_writing() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = ignore::ignore_file_path(workspace.path());
    let contents = "[[ignore]\nfingerprint = \"retain this document\"\n";
    fs::write(&path, contents)?;
    let mut output = Vec::new();
    let outcome = cmd_ignore(
      workspace.path(),
      &Fingerprint::from_bytes(b"new registration").to_hex(),
      Some("proposed registration".to_owned()),
      &empty_result(),
      &mut output,
    );
    let after = fs::read(&path)?;
    ensure(
      matches!(outcome, Err(CliError::Registry(IgnoreFileError::Decode { path: ref observed_path, contents: ref observed_contents, .. }))
        if *observed_path == path && observed_contents == contents)
        && after == contents.as_bytes()
        && output.is_empty(),
      "registration preserves a malformed registry and returns its decoding failure before saving or reporting success",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::RegistryPreservation {
      outcome: Box::new(outcome),
      output,
      contents: after,
      source,
    })
  }

  /// A completed check preserves the requested command, native preparation, renderer, and
  /// decisions.
  #[test]
  fn successful_command_retains_analysis_and_check_outcome() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("source.rs");
    fs::write(&path, "fn inspected_source() {}\n")?;
    let thresholds = CheckThresholds {
      exact_groups: Some(0),
      near_groups: Some(0),
      ..CheckThresholds::default()
    };
    let statistics = stats_with_groups(0, 0);
    let expected = evaluate_check(&thresholds, &statistics).map_err(CliError::CheckEvaluation)?;
    check_prepared_thresholds(workspace.path(), statistics, &thresholds, |outcome, output| {
      ensure(
        matches!(*outcome, Ok(CommandOutput::Analyzed {
        command: Command::Check { thresholds: ref requested }, ref analysis,
        outcome: AnalysisCommandOutcome::Check(ref checked),
      }) if *requested == thresholds && *checked == expected
        && analysis.config.root == workspace.path() && analysis.config.sources.len() == 2
        && analysis.result.stats == *checked.stats
        && analysis.scans.len() == 1
        && analysis.scans.iter().all(|scan| scan.files().collect::<Vec<_>>() == [path.as_path()])
        && matches!(analysis.reporter, ReportRenderer::Json(ref reporter) if reporter.base_path.as_deref() == Some(workspace.path())))
          && output.ends_with(b"\nCheck passed.\n"),
        "successful dispatch returns the complete analysis and every check decision with the original requested command",
      )
      .map(drop)
    })
  }

  /// A rejected check retains its original thresholds, completed comparisons, and prepared
  /// analysis.
  #[test]
  fn rejected_check_retains_request_analysis_and_decisions() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let thresholds = CheckThresholds {
      exact_groups: Some(0),
      near_groups: Some(3),
      ..CheckThresholds::default()
    };
    let statistics = stats_with_groups(2, 1);
    let expected = zero_line_check_expectation(statistics.clone(), &thresholds, [
      ThresholdDecision::Compared {
        observed: 2,
        limit:    0,
        ordering: Some(Ordering::Greater),
      },
      ThresholdDecision::Compared {
        observed: 1,
        limit:    3,
        ordering: Some(Ordering::Less),
      },
    ]);
    check_prepared_thresholds(workspace.path(), statistics, &thresholds, |outcome, _output| {
      ensure(
        matches!(*outcome, Err(CommandFailure::Analyzed {
        ref root, command: Command::Check { thresholds: requested }, ref analysis, ref source,
      }) if root == workspace.path() && requested == thresholds
        && analysis.config.root == workspace.path() && analysis.config.sources.len() == 2
        && analysis.result.stats == *expected.stats
        && analysis.scans.len() == 1 && analysis.scans.iter().all(|scan| scan.files().next().is_none())
        && matches!(analysis.reporter, ReportRenderer::Json(ref reporter) if reporter.base_path.as_deref() == Some(workspace.path()))
        && matches!(**source, CliError::CheckFailed(ref checked) if **checked == expected))
          && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 1),
        "threshold rejection preserves passing, failing, and unconfigured decisions with the request, native preparation, renderer, and \
         status",
      )
      .map(drop)
    })
  }

  /// A failed report preserves the native analysis and preparation completed before output began.
  #[test]
  fn failed_report_preserves_completed_analysis_configuration_and_scans() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("source.rs");
    let contents = "fn preserved_source() {}\n";
    fs::write(&path, contents)?;
    let expected_stats = stats_with_groups(2, 3);
    let output = command_analysis_output(workspace.path(), expected_stats.clone())?;
    let mut read_only = fs::File::open(&path)?;
    let outcome = run_command_with_analysis(workspace.path(), &Command::Report, &mut read_only, || Ok(output));
    let after = fs::read(&path)?;
    ensure(
      matches!(outcome, Err(CommandFailure::Analyzed { ref root, command: Command::Report, ref analysis, ref source })
        if root == workspace.path() && analysis.config.root == workspace.path() && analysis.config.sources.len() == 2
          && analysis.result.stats == expected_stats
          && analysis.scans.len() == 1 && analysis.scans.iter().all(|completed| completed.files().collect::<Vec<_>>() == vec![path.as_path()])
          && matches!(analysis.reporter, ReportRenderer::Json(ref reporter)
            if reporter.base_path.as_deref() == Some(workspace.path()))
          && matches!(**source, CliError::Report(ReportError::Write(ref native)) if native.raw_os_error().is_some()))
        && after == contents.as_bytes(),
      "a report-write failure retains the original request, renderer, complete analysis, and native cause without changing the input file",
    ).map(drop)
    .map_err(|source| CommandTestFailure::CommandExpectation {
      outcome: Box::new(outcome),
      output: after,
      source,
    })
  }

  /// Cleanup previews successors and removals while preserving the entire registry.
  #[test]
  fn cleanup_dry_run_suggests_successors_for_stale_entries() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let mut ignore_file = IgnoreFile::default();
    ignore_file.ignore.push(IgnoreEntry {
      fingerprint:         RecordedFingerprint::parse("deadbeefdeadbeef".to_owned()),
      reason:              None,
      members:             vec!["line window (src/a.rs:10-14)".to_owned()],
      member_fingerprints: Vec::new(),
    });
    let previous_write = ignore::save_ignore_file(workspace.path(), &ignore_file)?;

    let successor_fingerprint = Fingerprint::from_bytes(b"successor");
    let members = vec![
      window_member("shifted", "src/a.rs", 12, 16),
      window_member("shifted", "src/b.rs", 30, 34),
    ];
    let group = duplicate_group(DetectionDimension::Line, MatchKind::Exact, successor_fingerprint, 1.0, members);
    let expected_successors = ignore_file
      .ignore
      .iter()
      .map(|entry| IgnoreEntrySuccessors {
        entry:      entry.clone(),
        members:    vec![IgnoreMemberObservation {
          description: "line window (src/a.rs:10-14)".to_owned(),
          location:    Ok(IgnoreMemberLocation {
            path:  PathBuf::from("src/a.rs"),
            start: 10,
            end:   14,
          }),
        }],
        candidates: Some(vec![SuccessorCandidate::Overlapping(group.clone())]),
      })
      .collect::<Vec<_>>();
    let result = result_with_line_group(group);

    let mut output = Vec::new();
    let outcome = cmd_cleanup(workspace.path(), &result, &mut output, true);
    let contents = fs::read(&previous_write.path)?;
    ensure(
      matches!(outcome, Ok(CleanupOutcome::Preview { ref registry, ref stale, ref successors })
        if registry.path == previous_write.path && registry.registry == ignore_file && *stale == ignore_file.ignore
          && *successors == expected_successors
          && matches!(registry.observation, IgnoreFileObservation::Read { contents: ref observed }
            if *observed == previous_write.contents))
        && contents == previous_write.contents.as_bytes()
        && output
          == format!(
            "Stale entries (dry run):\n  deadbeefdeadbeef [line window (src/a.rs:10-14)]\n    possible successor: {successor_fingerprint} \
             (line/exact, 2 members)\n\n1 stale entries would be removed.\n"
          )
          .as_bytes(),
      "a cleanup preview retains the full registry and stale entries, reports successors, and preserves the original document",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::CleanupExpectation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// A successor may drift five lines, while a sixth separating line prevents a match.
  #[test]
  fn successor_candidates_respect_line_drift_boundaries() -> Result<(), CommandTestFailure> {
    let recorded = vec![IgnoreMemberObservation {
      description: "line window (src/a.rs:10-14)".to_owned(),
      location:    Ok(IgnoreMemberLocation {
        path:  PathBuf::from("src/a.rs"),
        start: 10,
        end:   14,
      }),
    }];
    let candidate = |start, end| {
      duplicate_group(
        DetectionDimension::Line,
        MatchKind::Exact,
        Fingerprint::from_bytes(b"moving candidate"),
        1.0,
        vec![
          window_member("moving", "src/a.rs", start, end),
          window_member("unrelated", "src/b.rs", 30, 34),
        ],
      )
    };
    let boundary = candidate(19, 23);
    let beyond = candidate(20, 24);
    let observed = [
      successor_candidate(&boundary, &recorded),
      successor_candidate(&beyond, &recorded),
    ];
    let expected = [SuccessorCandidate::Overlapping(boundary), SuccessorCandidate::NoOverlap(beyond)];
    ensure(
      observed == expected,
      "successor classification preserves both complete groups at and beyond the allowed line drift",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::SuccessorExpectation {
      recorded,
      observed: Box::new(observed),
      expected: Box::new(expected),
      source,
    })
  }

  /// Pair usable and malformed recorded paths with one overlapping and one unrelated group.
  fn successor_search_fixture() -> (IgnoreEntry, AnalysisResult, Vec<SuccessorCandidate>) {
    let entry = IgnoreEntry {
      fingerprint:         RecordedFingerprint::from(Fingerprint::from_bytes(b"stale location family")),
      reason:              None,
      members:             vec![
        "line window (src/with spaces/a.rs:10-14)".to_owned(),
        "line window (a.rs:10-14)".to_owned(),
        "line window (src/broken.rs:ten-14)".to_owned(),
      ],
      member_fingerprints: Vec::new(),
    };
    let overlapping = duplicate_group(
      DetectionDimension::Line,
      MatchKind::Exact,
      Fingerprint::from_bytes(b"overlapping family"),
      1.0,
      vec![
        window_member("first", "src/with spaces/a.rs", 12, 16),
        window_member("second", "src/other.rs", 30, 34),
      ],
    );
    let unrelated = duplicate_group(
      DetectionDimension::Line,
      MatchKind::Exact,
      Fingerprint::from_bytes(b"unrelated family"),
      1.0,
      vec![
        window_member("suffix only", "src/with spaces/beta.rs", 12, 16),
        window_member("elsewhere", "src/different.rs", 30, 34),
      ],
    );
    let mut result = result_with_line_group(overlapping.clone());
    result.line_exact_groups.push(unrelated.clone());
    let expected = vec![
      SuccessorCandidate::Overlapping(overlapping),
      SuccessorCandidate::NoOverlap(unrelated),
    ];
    (entry, result, expected)
  }

  /// Malformed locations remain nonfatal while path components determine complete candidate
  /// decisions.
  #[test]
  fn cleanup_preview_retains_location_failures_and_candidate_decisions() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (entry, result, expected) = successor_search_fixture();
    let registry = IgnoreFile {
      ignore: vec![entry.clone()],
    };
    let previous_write = ignore::save_ignore_file(workspace.path(), &registry)?;
    let mut output = Vec::new();
    let outcome = cmd_cleanup(workspace.path(), &result, &mut output, true);
    let contents = fs::read(&previous_write.path)?;
    let diagnostic = b"    unusable member location: line window (src/broken.rs:ten-14): ";
    ensure(
      matches!(outcome, Ok(CleanupOutcome::Preview { registry: ref loaded, ref stale, ref successors })
        if loaded.path == previous_write.path && loaded.registry == registry && *stale == vec![entry.clone()]
          && matches!(loaded.observation, IgnoreFileObservation::Read { contents: ref observed }
            if *observed == previous_write.contents)
          && matches!(successors.as_slice(), &[IgnoreEntrySuccessors { entry: ref original, ref members, candidates: Some(ref candidates) }]
            if *original == entry && *candidates == expected
              && members.iter().map(|recorded| &recorded.description).eq(entry.members.iter())
              && matches!(members.last(), Some(&IgnoreMemberObservation {
                location: Err(IgnoreMemberLocationError::Start { ref path, ref source }), ..
              }) if path == Path::new("src/broken.rs") && *source.kind() == IntErrorKind::InvalidDigit)))
        && contents == previous_write.contents.as_bytes()
        && output.split(|byte| *byte == b'\n').any(|line| line.starts_with(diagnostic))
        && output.ends_with(b"\n1 stale entries would be removed.\n"),
      "cleanup retains malformed location evidence and both candidate outcomes without confusing a filename suffix with a path component",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::CleanupExpectation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// An unusable recorded description leaves successor comparison unattempted without failing
  /// cleanup.
  #[test]
  fn cleanup_preview_retains_an_unattempted_successor_search() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (group, mut entry) = line_registration_fixture();
    entry.fingerprint = RecordedFingerprint::from(Fingerprint::from_bytes(b"stale unusable location"));
    entry.members = vec!["member without a source location".to_owned()];
    entry.member_fingerprints.clear();
    let registry = IgnoreFile {
      ignore: vec![entry.clone()],
    };
    let previous_write = ignore::save_ignore_file(workspace.path(), &registry)?;
    let result = result_with_line_group(group);
    let expected = IgnoreEntrySuccessors {
      entry:      entry.clone(),
      members:    vec![IgnoreMemberObservation {
        description: "member without a source location".to_owned(),
        location:    Err(IgnoreMemberLocationError::DescriptionFormat),
      }],
      candidates: None,
    };
    let mut output = Vec::new();
    let outcome = cmd_cleanup(workspace.path(), &result, &mut output, true);
    let contents = fs::read(&previous_write.path)?;
    ensure(
      matches!(outcome, Ok(CleanupOutcome::Preview { registry: ref loaded, ref stale, ref successors })
        if loaded.path == previous_write.path && loaded.registry == registry && *stale == vec![entry]
          && matches!(loaded.observation, IgnoreFileObservation::Read { contents: ref observed }
            if *observed == previous_write.contents)
          && *successors == vec![expected])
        && contents == previous_write.contents.as_bytes()
        && output.ends_with(b"\n1 stale entries would be removed.\n"),
      "cleanup returns the complete unusable location and an unattempted search while retaining the registry and successful preview",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::CleanupExpectation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// Output failure after location analysis retains its native parsing and candidate outcomes.
  #[test]
  fn cleanup_retains_successor_search_when_hint_output_fails() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (entry, result, expected) = successor_search_fixture();
    let registry = IgnoreFile {
      ignore: vec![entry.clone()],
    };
    let previous_write = ignore::save_ignore_file(workspace.path(), &registry)?;
    let prefix = format!("Stale entries (dry run):\n  {} [{}]\n", entry.fingerprint, entry.members.join(", "));
    let mut output = vec![0; prefix.len()];
    let mut writer = io::Cursor::new(output.as_mut_slice());
    let outcome = cmd_cleanup(workspace.path(), &result, &mut writer, true);
    let contents = fs::read(&previous_write.path)?;
    ensure(
      matches!(outcome, Err(CliError::CleanupReporting { outcome: ref retained, ref source })
        if source.kind() == ErrorKind::WriteZero
          && matches!(**retained, CleanupOutcome::Preview { registry: ref loaded, ref stale, ref successors }
            if loaded.path == previous_write.path && loaded.registry == registry && *stale == vec![entry.clone()]
              && matches!(loaded.observation, IgnoreFileObservation::Read { contents: ref observed }
                if *observed == previous_write.contents)
              && matches!(successors.as_slice(), &[IgnoreEntrySuccessors { entry: ref original, ref members, candidates: Some(ref candidates) }]
                if *original == entry && *candidates == expected
                  && members.iter().map(|recorded| &recorded.description).eq(entry.members.iter())
                  && members.iter().any(|recorded| recorded.location.is_err()))))
        && output == prefix.as_bytes()
        && contents == previous_write.contents.as_bytes(),
      "a native bounded-writer failure retains the reached successor search, every parsed member outcome, and the unchanged registry",
    ).map(drop).map_err(|source| CommandTestFailure::CleanupExpectation {
      outcome: Box::new(outcome), output, contents, source,
    })
  }

  /// Applying cleanup retains the removed entries and persists only the still-live registry.
  #[test]
  fn cleanup_preserves_removed_entries_and_successful_write() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (group, live_entry) = line_registration_fixture();
    let mut result = empty_result();
    result.all_fingerprints = HashSet::from([group.fingerprint]);
    let stale_entry = IgnoreEntry {
      fingerprint:         RecordedFingerprint::from(Fingerprint::from_bytes(b"stale content")),
      reason:              Some("old content".to_owned()),
      members:             vec!["former member (src/old.rs:10-14)".to_owned()],
      member_fingerprints: Vec::new(),
    };
    let original = IgnoreFile {
      ignore: vec![stale_entry.clone(), live_entry.clone()],
    };
    let previous_write = ignore::save_ignore_file(workspace.path(), &original)?;
    let mut output = Vec::new();
    let outcome = cmd_cleanup(workspace.path(), &result, &mut output, false);
    let contents = fs::read(&previous_write.path)?;
    ensure(
      matches!(outcome, Ok(CleanupOutcome::Removed { ref registry, ref removed, ref write })
        if registry.path == previous_write.path && registry.registry == original
          && matches!(registry.observation, IgnoreFileObservation::Read { contents: ref observed }
            if *observed == previous_write.contents)
          && *removed == vec![stale_entry.clone()]
          && write.path == previous_write.path && write.registry.ignore == vec![live_entry]
          && write.contents.as_bytes() == contents)
        && output
          == format!(
            "Removed stale entries:\n  {} (reason: old content) [former member (src/old.rs:10-14)]\n\nRemoved 1 stale entries.\n",
            stale_entry.fingerprint,
          )
          .as_bytes(),
      "applying cleanup returns the complete original registry, removed entry, and successful write while retaining the live entry",
    )
    .map(drop)
    .map_err(|source| CommandTestFailure::CleanupExpectation {
      outcome: Box::new(outcome),
      output,
      contents,
      source,
    })
  }

  /// Empty selections preserve the exact source document in both preview and applying modes.
  #[test]
  fn cleanup_without_stale_entries_preserves_the_original_document() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let fingerprint = Fingerprint::from_bytes(b"live content");
    let path = ignore::ignore_file_path(workspace.path());
    let document = format!("# preserve this original comment\n[[ignore]]\nfingerprint = \"{fingerprint}\"\nreason = \"still live\"\n");
    fs::write(&path, &document)?;
    let original = IgnoreFile {
      ignore: vec![IgnoreEntry {
        fingerprint:         RecordedFingerprint::from(fingerprint),
        reason:              Some("still live".to_owned()),
        members:             Vec::new(),
        member_fingerprints: Vec::new(),
      }],
    };
    let mut result = empty_result();
    result.all_fingerprints = HashSet::from([fingerprint]);
    for dry_run in [false, true] {
      let mut output = Vec::new();
      let outcome = cmd_cleanup(workspace.path(), &result, &mut output, dry_run);
      let contents = fs::read(&path)?;
      let retained = match outcome {
        Ok(CleanupOutcome::Unchanged(ref registry)) if !dry_run => Some(registry),
        Ok(CleanupOutcome::Preview {
          ref registry,
          ref stale,
          ref successors,
        }) if dry_run && stale.is_empty() && successors.is_empty() => Some(registry),
        Ok(
          CleanupOutcome::Unchanged(_)
          | CleanupOutcome::Preview {
            ..
          }
          | CleanupOutcome::Removed {
            ..
          },
        )
        | Err(_) => None,
      };
      ensure(
        retained.is_some_and(|registry| {
          registry.path == path
            && registry.registry == original
            && matches!(registry.observation, IgnoreFileObservation::Read { contents: ref observed } if *observed == document)
        }) && contents == document.as_bytes()
          && output == b"No stale entries found.\n",
        "an empty cleanup selection returns the correct mode and full native load without rewriting the original registry document",
      )
      .map(drop)
      .map_err(|source| CommandTestFailure::CleanupExpectation {
        outcome: Box::new(outcome),
        output,
        contents,
        source,
      })?;
    }
    Ok(())
  }

  /// A failed cleanup diagnostic retains the completed preview or successful removal and write.
  #[test]
  fn cleanup_retains_completed_work_when_reporting_fails() -> Result<(), CommandTestFailure> {
    let workspace = TempDir::new()?;
    let (_, stale_entry) = line_registration_fixture();
    let original = IgnoreFile {
      ignore: vec![stale_entry.clone()],
    };
    let output_path = workspace.path().join("cleanup-output.txt");
    fs::write(&output_path, b"existing output")?;
    for dry_run in [false, true] {
      let previous_write = ignore::save_ignore_file(workspace.path(), &original)?;
      let mut writer = fs::File::open(&output_path)?;
      let outcome = cmd_cleanup(workspace.path(), &empty_result(), &mut writer, dry_run);
      let contents = fs::read(&previous_write.path)?;
      let output = fs::read(&output_path)?;
      let completed = match outcome {
        Err(CliError::CleanupReporting {
          outcome: ref retained,
          ref source,
        }) if source.raw_os_error().is_some() => Some(retained.as_ref()),
        Ok(_) | Err(_) => None,
      };
      let registry = completed.and_then(|retained| match *retained {
        CleanupOutcome::Preview {
          ref registry,
          ref stale,
          ref successors,
        } if dry_run && *stale == vec![stale_entry.clone()] && successors.is_empty() && contents == previous_write.contents.as_bytes() => {
          Some(registry)
        }
        CleanupOutcome::Removed {
          ref registry,
          ref removed,
          ref write,
        } if !dry_run
          && *removed == vec![stale_entry.clone()]
          && write.registry == IgnoreFile::default()
          && write.path == previous_write.path
          && write.contents.as_bytes() == contents =>
        {
          Some(registry)
        }
        CleanupOutcome::Preview {
          ..
        }
        | CleanupOutcome::Removed {
          ..
        }
        | CleanupOutcome::Unchanged(_) => None,
      });
      ensure(
        registry.is_some_and(|loaded| {
          loaded.path == previous_write.path
            && loaded.registry == original
            && matches!(loaded.observation, IgnoreFileObservation::Read { contents: ref observed } if *observed == previous_write.contents)
        }) && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2)
          && output == b"existing output",
        "cleanup reporting failure retains its completed preview or persisted removal, original registry, and native output error",
      )
      .map(drop)
      .map_err(|source| CommandTestFailure::CleanupExpectation {
        outcome: Box::new(outcome),
        output,
        contents,
        source,
      })?;
    }
    Ok(())
  }
}
