//! `cargo-dupes`: the Rust-only Cargo subcommand. Parses the shared CLI
//! surface and wires [`RustAnalyzer`] into `dupes_core::cli::run_analysis`.

use std::io;
use std::process::ExitCode;

use clap::Parser;
use dupes_core::cli;
use dupes_core::cli::CliError;
use dupes_core::cli::Command;
use dupes_core::cli::CommonCliArgs;
use dupes_core::output::ReportRenderer;
use dupes_rust::RustAnalyzer;
use dupes_rust::parser::RustParseError;

/// Parsed Cargo command and the shared duplicate-detection options.
#[derive(Debug, Parser)]
#[command(name = "cargo-dupes", version, about = "Detect duplicate code in Rust codebases")]
struct Cli {
  /// When invoked as `cargo dupes`, cargo passes "dupes" as the first arg.
  #[arg(hide = true, default_value = "")]
  _cargo_subcommand: String,

  /// Requested operation, defaulting to a full report.
  #[command(subcommand)]
  command: Option<Command>,

  /// Options shared with the multi-language command.
  #[command(flatten)]
  common: CommonCliArgs,
}

/// Startup and shared command failures retain their native evidence.
#[derive(Debug, thiserror::Error)]
enum CommandError {
  /// Resolving the command root failed before analysis.
  #[error(transparent)]
  Root(#[from] CliError),
  /// The shared Rust command failed.
  #[error(transparent)]
  Command(#[from] cli::CommandFailure<ReportRenderer, RustParseError>),
}

impl CommandError {
  /// Preserve the shared command's documented exit-status policy.
  #[allow(
    clippy::single_call_fn,
    reason = "The frontend owns the exit-status mapping from its complete startup or shared-command failure."
  )]
  const fn exit_code(&self) -> u8 {
    match *self {
      Self::Root(_) => 2,
      Self::Command(ref source) => source.exit_code(),
    }
  }
}

/// Resolve Cargo arguments and dispatch Rust analysis through the shared workflow.
#[allow(
  clippy::single_call_fn,
  reason = "Command execution stays separate from terminal reporting so failures retain their complete shared outcome."
)]
fn run(arguments: &Cli) -> Result<cli::CommandOutput<ReportRenderer, RustParseError>, CommandError> {
  let root = arguments.common.root()?;
  let command = arguments.command.as_ref().unwrap_or(&Command::Report);
  let stdout = io::stdout();
  let mut writer = stdout.lock();

  cli::run_command_with_analysis(&root, command, &mut writer, || {
    let analyzer = RustAnalyzer::new();
    let overrides = arguments.common.overrides(vec!["rs".to_owned()]);
    cli::run_analysis(&analyzer, &root, arguments.common.format, &overrides)
  })
  .map_err(CommandError::from)
}

/// Return normally after reporting, retaining both failures if reporting fails.
fn main() -> Result<ExitCode, cli::ErrorReportFailure<CommandError>> {
  cli::finish_command_line(Cli::try_parse(), run, CommandError::exit_code, &mut io::stderr().lock())
}
