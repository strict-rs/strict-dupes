//! `code-dupes`: the multi-language CLI binary. Parses the shared CLI
//! surface, auto-detects or accepts a `--language`, selects the matching
//! analyzer, and wires it into `dupes_core::cli::run_analysis`.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::ValueEnum;
use dupes_core::analyzer::LanguageAnalyzer;
use dupes_core::cli;
use dupes_core::cli::CliError;
use dupes_core::cli::Command;
use dupes_core::cli::CommonCliArgs;
use dupes_core::code_unit::CodeUnit;
use dupes_core::config::AnalysisConfig;
use dupes_core::output::ReportRenderer;
use dupes_python::PythonAnalyzer;
use dupes_python::PythonAnalyzerError;
use dupes_rust::RustAnalyzer;
use dupes_rust::parser::RustParseError;
use walkdir::DirEntry;
use walkdir::WalkDir;

/// Parsed multi-language command, language selection, and shared options.
#[derive(Debug, Parser)]
#[command(
  name = "code-dupes",
  version,
  about = "Detect duplicate code across multiple languages"
)]
struct Cli {
  /// Requested operation, defaulting to a report when omitted.
  #[command(subcommand)]
  command: Option<Command>,

  /// Language to analyze. Auto-detected from file extensions if omitted.
  #[arg(short, long, global = true)]
  language: Option<Language>,

  /// Options shared with the Rust-only Cargo command.
  #[command(flatten)]
  common: CommonCliArgs,
}

/// Supported AST analyzers and language-neutral text analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Language {
  /// Rust syntax analyzed through `syn`.
  Rust,
  /// Python syntax analyzed through tree-sitter.
  Python,
  /// Token and line analysis without a language parser.
  Generic,
}

impl Cli {
  /// Resolve the requested command, defaulting to a full report.
  fn requested_command(&self) -> Command {
    self.command.clone().unwrap_or(Command::Report)
  }

  /// Convert CLI options into shared core overrides.
  fn overrides(&self) -> cli::CliOverrides {
    self
      .common
      .overrides(GENERIC_EXTENSIONS.iter().map(ToString::to_string).collect())
  }
}

impl Language {
  /// Static file extension registry — avoids constructing analyzers for detection.
  const fn extensions(self) -> &'static [&'static str] {
    match self {
      Self::Rust => &["rs"],
      Self::Python => &["py", "pyi"],
      Self::Generic => &[],
    }
  }

  /// Languages with an AST analyzer available for automatic selection.
  const AST: &[Self] = &[Self::Rust, Self::Python];
}

impl fmt::Display for Language {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::Rust => write!(f, "rust"),
      Self::Python => write!(f, "python"),
      Self::Generic => write!(f, "generic"),
    }
  }
}

/// Extensions scanned by generic token and line detection.
const GENERIC_EXTENSIONS: &[&str] = &[
  "rs", "py", "pyi", "md", "markdown", "toml", "yaml", "yml", "json", "js", "jsx", "ts", "tsx", "css", "scss", "sh", "bash", "zsh", "fish",
  "just", "txt",
];

/// The caller's explicit selection or a language inferred from completed discovery.
#[derive(Debug)]
enum LanguageSelection {
  /// The caller selected the analyzer without filesystem discovery.
  Requested(Language),
  /// A completed discovery selected one language and retained its native observations.
  Detected {
    /// Language selected by the extension registry.
    language:  Language,
    /// Complete discovery used to make the selection.
    discovery: LanguageDiscovery,
  },
}

impl LanguageSelection {
  /// Prepare analysis for the selected language and the root that supplied its discovery.
  #[allow(
    clippy::single_call_fn,
    reason = "Language selection owns analyzer construction and the discovery root supplied to shared analysis."
  )]
  fn prepare_analysis(
    &self,
    requested_root: &Path,
    arguments: &Cli,
  ) -> Result<cli::AnalysisOutput<ReportRenderer, LanguageParseError>, AnalysisPreparationError> {
    let (language, analysis_root) = match *self {
      Self::Requested(language) => (language, requested_root),
      Self::Detected {
        language,
        ref discovery,
      } => (language, discovery.root.as_path()),
    };
    let analyzer = resolve_analyzer(language)?;
    let overrides = arguments.overrides();
    cli::run_analysis(&analyzer, analysis_root, arguments.common.format, &overrides).map_err(AnalysisPreparationError::from)
  }
}

/// A directory excluded from automatic language selection before descent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryExclusion {
  /// Cargo build output is not a source-language signal.
  BuildOutput,
  /// A hidden directory below the requested root is outside discovery.
  Hidden,
}

/// One native walker entry and the metadata used for language discovery.
#[derive(Debug)]
struct DiscoveredEntry {
  /// Native entry, preserving link identity and depth.
  entry:    DirEntry,
  /// Resolved metadata, following file links as the existing selection contract requires.
  metadata: fs::Metadata,
  /// The directory policy that prevented descent, when applicable.
  excluded: Option<DirectoryExclusion>,
}

/// All observations completed during one automatic-language discovery.
#[derive(Debug)]
struct LanguageDiscovery {
  /// Native root requested by the caller.
  root:    PathBuf,
  /// Native entries, metadata, and exclusions in walker order.
  entries: Vec<DiscoveredEntry>,
}

impl LanguageDiscovery {
  /// Test the extension registry without consuming or decoding native paths.
  fn has_extension(&self, extensions: &[&str]) -> bool {
    self.entries.iter().any(|observed| {
      observed.excluded.is_none()
        && observed.metadata.is_file()
        && observed.entry.path().extension().is_some_and(|extension| {
          extensions
            .iter()
            .any(|configured| extension.as_encoded_bytes().eq_ignore_ascii_case(configured.as_bytes()))
        })
    })
  }
}

/// Automatic selection failed with its native cause and completed discovery retained.
#[derive(Debug, thiserror::Error)]
enum LanguageDetectionError {
  /// The walker could not produce its next entry.
  #[error("language discovery failed: {source}")]
  Walk {
    /// Every native observation completed before traversal failed.
    discovery: Box<LanguageDiscovery>,
    /// Original walker failure, including its path, depth, and native cause.
    source:    walkdir::Error,
  },
  /// Entry metadata could not be resolved.
  #[error("cannot observe language-discovery entry {}: {source}", entry.path().display())]
  Metadata {
    /// Every native observation completed before this entry.
    discovery: Box<LanguageDiscovery>,
    /// The native entry whose metadata operation failed.
    entry:     DirEntry,
    /// Original filesystem failure.
    source:    io::Error,
  },
  /// A complete discovery found no supported source language.
  #[error("No recognized source files found. Use --language to specify the language.")]
  NoRecognizedFiles {
    /// Complete discovery, including unrecognized entries and excluded directories.
    discovery: LanguageDiscovery,
  },
  /// A complete discovery found more than one AST language.
  #[error("Multiple languages detected: {}. Use --language to specify which to analyze.", languages.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))]
  Ambiguous {
    /// Complete discovery used to identify the competing languages.
    discovery: LanguageDiscovery,
    /// All matching languages in registry order.
    languages: Vec<Language>,
  },
}

/// The selected concrete analyzer, including the mode that uses only generic text extraction.
#[derive(Debug)]
enum SelectedAnalyzer {
  /// Rust analysis with native `syn` failures.
  Rust(RustAnalyzer),
  /// Python analysis with native tree-sitter failures.
  Python(Box<PythonAnalyzer>),
  /// Generic text extraction without an AST parser.
  Generic,
}

/// The selected language's original parse failure.
#[derive(Debug, thiserror::Error)]
enum LanguageParseError {
  /// Rust source parsing failed.
  #[error(transparent)]
  Rust(RustParseError),
  /// Python source parsing failed.
  #[error(transparent)]
  Python(<PythonAnalyzer as LanguageAnalyzer>::Error),
}

/// Native failures encountered while selecting an analyzer and preparing its analysis.
#[derive(Debug, thiserror::Error)]
enum AnalysisPreparationError {
  /// Automatic language selection failed before analyzer construction.
  #[error(transparent)]
  Detection(#[from] LanguageDetectionError),
  /// The Python extraction query could not be compiled.
  #[error(transparent)]
  PythonInitialization(#[from] PythonAnalyzerError),
  /// Shared analysis failed with its native language-specific evidence.
  #[error(transparent)]
  Analysis(#[from] CliError<LanguageParseError>),
}

/// Startup and shared command failures retain the frontend's language-selection evidence.
#[derive(Debug, thiserror::Error)]
enum CommandError {
  /// Resolving the command's root failed before language selection.
  #[error(transparent)]
  Root(#[from] CliError),
  /// The shared command failed during preparation, warning output, or dispatch.
  #[error("{source}")]
  Command {
    /// Explicit or discovered language selection, when reached before failure.
    selection: Option<LanguageSelection>,
    /// Complete request, prepared analysis when available, and native failure.
    source:    Box<cli::CommandFailure<ReportRenderer, LanguageParseError, AnalysisPreparationError>>,
  },
}

/// Complete frontend result, retaining language selection and the shared command outcome.
type CommandResult = Result<(Option<LanguageSelection>, cli::CommandOutput<ReportRenderer, LanguageParseError>), CommandError>;

impl CommandError {
  /// Preserve check failures as status `1` and operational failures as status `2`.
  #[allow(
    clippy::single_call_fn,
    reason = "The frontend owns the exit-status mapping from its complete startup or language-aware command failure."
  )]
  const fn exit_code(&self) -> u8 {
    match *self {
      Self::Root(_) => 2,
      Self::Command {
        ref source, ..
      } => source.exit_code(),
    }
  }
}

impl LanguageAnalyzer for SelectedAnalyzer {
  type Error = LanguageParseError;

  fn file_extensions(&self) -> &[&str] {
    match *self {
      Self::Rust(ref analyzer) => analyzer.file_extensions(),
      Self::Python(ref analyzer) => analyzer.file_extensions(),
      Self::Generic => &[],
    }
  }

  fn parse_file(&self, path: &Path, source: &str, config: AnalysisConfig) -> Result<Vec<CodeUnit>, Self::Error> {
    match *self {
      Self::Rust(ref analyzer) => analyzer.parse_file(path, source, config).map_err(LanguageParseError::Rust),
      Self::Python(ref analyzer) => analyzer.parse_file(path, source, config).map_err(LanguageParseError::Python),
      Self::Generic => Ok(Vec::new()),
    }
  }

  fn parse_sub_units(&self, path: &Path, source: &str, config: AnalysisConfig, min_nodes: usize) -> Result<Vec<CodeUnit>, Self::Error> {
    match *self {
      Self::Rust(ref analyzer) => analyzer
        .parse_sub_units(path, source, config, min_nodes)
        .map_err(LanguageParseError::Rust),
      Self::Python(ref analyzer) => analyzer
        .parse_sub_units(path, source, config, min_nodes)
        .map_err(LanguageParseError::Python),
      Self::Generic => Ok(Vec::new()),
    }
  }
}

/// Create a language analyzer for the given language.
#[allow(
  clippy::single_call_fn,
  reason = "Analyzer construction is the named boundary that maps a selected language to its concrete parser and native initialization \
            failure."
)]
fn resolve_analyzer(language: Language) -> Result<SelectedAnalyzer, PythonAnalyzerError> {
  match language {
    Language::Rust => Ok(SelectedAnalyzer::Rust(RustAnalyzer::new())),
    Language::Python => PythonAnalyzer::new().map(Box::new).map(SelectedAnalyzer::Python),
    Language::Generic => Ok(SelectedAnalyzer::Generic),
  }
}

/// Auto-detect language by scanning for files matching known extensions.
///
/// Performs a single directory walk (instead of one per language) and collects
/// file extensions, then matches against `Language::AST`. Returns an error if
/// multiple AST languages are detected — the user must specify `--language` to
/// disambiguate. Directories with only generic extensions fall back to
/// `Language::Generic` (token/line detection without an AST analyzer).
#[allow(
  clippy::single_call_fn,
  reason = "Automatic selection owns the complete filesystem discovery and resolves its observed language population before analysis."
)]
fn auto_detect_language(root: &Path) -> Result<LanguageSelection, LanguageDetectionError> {
  let mut discovery = LanguageDiscovery {
    root:    root.to_path_buf(),
    entries: Vec::new(),
  };
  let mut walker = WalkDir::new(root).into_iter();
  while let Some(next) = walker.next() {
    let entry = match next {
      Ok(observed) => observed,
      Err(source) => {
        return Err(LanguageDetectionError::Walk {
          discovery: Box::new(discovery),
          source,
        });
      }
    };
    let metadata = match fs::metadata(entry.path()) {
      Ok(observed) => observed,
      Err(source) => {
        return Err(LanguageDetectionError::Metadata {
          discovery: Box::new(discovery),
          entry,
          source,
        });
      }
    };
    let excluded = if metadata.is_dir() {
      match entry.path().file_name().and_then(|name| name.to_str()) {
        Some("target") => Some(DirectoryExclusion::BuildOutput),
        Some(name) if name.starts_with('.') && entry.path() != root => Some(DirectoryExclusion::Hidden),
        Some(_) | None => None,
      }
    } else {
      None
    };
    if excluded.is_some() && entry.file_type().is_dir() {
      walker.skip_current_dir();
    }
    discovery.entries.push(DiscoveredEntry {
      entry,
      metadata,
      excluded,
    });
  }

  let detected: Vec<Language> = Language::AST
    .iter()
    .copied()
    .filter(|language| discovery.has_extension(language.extensions()))
    .collect();

  match *detected.as_slice() {
    [] => {
      if discovery.has_extension(GENERIC_EXTENSIONS) {
        Ok(LanguageSelection::Detected {
          language: Language::Generic,
          discovery,
        })
      } else {
        Err(LanguageDetectionError::NoRecognizedFiles {
          discovery,
        })
      }
    }
    [language] => Ok(LanguageSelection::Detected {
      language,
      discovery,
    }),
    _ => Err(LanguageDetectionError::Ambiguous {
      discovery,
      languages: detected,
    }),
  }
}

/// Return the frontend's optional language selection together with the complete shared command
/// output.
#[allow(
  clippy::single_call_fn,
  reason = "Frontend execution retains language-selection and shared-command outcomes before the terminal adapter renders failures."
)]
fn run(cli_args: &Cli) -> CommandResult {
  let root = cli_args.common.root()?;
  let command = cli_args.requested_command();
  let stdout = io::stdout();
  let mut writer = stdout.lock();
  let mut selected = None;

  let outcome = cli::run_command_with_analysis(&root, &command, &mut writer, || {
    let selection = cli_args.language.map_or_else(
      || auto_detect_language(&root),
      |language| Ok(LanguageSelection::Requested(language)),
    )?;
    let preparation = selection.prepare_analysis(&root, cli_args);
    selected = Some(selection);
    preparation
  });
  match outcome {
    Ok(completed) => Ok((selected, completed)),
    Err(source) => Err(CommandError::Command {
      selection: selected,
      source:    Box::new(source),
    }),
  }
}

/// Return normally after reporting, retaining both failures if reporting fails.
fn main() -> Result<ExitCode, cli::ErrorReportFailure<CommandError>> {
  cli::finish_command_line(Cli::try_parse(), run, CommandError::exit_code, &mut io::stderr().lock())
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::io;
  #[cfg(unix)]
  use std::os::unix::fs::symlink;
  use std::path::Path;

  use dupes_cli_test_support::CliTestFailure;
  use dupes_cli_test_support::write_fixture;
  use dupes_core::cli;
  use dupes_core::ignore;
  use dupes_core::ignore::IgnoreFile;
  use dupes_core::ignore::IgnoreFileObservation;
  use dupes_core::output::ReportRenderer;
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;

  use super::AnalysisPreparationError;
  use super::Cli;
  use super::CliError;
  use super::Command;
  use super::CommandError;
  use super::CommandResult;
  use super::CommonCliArgs;
  use super::DirectoryExclusion;
  use super::Language;
  use super::LanguageDetectionError;
  use super::LanguageSelection;
  use super::auto_detect_language;
  use super::run;

  /// Fixture failures and complete unexpected language or command outcomes.
  #[derive(Debug, thiserror::Error)]
  enum LanguageTestFailure {
    /// Temporary workspace allocation failed with its native cause.
    #[error(transparent)]
    Workspace(#[from] io::Error),
    /// Preparing a source fixture failed with its native path and cause.
    #[error(transparent)]
    Fixture(#[from] CliTestFailure),
    /// Discovery failed to preserve the promised selection or native observations.
    #[error("language discovery expectation failed: {source}; outcome: {outcome:?}")]
    Discovery {
      /// Complete result observed at the selection boundary.
      outcome: Box<Result<LanguageSelection, LanguageDetectionError>>,
      /// Failed behavioral expectation.
      source:  TestFailure,
    },
    /// A command lost its language selection or complete shared outcome.
    #[error("command selection expectation failed: {source}; arguments: {arguments:?}; outcome: {outcome:?}")]
    Command {
      /// Complete frontend arguments supplied to command execution.
      arguments: Box<Cli>,
      /// Complete result returned by the frontend.
      outcome:   Box<CommandResult>,
      /// Failed behavioral expectation.
      source:    TestFailure,
    },
  }

  /// Preserve the whole discovery result when a native-evidence expectation fails.
  fn check_discovery(
    outcome: Result<LanguageSelection, LanguageDetectionError>,
    check: impl FnOnce(&Result<LanguageSelection, LanguageDetectionError>) -> Result<(), TestFailure>,
  ) -> Result<(), LanguageTestFailure> {
    check(&outcome).map_err(|source| LanguageTestFailure::Discovery {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Prepare the single Rust source shared by native-discovery and command-selection scenarios.
  fn rust_source_workspace() -> Result<TempDir, LanguageTestFailure> {
    let workspace = TempDir::new()?;
    write_fixture(&workspace.path().join("source.rs"), "fn source() {}\n")?;
    Ok(workspace)
  }

  /// Construct a frontend request rooted in its isolated fixture workspace.
  fn command_arguments(root: &Path, command: Command, language: Option<Language>) -> Cli {
    Cli {
      command: Some(command),
      language,
      common: CommonCliArgs {
        path: Some(root.to_path_buf()),
        ..CommonCliArgs::default()
      },
    }
  }

  /// Check the frontend boundary while retaining the complete request and native outcome.
  fn check_command(arguments: Cli, check: impl FnOnce(&CommandResult) -> Result<(), TestFailure>) -> Result<(), LanguageTestFailure> {
    let outcome = run(&arguments);
    check(&outcome).map_err(|source| LanguageTestFailure::Command {
      arguments: Box::new(arguments),
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Supported extensions select their language while preserving native root and file observations.
  #[test]
  fn supported_languages_retain_native_discovery() -> Result<(), LanguageTestFailure> {
    for (name, contents, expected) in [
      ("source.RS", "fn source() {}\n", Language::Rust),
      ("source.pyi", "def source(): ...\n", Language::Python),
      ("source.txt", "generic source\n", Language::Generic),
    ] {
      let workspace = TempDir::new()?;
      let path = workspace.path().join(name);
      write_fixture(&path, contents)?;
      check_discovery(auto_detect_language(workspace.path()), |observed| {
        ensure(
          matches!(*observed, Ok(LanguageSelection::Detected { language, ref discovery })
            if language == expected && discovery.root == workspace.path() && discovery.entries.len() == 2
              && discovery.entries.iter().any(|entry| entry.entry.path() == workspace.path() && entry.metadata.is_dir())
              && discovery.entries.iter().any(|entry| entry.entry.path() == path && entry.metadata.is_file() && entry.excluded.is_none())),
          "selection preserves the requested root and complete native file observation, including case-insensitive extensions",
        )
      })?;
    }
    Ok(())
  }

  /// Mixed AST languages retain their typed identities and completed discovery.
  #[test]
  fn ambiguous_languages_retain_native_discovery() -> Result<(), LanguageTestFailure> {
    let workspace = rust_source_workspace()?;
    write_fixture(&workspace.path().join("source.py"), "def source(): pass\n")?;
    check_discovery(auto_detect_language(workspace.path()), |observed| {
      ensure(
        matches!(*observed, Err(LanguageDetectionError::Ambiguous { ref discovery, ref languages })
          if discovery.root == workspace.path() && discovery.entries.len() == 3
            && *languages == [Language::Rust, Language::Python]
            && discovery.has_extension(&["rs"]) && discovery.has_extension(&["py"])),
        "ambiguity retains both language values and the native observations that support them",
      )
    })
  }

  /// Unsupported files remain observable when a complete discovery selects no language.
  #[test]
  fn unrecognized_files_retain_native_discovery() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("records.csv");
    write_fixture(&path, "first,second\n")?;
    check_discovery(auto_detect_language(workspace.path()), |observed| {
      ensure(
        matches!(*observed, Err(LanguageDetectionError::NoRecognizedFiles { ref discovery })
          if discovery.root == workspace.path() && discovery.entries.len() == 2
            && discovery.entries.iter().any(|entry| entry.entry.path() == path && entry.metadata.is_file())),
        "unrecognized source selection retains the successfully observed unsupported file",
      )
    })
  }

  /// Build output and hidden directories are observed but pruned before their contents are visited.
  #[test]
  fn directory_exclusions_retain_native_observations() -> Result<(), LanguageTestFailure> {
    let workspace = rust_source_workspace()?;
    for name in ["target", ".hidden"] {
      let path = workspace.path().join(name);
      fs::create_dir_all(&path).map_err(|source| CliTestFailure::Fixture {
        path: path.clone(),
        source,
      })?;
      write_fixture(&path.join("hidden.py"), "def hidden(): pass\n")?;
    }
    check_discovery(auto_detect_language(workspace.path()), |observed| {
      ensure(
        matches!(*observed, Ok(LanguageSelection::Detected { language: Language::Rust, ref discovery })
          if discovery.entries.len() == 4
            && [("target", DirectoryExclusion::BuildOutput), (".hidden", DirectoryExclusion::Hidden)]
              .iter().all(|&(name, reason)| discovery.entries.iter().any(|entry|
                entry.entry.path() == workspace.path().join(name) && entry.metadata.is_dir() && entry.excluded == Some(reason)))),
        "excluded directories retain native metadata and their reasons while their Python files cannot affect Rust selection",
      )
    })
  }

  /// An inaccessible root returns the native walker failure instead of an empty-language result.
  #[test]
  fn missing_root_retains_native_walk_failure() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    let root = workspace.path().join("missing");
    check_discovery(auto_detect_language(&root), |observed| {
      ensure(
        matches!(*observed, Err(LanguageDetectionError::Walk { ref discovery, ref source })
          if discovery.root == root && discovery.entries.is_empty() && source.path() == Some(root.as_path())
            && source.io_error().is_some_and(|native| native.kind() == io::ErrorKind::NotFound)),
        "failed traversal preserves its native path and cause without inventing a completed scan",
      )
    })
  }

  /// Failed file-link metadata retains the link and the root observed before it.
  #[cfg(unix)]
  #[test]
  fn dangling_link_retains_native_metadata_failure() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    let link = workspace.path().join("source.rs");
    symlink("absent.rs", &link).map_err(|source| CliTestFailure::Fixture {
      path: link.clone(),
      source,
    })?;
    check_discovery(auto_detect_language(workspace.path()), |observed| {
      ensure(
        matches!(*observed, Err(LanguageDetectionError::Metadata { ref discovery, ref entry, ref source })
          if discovery.root == workspace.path() && discovery.entries.len() == 1
            && discovery.entries.iter().all(|completed| completed.entry.path() == workspace.path() && completed.metadata.is_dir())
            && entry.path() == link && entry.path_is_symlink() && source.kind() == io::ErrorKind::NotFound),
        "failed target metadata preserves the native link entry, I/O cause, and completed root observation",
      )
    })
  }

  /// File links remain eligible while directory-link targets remain outside traversal.
  #[cfg(unix)]
  #[test]
  fn link_discovery_preserves_identity_and_traversal_boundaries() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    let root = workspace.path().join("sources");
    let directory_target = workspace.path().join("external");
    for path in [&root, &directory_target] {
      fs::create_dir_all(path).map_err(|source| CliTestFailure::Fixture {
        path: path.clone(),
        source,
      })?;
    }
    let file_target = workspace.path().join("external.rs");
    write_fixture(&file_target, "fn external() {}\n")?;
    write_fixture(&directory_target.join("external.py"), "def external(): pass\n")?;
    let file_link = root.join("linked.RS");
    let directory_link = root.join("nested");
    for (target, link) in [(&file_target, &file_link), (&directory_target, &directory_link)] {
      symlink(target, link).map_err(|source| CliTestFailure::Fixture {
        path: link.clone(),
        source,
      })?;
    }
    check_discovery(auto_detect_language(&root), |observed| {
      ensure(
        matches!(*observed, Ok(LanguageSelection::Detected { language: Language::Rust, ref discovery })
          if discovery.entries.len() == 3
            && discovery.entries.iter().any(|entry| entry.entry.path() == file_link && entry.entry.path_is_symlink() && entry.metadata.is_file())
            && discovery.entries.iter().any(|entry| entry.entry.path() == directory_link && entry.entry.path_is_symlink() && entry.metadata.is_dir())),
        "file-link metadata enables language selection without traversing directory links or losing either link identity",
      )
    })
  }

  /// Successful analysis retains explicit or discovered selection with the shared command outcome.
  #[test]
  fn successful_command_retains_language_and_shared_analysis() -> Result<(), LanguageTestFailure> {
    let workspace = rust_source_workspace()?;
    let path = workspace.path().join("source.rs");
    for language in [None, Some(Language::Rust)] {
      let mut arguments = command_arguments(workspace.path(), Command::Stats, language);
      arguments.common.format = cli::OutputFormat::Json;
      check_command(arguments, |outcome| {
        let preserved_selection = matches!(*outcome,
          Ok((Some(LanguageSelection::Requested(Language::Rust)), _)) if language == Some(Language::Rust))
          || matches!(*outcome, Ok((
            Some(LanguageSelection::Detected {
              language: Language::Rust,
              ref discovery,
            }),
            _,
          )) if language.is_none()
              && discovery.root == workspace.path()
              && discovery.entries.len() == 2
              && discovery
                .entries
                .iter()
                .any(|observed| observed.entry.path() == path && observed.metadata.is_file()));
        ensure(
          preserved_selection
            && matches!(*outcome, Ok((Some(_), cli::CommandOutput::Analyzed {
          command: Command::Stats, ref analysis, outcome: cli::AnalysisCommandOutcome::Stats,
        })) if analysis.config.root == workspace.path()
          && analysis.scans.len() == 2
          && analysis.scans.iter().all(|scan| scan.files().collect::<Vec<_>>() == [path.as_path()])
          && matches!(analysis.reporter, ReportRenderer::Json(ref reporter)
            if reporter.base_path.as_deref() == Some(workspace.path()))),
          "successful frontend dispatch retains the selection source, native preparation, command outcome, and renderer",
        )
      })?;
    }
    Ok(())
  }

  /// Listing can complete with no selected analyzer, preserving the native registry observation.
  #[test]
  fn ignored_command_retains_registry_without_selecting_language() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    check_command(command_arguments(workspace.path(), Command::Ignored, None), |outcome| {
      ensure(
        matches!(*outcome, Ok((None, cli::CommandOutput::Ignored(ref loaded)))
        if loaded.path == ignore::ignore_file_path(workspace.path())
          && loaded.registry == IgnoreFile::default()
          && matches!(loaded.observation, IgnoreFileObservation::Absent { ref source }
            if source.kind() == io::ErrorKind::NotFound)),
        "a registry-only command returns native absence evidence without requiring a discoverable source language",
      )
    })
  }

  /// Failed discovery preserves its command request without claiming a language was selected.
  #[test]
  fn command_failure_before_selection_retains_request_and_discovery() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    check_command(
      command_arguments(
        workspace.path(),
        Command::Cleanup {
          dry_run: true
        },
        None,
      ),
      |outcome| {
        ensure(
          matches!(*outcome, Err(CommandError::Command { selection: None, source: ref failure })
        if matches!(**failure, cli::CommandFailure::Preparation { ref root, command: Command::Cleanup { dry_run: true }, ref source }
          if root == workspace.path()
            && matches!(**source, AnalysisPreparationError::Detection(LanguageDetectionError::NoRecognizedFiles { ref discovery })
              if discovery.root == workspace.path() && discovery.entries.len() == 1
                && discovery.entries.iter().all(|observed| observed.entry.path() == workspace.path() && observed.metadata.is_dir()))))
            && outcome.as_ref().is_err_and(|failure| failure.exit_code() == 2),
          "failed language discovery preserves the requested dry run and native observations without claiming a completed language \
           selection",
        )
      },
    )
  }

  /// A selected language and its observations survive a later configuration failure.
  #[test]
  fn command_failure_retains_detected_language() -> Result<(), LanguageTestFailure> {
    let workspace = rust_source_workspace()?;
    write_fixture(&workspace.path().join("dupes.toml"), "[invalid")?;
    check_command(command_arguments(workspace.path(), Command::Stats, None), |outcome| {
      ensure(
        matches!(*outcome, Err(CommandError::Command {
        selection: Some(LanguageSelection::Detected { language: Language::Rust, ref discovery }), source: ref failure,
      }) if discovery.root == workspace.path() && discovery.entries.len() == 3
        && matches!(**failure, cli::CommandFailure::Preparation { ref root, command: Command::Stats, ref source }
          if root == workspace.path() && matches!(**source, AnalysisPreparationError::Analysis(CliError::Config(_))))),
        "configuration failure retains the prior Rust selection and every native discovery observation",
      )
    })
  }

  /// Explicit selection remains distinct from discovery when analysis finds no sources.
  #[test]
  fn command_failure_retains_explicit_language() -> Result<(), LanguageTestFailure> {
    let workspace = TempDir::new()?;
    check_command(
      command_arguments(workspace.path(), Command::Stats, Some(Language::Rust)),
      |outcome| {
        ensure(
          matches!(*outcome, Err(CommandError::Command {
        selection: Some(LanguageSelection::Requested(Language::Rust)), source: ref failure,
      }) if matches!(**failure, cli::CommandFailure::Preparation { ref root, command: Command::Stats, ref source }
        if root == workspace.path() && matches!(**source, AnalysisPreparationError::Analysis(CliError::NoSourceFiles { .. })))),
          "an explicit language remains caller-selected after a later missing-source failure",
        )
      },
    )
  }
}
