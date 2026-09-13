//! Run configuration shared by both CLIs: defaults, `dupes.toml` and
//! `[package.metadata.dupes]` loading, and dimension/suppression toggles.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::string::FromUtf8Error;
use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;
use toml::de::Error as TomlDecodeError;

use crate::code_unit::DetectionDimension;
use crate::suppression::SuppressionPolicy;
use crate::suppression::SuppressionWarning;

/// The subset of configuration relevant to language-specific parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisConfig {
  /// Minimum number of AST nodes for a code unit to be analyzed.
  pub min_nodes: usize,
  /// Minimum number of source lines for a code unit to be analyzed.
  pub min_lines: usize,
}

/// Configuration for a duplicate-detection run, shared by both CLIs.
#[derive(Debug, Clone)]
pub struct Config {
  /// Minimum number of AST nodes for a code unit to be analyzed.
  pub min_nodes: usize,
  /// Similarity threshold for near-duplicates (0.0 to 1.0).
  pub similarity_threshold: f64,
  /// Path patterns to exclude from scanning.
  pub exclude: Vec<String>,
  /// Exit code threshold: fail if exact duplicate count exceeds this.
  pub max_exact_duplicates: Option<usize>,
  /// Exit code threshold: fail if near duplicate count exceeds this.
  pub max_near_duplicates: Option<usize>,
  /// Exit code threshold: fail if exact duplicate percentage exceeds this.
  pub max_exact_percent: Option<f64>,
  /// Exit code threshold: fail if near duplicate percentage exceeds this.
  pub max_near_percent: Option<f64>,
  /// Minimum number of source lines for a code unit to be analyzed.
  pub min_lines: usize,
  /// Exclude test code (#[test] functions and #[cfg(test)] modules).
  pub exclude_tests: bool,
  /// Enable sub-function duplicate detection.
  pub sub_function: bool,
  /// Minimum number of AST nodes for a sub-function unit to be analyzed.
  pub min_sub_nodes: usize,
  /// Enabled duplicate detection dimensions.
  pub enabled_dimensions: BTreeSet<DetectionDimension>,
  /// Minimum number of tokens in a token window.
  pub token_min_tokens: usize,
  /// Minimum number of source lines a token window must span.
  pub token_min_lines: usize,
  /// Similarity threshold for normalized token near-duplicates.
  pub token_similarity_threshold: f64,
  /// Minimum number of lines in a line window.
  pub line_min_lines: usize,
  /// Active suppression/admission rule set.
  pub suppression: SuppressionPolicy,
  /// Complete nonfatal rule-selection warnings produced while loading configuration.
  pub load_warnings: Vec<SuppressionWarning>,
  /// Complete file observations in the order their settings were applied.
  pub sources: Vec<ConfigSource>,
  /// Root path to analyze.
  pub root: PathBuf,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      min_nodes: 10,
      similarity_threshold: 0.8,
      exclude: Vec::new(),
      max_exact_duplicates: None,
      max_near_duplicates: None,
      max_exact_percent: None,
      max_near_percent: None,
      min_lines: 0,
      exclude_tests: false,
      sub_function: false,
      min_sub_nodes: 5,
      enabled_dimensions: DetectionDimension::all().iter().copied().collect(),
      token_min_tokens: 50,
      token_min_lines: 2,
      token_similarity_threshold: 0.9,
      line_min_lines: 5,
      suppression: SuppressionPolicy::default(),
      load_warnings: Vec::new(),
      sources: Vec::new(),
      root: PathBuf::from("."),
    }
  }
}

/// Config as stored in `dupes.toml` or `Cargo.toml` metadata.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct FileConfig {
  /// Optional minimum AST size.
  pub min_nodes:            Option<usize>,
  /// Optional AST similarity threshold.
  pub similarity_threshold: Option<f64>,
  /// Optional replacement source-path exclusions.
  pub exclude:              Option<Vec<String>>,
  /// Optional exact-group count limit.
  pub max_exact_duplicates: Option<usize>,
  /// Optional near-group count limit.
  pub max_near_duplicates:  Option<usize>,
  /// Optional exact-duplication percentage limit.
  pub max_exact_percent:    Option<f64>,
  /// Optional near-duplication percentage limit.
  pub max_near_percent:     Option<f64>,
  /// Optional minimum source span for AST units.
  pub min_lines:            Option<usize>,
  /// Optional exclusion of test functions and modules.
  pub exclude_tests:        Option<bool>,
  /// Optional activation of sub-function extraction.
  pub sub_function:         Option<bool>,
  /// Optional minimum AST size for extracted sub-units.
  pub min_sub_nodes:        Option<usize>,
  /// Optional per-dimension enablement overrides.
  pub dimensions:           Option<DimensionConfig>,
  /// Optional token-window detection settings.
  pub token:                Option<TokenConfig>,
  /// Optional line-window detection settings.
  pub line:                 Option<LineConfig>,
  /// Optional reportability-rule overrides.
  pub suppress:             Option<SuppressConfig>,
}

/// Optional suppression-rule toggles from file config.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct SuppressConfig {
  /// Rule identifiers to disable before processing explicit enables.
  pub disable: Option<Vec<String>>,
  /// Rule identifiers to enable after processing disables.
  pub enable:  Option<Vec<String>>,
}

/// Optional dimension switches from file config.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct DimensionConfig {
  /// Enablement override for complete AST units.
  pub ast:              Option<bool>,
  /// Enablement override for extracted AST units.
  pub sub_ast:          Option<bool>,
  /// Enablement override for normalized tokens.
  pub token_normalized: Option<bool>,
  /// Enablement override for source-preserving tokens.
  pub token_raw:        Option<bool>,
  /// Enablement override for normalized source lines.
  pub line:             Option<bool>,
}

/// Optional token settings from file config.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct TokenConfig {
  /// Optional minimum token count per window.
  pub min_tokens:           Option<usize>,
  /// Optional minimum source span per token window.
  pub min_lines:            Option<usize>,
  /// Optional normalized-token similarity threshold.
  pub similarity_threshold: Option<f64>,
}

/// Optional line settings from file config.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct LineConfig {
  /// Optional minimum line count per window.
  pub min_lines: Option<usize>,
}

/// `Cargo.toml` metadata section.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CargoMetadata {
  /// Package declaration, absent for virtual workspaces.
  #[serde(default)]
  pub package: Option<CargoPackage>,
}

/// Package-level container for Cargo metadata.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CargoPackage {
  /// Tool-owned metadata associated with the package.
  #[serde(default)]
  pub metadata: Option<CargoPackageMetadata>,
}

/// Package metadata containing an optional duplicate-detection policy.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CargoPackageMetadata {
  /// Duplicate-detection settings applied before the dedicated config file.
  #[serde(default)]
  pub dupes: Option<FileConfig>,
}

/// The typed document decoded from a configuration source.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigDocument {
  /// Cargo package metadata, including an absent package or tool section.
  Cargo(Box<CargoMetadata>),
  /// Overrides from the dedicated `dupes.toml` document.
  Dedicated(Box<FileConfig>),
}

/// A configuration file observation retained with the resolved settings.
#[derive(Debug, Clone)]
pub enum ConfigSource {
  /// A complete document was read and decoded.
  Read {
    /// Exact path passed to the reader.
    path:     PathBuf,
    /// Complete original document before deserialization.
    contents: String,
    /// The file-format model used to resolve this layer's settings.
    document: ConfigDocument,
  },
  /// An optional file was absent and supplied no overrides.
  Absent {
    /// Exact optional configuration path.
    path:   PathBuf,
    /// Shared native absence observation, preserved when configurations clone.
    source: Arc<io::Error>,
  },
}

/// A configuration file could not be read or decoded.
#[derive(Debug, Error)]
pub enum ConfigFileError {
  /// Reading failed for a reason other than optional-file absence.
  #[error("failed to read configuration {}: {source}", path.display())]
  Read {
    /// Exact file path passed to the reader.
    path:   PathBuf,
    /// Native filesystem failure.
    source: io::Error,
  },
  /// A complete byte buffer was read but was not valid UTF-8.
  #[error("configuration {} is not UTF-8: {source}", path.display())]
  Utf8 {
    /// Configuration path that supplied the bytes.
    path:   PathBuf,
    /// Native decoding failure with its complete input bytes.
    source: FromUtf8Error,
  },
  /// TOML deserialization rejected the complete document.
  #[error("failed to decode configuration {}: {source}", path.display())]
  Decode {
    /// Configuration path that supplied the document.
    path:     PathBuf,
    /// Complete text supplied to the TOML decoder.
    contents: String,
    /// Native typed TOML failure.
    source:   Box<TomlDecodeError>,
  },
}

/// Configuration loading stopped after retaining every completed lower layer.
#[derive(Debug, Error)]
#[error("{source}")]
pub struct ConfigLoadError {
  /// Settings and source observations resolved before the failing file.
  pub config: Box<Config>,
  /// The file operation that could not complete.
  pub source: ConfigFileError,
}

/// Overwrite `slot` when an override value is present.
pub(crate) fn override_with<Value>(slot: &mut Value, supplied: Option<Value>) {
  if let Some(replacement) = supplied {
    *slot = replacement;
  }
}

/// Overwrite an optional `slot` only when an override value is present.
pub(crate) fn override_option<Value>(slot: &mut Option<Value>, supplied: Option<Value>) {
  override_with(slot, supplied.map(Some));
}

impl Config {
  /// Extract the parsing-relevant subset of the configuration.
  #[must_use]
  pub const fn analysis_config(&self) -> AnalysisConfig {
    AnalysisConfig {
      min_nodes: self.min_nodes,
      min_lines: self.min_lines,
    }
  }

  /// Load config with the following precedence:
  /// 1. CLI overrides (applied by the caller after this method)
  /// 2. `dupes.toml` in the project root
  /// 3. `[package.metadata.dupes]` in `Cargo.toml`
  /// 4. Defaults
  ///
  /// # Errors
  ///
  /// Returns the native read or decoding failure together with every
  /// configuration layer resolved before it. Only absent files use defaults.
  #[allow(
    clippy::single_call_fn,
    reason = "Configuration loading owns the shared file-precedence contract for both CLI adapters."
  )]
  pub fn load(root: &Path) -> Result<Self, ConfigLoadError> {
    let mut config = Self {
      root: root.to_path_buf(),
      ..Default::default()
    };

    let cargo = read_toml_file(root.join("Cargo.toml"), |contents| {
      toml::from_str(contents).map(ConfigDocument::Cargo)
    })
    .map_err(|source| ConfigLoadError {
      config: Box::new(config.clone()),
      source,
    })?;
    config.apply_source(cargo);
    let dedicated = read_toml_file(root.join("dupes.toml"), |contents| {
      toml::from_str(contents).map(ConfigDocument::Dedicated)
    })
    .map_err(|source| ConfigLoadError {
      config: Box::new(config.clone()),
      source,
    })?;
    config.apply_source(dedicated);
    Ok(config)
  }

  /// Apply a decoded file's optional settings and retain its complete observation.
  fn apply_source(&mut self, source: ConfigSource) {
    let settings = match source {
      ConfigSource::Read {
        document: ConfigDocument::Cargo(ref cargo),
        ..
      } => cargo
        .package
        .as_ref()
        .and_then(|package| package.metadata.as_ref())
        .and_then(|metadata| metadata.dupes.as_ref()),
      ConfigSource::Read {
        document: ConfigDocument::Dedicated(ref dedicated),
        ..
      } => Some(dedicated.as_ref()),
      ConfigSource::Absent {
        ..
      } => None,
    };
    if let Some(overrides) = settings {
      self.apply_file_config(overrides);
    }
    self.sources.push(source);
  }

  /// Apply only explicitly declared settings, preserving earlier layer values otherwise.
  #[allow(
    clippy::single_call_fn,
    reason = "Applying optional overrides is the precedence boundary between a retained source document and resolved run configuration."
  )]
  fn apply_file_config(&mut self, file_config: &FileConfig) {
    override_with(&mut self.min_nodes, file_config.min_nodes);
    override_with(&mut self.similarity_threshold, file_config.similarity_threshold);
    if let Some(ref exclusions) = file_config.exclude {
      self.exclude.clone_from(exclusions);
    }
    override_option(&mut self.max_exact_duplicates, file_config.max_exact_duplicates);
    override_option(&mut self.max_near_duplicates, file_config.max_near_duplicates);
    override_option(&mut self.max_exact_percent, file_config.max_exact_percent);
    override_option(&mut self.max_near_percent, file_config.max_near_percent);
    override_with(&mut self.min_lines, file_config.min_lines);
    override_with(&mut self.exclude_tests, file_config.exclude_tests);
    override_with(&mut self.sub_function, file_config.sub_function);
    override_with(&mut self.min_sub_nodes, file_config.min_sub_nodes);
    if let Some(dimensions) = file_config.dimensions {
      let toggles = [
        (DetectionDimension::Ast, dimensions.ast),
        (DetectionDimension::SubAst, dimensions.sub_ast),
        (DetectionDimension::TokenNormalized, dimensions.token_normalized),
        (DetectionDimension::TokenRaw, dimensions.token_raw),
        (DetectionDimension::Line, dimensions.line),
      ];
      for (dimension, enabled) in toggles
        .into_iter()
        .filter_map(|(dimension, toggle)| toggle.map(|enabled| (dimension, enabled)))
      {
        self.set_dimension(dimension, enabled);
      }
    }
    if let Some(token) = file_config.token {
      override_with(&mut self.token_min_tokens, token.min_tokens);
      override_with(&mut self.token_min_lines, token.min_lines);
      override_with(&mut self.token_similarity_threshold, token.similarity_threshold);
    }
    if let Some(line) = file_config.line
      && let Some(min_lines) = line.min_lines
    {
      self.line_min_lines = min_lines;
    }
    if let Some(ref suppress) = file_config.suppress {
      let warnings = self.suppression.apply_toggles(
        suppress.disable.as_deref().unwrap_or_default(),
        suppress.enable.as_deref().unwrap_or_default(),
      );
      self.load_warnings.extend(warnings);
    }
  }

  /// Disable a duplicate-detection dimension.
  pub fn disable_dimension(&mut self, dimension: DetectionDimension) {
    self.enabled_dimensions.retain(|candidate| *candidate != dimension);
  }

  /// Enable only the provided duplicate-detection dimensions.
  pub fn enable_only_dimensions(&mut self, dimensions: impl IntoIterator<Item = DetectionDimension>) {
    self.enabled_dimensions = dimensions.into_iter().collect();
  }

  /// Return true when a duplicate-detection dimension is enabled.
  #[must_use]
  pub fn dimension_enabled(&self, dimension: DetectionDimension) -> bool {
    self.enabled_dimensions.contains(&dimension)
  }

  /// Set a duplicate-detection dimension on or off.
  fn set_dimension(&mut self, dimension: DetectionDimension, enabled: bool) {
    if enabled {
      self.enabled_dimensions.extend([dimension]);
    } else {
      self.disable_dimension(dimension);
    }
  }
}

/// Read an optional TOML configuration document.
fn read_toml_file(
  path: PathBuf,
  decode: impl FnOnce(&str) -> Result<ConfigDocument, TomlDecodeError>,
) -> Result<ConfigSource, ConfigFileError> {
  let bytes = match fs::read(&path) {
    Ok(bytes) => bytes,
    Err(source) if source.kind() == io::ErrorKind::NotFound => {
      return Ok(ConfigSource::Absent {
        path,
        source: Arc::new(source),
      });
    }
    Err(source) => {
      return Err(ConfigFileError::Read {
        path,
        source,
      });
    }
  };
  let contents = String::from_utf8(bytes).map_err(|source| ConfigFileError::Utf8 {
    path: path.clone(),
    source,
  })?;
  match decode(&contents) {
    Ok(document) => Ok(ConfigSource::Read {
      path,
      contents,
      document,
    }),
    Err(source) => Err(ConfigFileError::Decode {
      path,
      contents,
      source: Box::new(source),
    }),
  }
}

#[cfg(test)]
mod tests {
  use std::cmp::Ordering;
  use std::collections::BTreeSet;
  use std::fs;
  use std::io;
  use std::path::PathBuf;

  use strict_test_support::ConditionFailure;
  use strict_test_support::PredicateFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_that;
  use tempfile::TempDir;
  use thiserror::Error;

  use super::CargoMetadata;
  use super::CargoPackage;
  use super::CargoPackageMetadata;
  use super::Config;
  use super::ConfigDocument;
  use super::ConfigFileError;
  use super::ConfigLoadError;
  use super::ConfigSource;
  use super::FileConfig;
  use crate::code_unit::DetectionDimension;
  use crate::suppression::RuleId;
  use crate::suppression::SuppressionWarning;

  /// Native fixture failures and policy expectation failures.
  #[derive(Debug, Error)]
  enum ConfigTestFailure {
    /// Temporary configuration directory allocation failed.
    #[error("cannot allocate a configuration fixture workspace")]
    Workspace(#[from] io::Error),
    /// A configuration document could not be written.
    #[error("cannot write configuration fixture at {}", path.display())]
    Fixture {
      /// Native destination path of the document.
      path:   PathBuf,
      /// Original filesystem failure.
      source: io::Error,
    },
    /// Configuration loading retained a native failure and completed layers.
    #[error(transparent)]
    Load(#[from] ConfigLoadError),
    /// A loading outcome did not satisfy the expected preservation contract.
    #[error("configuration outcome expectation failed: {source}")]
    LoadExpectation {
      /// Complete successful or failed configuration load.
      outcome: Box<Result<Config, ConfigLoadError>>,
      /// Assertion explaining the violated contract.
      source:  ConditionFailure,
    },
    /// A loaded setting violated its contract, retaining the complete configuration.
    #[error(transparent)]
    LoadedSetting(#[from] Box<PredicateFailure<Config>>),
  }

  /// Load a dedicated file and retain its complete configuration if the requested check fails.
  fn check_dedicated_config(contents: &str, context: &'static str, accepts: impl FnOnce(&Config) -> bool) -> Result<(), ConfigTestFailure> {
    let config = {
      let workspace = TempDir::new()?;
      write_config(&workspace, "dupes.toml", contents)?;
      Config::load(workspace.path())?
    };
    ensure_that(config, context, accepts)
      .map(drop)
      .map_err(Box::new)
      .map_err(ConfigTestFailure::from)
  }

  /// Materialize one configuration layer at the filename used by the loader.
  fn write_config(workspace: &TempDir, file_name: &str, contents: &str) -> Result<(), ConfigTestFailure> {
    let path = workspace.path().join(file_name);
    fs::write(&path, contents).map_err(|source| ConfigTestFailure::Fixture {
      path,
      source,
    })
  }

  /// Materialize package metadata beneath a valid Cargo package declaration.
  fn write_package_config(workspace: &TempDir, metadata: &str) -> Result<(), ConfigTestFailure> {
    write_config(
      workspace,
      "Cargo.toml",
      &[
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        metadata,
      ]
      .concat(),
    )
  }

  /// Dedicated dimension and window settings override only the declared parts of Cargo metadata.
  #[test]
  fn dimension_and_window_layers_preserve_omitted_settings() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    write_package_config(
      &workspace,
      "\
[package.metadata.dupes.dimensions]
ast = false
sub_ast = false
token_normalized = false
token_raw = false
line = false
[package.metadata.dupes.token]
min_tokens = 32
min_lines = 4
similarity_threshold = 0.625
[package.metadata.dupes.line]
min_lines = 9
",
    )?;
    for (document, dimensions, token_lines, line_lines) in [
      ("", BTreeSet::new(), 4, 9),
      (
        "\
[dimensions]
ast = true
token_normalized = true
sub_ast = false
[token]
min_lines = 2
[line]
min_lines = 3
",
        BTreeSet::from([DetectionDimension::Ast, DetectionDimension::TokenNormalized]),
        2,
        3,
      ),
    ] {
      write_config(&workspace, "dupes.toml", document)?;
      let outcome = Config::load(workspace.path());
      ensure(
        matches!(outcome, Ok(ref config)
          if config.enabled_dimensions == dimensions
            && config.token_min_tokens == 32 && config.token_min_lines == token_lines
            && config.token_similarity_threshold.total_cmp(&0.625) == Ordering::Equal
            && config.line_min_lines == line_lines
            && matches!(config.sources.as_slice(), [ConfigSource::Read { document: ConfigDocument::Cargo(_), .. },
              ConfigSource::Read { contents, document: ConfigDocument::Dedicated(_), .. }] if contents == document)),
        "explicit toggles can disable or re-enable dimensions while omitted dimensions and window settings retain their earlier values",
      )
      .map(drop)
      .map_err(|source| ConfigTestFailure::LoadExpectation {
        outcome: Box::new(outcome),
        source,
      })?;
    }
    Ok(())
  }

  /// Dedicated rule toggles override Cargo metadata while preserving unrelated selections.
  #[test]
  fn suppress_table_toggles_rules_with_dupes_toml_winning() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    write_package_config(
      &workspace,
      r#"
            [package.metadata.dupes.suppress]
            disable = ["line.chain-tail", "token.low-signal"]
            "#,
    )?;
    write_config(
      &workspace,
      "dupes.toml",
      r#"
            [suppress]
            enable = ["line.chain-tail"]
            disable = ["sub.value-plumbing"]
            "#,
    )?;
    let config = Config::load(workspace.path())?;
    let checked_config = ensure_that(
      config,
      "dedicated-file rule overrides win while retaining unrelated Cargo rule settings",
      |observed| {
        [
          observed.suppression.is_enabled(RuleId::LineChainTail),
          observed.suppression.is_enabled(RuleId::TokenLowSignal),
          observed.suppression.is_enabled(RuleId::SubValuePlumbing),
        ] == [true, false, false]
      },
    )
    .map_err(Box::new)?;
    ensure_that(checked_config, "recognized rule overrides produce no warnings", |observed| {
      observed.load_warnings.is_empty()
    })
    .map(drop)
    .map_err(Box::new)
    .map_err(ConfigTestFailure::from)
  }

  /// Unknown rules remain nonfatal while retaining the complete rejected request.
  #[test]
  fn unknown_suppress_rule_ids_warn_without_failing() -> Result<(), ConfigTestFailure> {
    check_dedicated_config(
      r#"
            [suppress]
            disable = ["no.such-rule"]
            enable = ["no.such-rule"]
            "#,
      "retain both unknown suppression requests without rejecting the configuration",
      |observed| {
        observed.load_warnings
          == [
            SuppressionWarning::UnknownDisabledRule {
              id: "no.such-rule".to_owned(),
            },
            SuppressionWarning::UnknownEnabledRule {
              id: "no.such-rule".to_owned(),
            },
          ]
      },
    )
  }

  /// Defaults establish the documented detector sizes, thresholds, and source policy.
  #[test]
  fn default_config() -> Result<(), Box<PredicateFailure<Config>>> {
    ensure_that(
      Config::default(),
      "preserve the default detector sizes, similarity threshold, and source-selection policy",
      |observed| {
        (observed.min_nodes, observed.line_min_lines, observed.sub_function) == (10, 5, false)
          && observed.exclude.is_empty()
          && observed.similarity_threshold.total_cmp(&0.8) == Ordering::Equal
      },
    )
    .map(drop)
    .map_err(Box::new)
  }

  /// The dedicated document supplies detector settings and path exclusions.
  #[test]
  fn load_from_dupes_toml() -> Result<(), ConfigTestFailure> {
    check_dedicated_config(
      r#"
            min_nodes = 20
            similarity_threshold = 0.9
            exclude = ["tests"]
            "#,
      "load detector settings and path exclusions from the dedicated configuration file",
      |observed| {
        (observed.min_nodes, &observed.exclude) == (20, &vec!["tests".to_owned()])
          && observed.similarity_threshold.total_cmp(&0.9) == Ordering::Equal
      },
    )
  }

  /// Cargo package metadata supplies settings when the dedicated file is absent.
  #[test]
  fn load_from_cargo_toml_metadata() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    write_package_config(
      &workspace,
      "
            [package.metadata.dupes]
            min_nodes = 15
            similarity_threshold = 0.75
            ",
    )?;
    let config = Config::load(workspace.path())?;
    ensure_that(
      config,
      "load package metadata when the dedicated configuration file is absent",
      |observed| observed.min_nodes == 15 && observed.similarity_threshold.total_cmp(&0.75) == Ordering::Equal,
    )
    .map(drop)
    .map_err(Box::new)
    .map_err(ConfigTestFailure::from)
  }

  /// Dedicated settings take precedence over the same Cargo metadata fields.
  #[test]
  fn dupes_toml_overrides_cargo_toml() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    write_package_config(
      &workspace,
      "
            [package.metadata.dupes]
            min_nodes = 15
            ",
    )?;
    write_config(&workspace, "dupes.toml", "min_nodes = 25\n")?;
    let config = Config::load(workspace.path())?;
    ensure_that(
      config,
      "dedicated configuration replaces the same Cargo metadata setting",
      |observed| observed.min_nodes == 25,
    )
    .map(drop)
    .map_err(Box::new)?;
    Ok(())
  }

  /// Absent optional files preserve defaults and both native absence observations.
  #[test]
  fn load_no_config_files() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let config = ensure_that(
      Config::load(workspace.path())?,
      "absence of both configuration files retains the default AST size",
      |observed| observed.min_nodes == 10,
    )
    .map_err(Box::new)?;
    let paths = [workspace.path().join("Cargo.toml"), workspace.path().join("dupes.toml")];
    ensure(
      config.sources.len() == paths.len()
        && config.sources.iter().zip(paths).all(|(observation, expected_path)| {
          matches!(*observation, ConfigSource::Absent { ref path, ref source }
            if *path == expected_path && source.kind() == io::ErrorKind::NotFound)
        }),
      "default configuration retains both native absence observations in precedence order",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(Ok(config)),
      source,
    })
  }

  /// Resolving precedence retains every complete input document and parsed file model.
  #[test]
  fn loaded_sources_preserve_documents_before_precedence_resolution() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let cargo_contents = "[package.metadata.dupes]\nmin_nodes = 15\n";
    let dedicated_contents = "min_nodes = 25\n";
    write_config(&workspace, "Cargo.toml", cargo_contents)?;
    write_config(&workspace, "dupes.toml", dedicated_contents)?;
    let config = Config::load(workspace.path())?;
    let expected = [
      (
        workspace.path().join("Cargo.toml"),
        cargo_contents,
        ConfigDocument::Cargo(Box::new(CargoMetadata {
          package: Some(CargoPackage {
            metadata: Some(CargoPackageMetadata {
              dupes: Some(FileConfig {
                min_nodes: Some(15),
                ..Default::default()
              }),
            }),
          }),
        })),
      ),
      (
        workspace.path().join("dupes.toml"),
        dedicated_contents,
        ConfigDocument::Dedicated(Box::new(FileConfig {
          min_nodes: Some(25),
          ..Default::default()
        })),
      ),
    ];
    ensure(
      config.min_nodes == 25
        && config.sources.len() == expected.len()
        && config
          .sources
          .iter()
          .zip(expected)
          .all(|(observed, (expected_path, expected_contents, expected_document))| {
            matches!(*observed, ConfigSource::Read { ref path, ref contents, ref document }
            if *path == expected_path && contents == expected_contents && *document == expected_document)
          }),
      "resolved settings retain both complete file-format models, paths, and source documents in application order",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(Ok(config)),
      source,
    })
  }

  /// A virtual workspace is a successful Cargo document with no package overrides.
  #[test]
  fn cargo_without_package_retains_its_successful_document_observation() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let contents = "[workspace]\nmembers = []\n";
    write_config(&workspace, "Cargo.toml", contents)?;
    let config = Config::load(workspace.path())?;
    let expected_path = workspace.path().join("Cargo.toml");
    ensure(
      config.min_nodes == Config::default().min_nodes
        && config.sources.iter().any(|observation| {
          matches!(*observation, ConfigSource::Read {
            ref path, contents: ref observed_contents, document: ConfigDocument::Cargo(ref cargo),
          } if *path == expected_path && observed_contents == contents && **cargo == CargoMetadata { package: None })
        }),
      "a Cargo document without package settings is observed successfully and supplies no overrides",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(Ok(config)),
      source,
    })
  }

  /// A failed higher-precedence document preserves lower-layer settings, warnings, and input.
  #[test]
  fn malformed_dedicated_config_preserves_completed_cargo_layer() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let cargo_contents = "[package.metadata.dupes]\nmin_nodes = 37\n[package.metadata.dupes.suppress]\ndisable = [\"no.such-rule\"]\n";
    let dedicated_contents = "min_nodes = [\n";
    write_config(&workspace, "Cargo.toml", cargo_contents)?;
    write_config(&workspace, "dupes.toml", dedicated_contents)?;
    let cargo_path = workspace.path().join("Cargo.toml");
    let dedicated_path = workspace.path().join("dupes.toml");
    let outcome = Config::load(workspace.path());
    ensure(
      matches!(outcome, Err(ConfigLoadError {
        ref config,
        source: ConfigFileError::Decode { path: ref failed_path, contents: ref failed_contents, .. },
      }) if *failed_path == dedicated_path
        && failed_contents == dedicated_contents
        && config.min_nodes == 37
        && config.load_warnings == [SuppressionWarning::UnknownDisabledRule { id: "no.such-rule".to_owned() }]
        && config.sources.len() == 1
        && config.sources.iter().all(|observation| {
          matches!(*observation, ConfigSource::Read {
            ref path, ref contents, document: ConfigDocument::Cargo(ref cargo),
          } if *path == cargo_path && contents == cargo_contents
            && cargo.package.as_ref().and_then(|package| package.metadata.as_ref())
              .and_then(|metadata| metadata.dupes.as_ref()).is_some_and(|settings| settings.min_nodes == Some(37)))
        })),
      "a higher-precedence decoding failure preserves the native cause, rejected document, and completed Cargo layer",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Invalid Cargo metadata stops loading before higher-precedence settings are applied.
  #[test]
  fn malformed_cargo_config_stops_before_dedicated_overrides() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let contents = "[package\n";
    write_config(&workspace, "Cargo.toml", contents)?;
    write_config(&workspace, "dupes.toml", "min_nodes = 37\n")?;
    let path = workspace.path().join("Cargo.toml");
    let outcome = Config::load(workspace.path());
    ensure(
      matches!(outcome, Err(ConfigLoadError {
        ref config,
        source: ConfigFileError::Decode { path: ref observed_path, contents: ref observed_contents, .. },
      }) if *observed_path == path && observed_contents == contents
        && config.min_nodes == Config::default().min_nodes && config.sources.is_empty()),
      "invalid Cargo configuration returns its complete decoding failure before applying later layers",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Failed UTF-8 decoding retains the complete file bytes and native cause.
  #[test]
  fn invalid_utf8_configuration_preserves_all_input_bytes() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("Cargo.toml");
    let bytes = [0xFF_u8, 0xFE_u8, b'a'];
    fs::write(&path, bytes).map_err(|source| ConfigTestFailure::Fixture {
      path: path.clone(),
      source,
    })?;
    let outcome = Config::load(workspace.path());
    ensure(
      matches!(outcome, Err(ConfigLoadError {
        ref config,
        source: ConfigFileError::Utf8 { path: ref observed_path, ref source },
      }) if *observed_path == path && source.as_bytes() == bytes && config.sources.is_empty()),
      "invalid configuration text retains its native UTF-8 failure, exact path, and complete bytes",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// An occupied configuration path remains a native read failure rather than optional absence.
  #[test]
  fn configuration_read_failure_is_not_optional_absence() -> Result<(), ConfigTestFailure> {
    let workspace = TempDir::new()?;
    let path = workspace.path().join("Cargo.toml");
    fs::create_dir_all(&path).map_err(|source| ConfigTestFailure::Fixture {
      path: path.clone(),
      source,
    })?;
    let outcome = Config::load(workspace.path());
    ensure(
      matches!(outcome, Err(ConfigLoadError {
        ref config,
        source: ConfigFileError::Read { path: ref observed_path, ref source },
      }) if *observed_path == path && source.kind() != io::ErrorKind::NotFound && config.sources.is_empty()),
      "an occupied configuration path returns its native read failure instead of default settings",
    )
    .map(drop)
    .map_err(|source| ConfigTestFailure::LoadExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Exact and near group-count limits remain independent configuration fields.
  #[test]
  fn config_with_thresholds() -> Result<(), ConfigTestFailure> {
    check_dedicated_config(
      "max_exact_duplicates = 0\nmax_near_duplicates = 5\n",
      "load exact and near group-count limits independently",
      |observed| (observed.max_exact_duplicates, observed.max_near_duplicates) == (Some(0), Some(5)),
    )
  }

  /// The file's test-code exclusion setting reaches the resolved configuration.
  #[test]
  fn config_with_exclude_tests() -> Result<(), ConfigTestFailure> {
    check_dedicated_config("exclude_tests = true\n", "load the explicit test-code exclusion", |observed| {
      observed.exclude_tests
    })
  }

  /// The AST source-span floor is loaded from the dedicated document.
  #[test]
  fn config_with_min_lines() -> Result<(), ConfigTestFailure> {
    check_dedicated_config("min_lines = 5\n", "load the AST source-span floor", |observed| {
      observed.min_lines == 5
    })
  }

  /// Exact and near percentage limits preserve their configured values.
  #[test]
  fn config_with_percentage_thresholds() -> Result<(), ConfigTestFailure> {
    check_dedicated_config(
      "max_exact_percent = 5.0\nmax_near_percent = 10.5\n",
      "preserve both configured percentage limits",
      |observed| {
        observed
          .max_exact_percent
          .zip(observed.max_near_percent)
          .is_some_and(|(exact, near)| exact.total_cmp(&5.0) == Ordering::Equal && near.total_cmp(&10.5) == Ordering::Equal)
      },
    )
  }

  /// Token windows receive both the token-count and source-span floors.
  #[test]
  fn config_with_token_min_lines() -> Result<(), ConfigTestFailure> {
    check_dedicated_config(
      "[token]\nmin_tokens = 25\nmin_lines = 3\n",
      "load both token-count and source-span floors",
      |observed| (observed.token_min_tokens, observed.token_min_lines) == (25, 3),
    )
  }

  /// Explicit dimension selection replaces the default enabled set.
  #[test]
  fn enable_only_dimensions_replaces_default_dimensions() -> Result<(), Box<PredicateFailure<Config>>> {
    let mut config = Config::default();
    config.enable_only_dimensions([DetectionDimension::Line]);
    ensure_that(
      config,
      "enabling only line detection replaces every default dimension",
      |observed| observed.enabled_dimensions.iter().copied().eq([DetectionDimension::Line]),
    )
    .map(drop)
    .map_err(Box::new)
  }
}
