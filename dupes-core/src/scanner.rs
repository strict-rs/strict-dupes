//! Filesystem scanning: gitignore-aware source-file discovery with
//! extension filters and glob/substring exclusion patterns.

use std::fs;
use std::fs::Metadata;
use std::io;
use std::iter;
use std::path::Path;
use std::path::PathBuf;

use globset::Error as GlobError;
use globset::Glob;
use globset::GlobSet;
use globset::GlobSetBuilder;
use ignore::DirEntry;
use ignore::Error as WalkError;
use ignore::WalkBuilder;
use thiserror::Error;

/// Configuration for scanning the filesystem for source files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
  /// Root directory to scan.
  pub root:             PathBuf,
  /// Glob-like patterns to exclude.
  pub exclude_patterns: Vec<String>,
  /// File extensions to include (without the leading dot). Defaults to `["rs"]`.
  pub extensions:       Vec<String>,
}

/// Why a discovered path was excluded by source-selection policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathExclusion {
  /// A path component identifies Cargo build output.
  BuildOutput,
  /// The configured glob set matched this native path.
  Glob,
  /// A configured literal substring matched the path's encoded bytes.
  Substring {
    /// Complete configured pattern responsible for the exclusion.
    pattern: String,
  },
}

/// The source-selection decision for one observed directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSelection {
  /// The entry is a source file selected for analysis.
  Included,
  /// The resolved entry is not a regular file.
  NotFile,
  /// The file's extension is outside the configured language set.
  UnsupportedExtension,
  /// A source file was excluded by the path policy.
  Excluded(PathExclusion),
}

/// A discovered entry, its native metadata, and the applied selection decision.
#[derive(Debug)]
pub struct ScannedEntry {
  /// Native walker observation, including any attached ignore-file errors.
  pub entry:     DirEntry,
  /// Metadata used to classify the entry, following file links as before.
  pub metadata:  Metadata,
  /// The decision reached using this scan's configuration.
  pub selection: SourceSelection,
}

/// Completed source discovery with every reached entry retained.
#[derive(Debug)]
pub struct SourceScan {
  /// Complete source-selection policy used by the walker.
  pub config:  ScanConfig,
  /// Native observations in walker order, including unselected entries.
  pub entries: Vec<ScannedEntry>,
}

impl SourceScan {
  /// Borrow selected paths without consuming their native observations.
  pub fn files(&self) -> impl Iterator<Item = &Path> {
    self
      .entries
      .iter()
      .filter(|observed| observed.selection == SourceSelection::Included)
      .map(|observed| observed.entry.path())
  }
}

/// A configured exclusion could not be compiled.
#[derive(Debug, Error)]
pub enum ExclusionError {
  /// A source pattern or one of its path variants was invalid.
  #[error("invalid exclusion pattern {pattern:?} ({variant:?}): {source}")]
  Pattern {
    /// Complete pattern supplied by the caller.
    pattern: String,
    /// Exact path-oriented variant submitted to the glob parser.
    variant: String,
    /// Native glob parsing failure.
    source:  GlobError,
  },
  /// Compiling individually parsed patterns into a set failed.
  #[error("failed to compile exclusion patterns: {source}")]
  Set {
    /// Complete pattern list whose variants supplied the set.
    patterns: Vec<String>,
    /// Native glob-set compilation failure.
    source:   GlobError,
  },
}

/// Source discovery stopped with its native failure and completed observations.
#[derive(Debug, Error)]
pub enum ScanError {
  /// Exclusions could not be compiled before filesystem traversal.
  #[error("cannot scan {}: {source}", config.root.display())]
  Exclusions {
    /// Complete requested scan configuration.
    config: Box<ScanConfig>,
    /// Pattern or glob-set failure.
    source: ExclusionError,
  },
  /// The walker could not produce its next directory entry.
  #[error("source traversal failed: {source}")]
  Walk {
    /// Every observation completed before the traversal failure.
    scan:   Box<SourceScan>,
    /// Original walker failure with its native path and cause information.
    source: WalkError,
  },
  /// Metadata failed after the walker supplied an entry.
  #[error("cannot observe source entry {}: {source}", entry.path().display())]
  Metadata {
    /// Every observation completed before this entry.
    scan:   Box<SourceScan>,
    /// Native entry for which metadata could not be read.
    entry:  Box<DirEntry>,
    /// Original metadata-read failure.
    source: io::Error,
  },
}

impl ScanConfig {
  /// Config scanning `root` for `.rs` files with no exclusions.
  #[must_use]
  pub fn new(root: PathBuf) -> Self {
    Self {
      root,
      exclude_patterns: Vec::new(),
      extensions: vec!["rs".to_owned()],
    }
  }

  /// Replace the exclusion patterns.
  #[must_use]
  pub fn with_excludes(mut self, patterns: Vec<String>) -> Self {
    self.exclude_patterns = patterns;
    self
  }

  /// Replace the included file extensions.
  #[must_use]
  pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
    self.extensions = extensions;
    self
  }
}

/// Scan for source files under the given config.
/// Always skips `target/` directories.
///
/// # Errors
///
/// Returns exclusion-compilation, traversal, or metadata failures with
/// every native observation completed before the failing step.
pub fn scan_files(config: &ScanConfig) -> Result<SourceScan, ScanError> {
  let exclude_set = build_exclude_set(&config.exclude_patterns).map_err(|source| ScanError::Exclusions {
    config: Box::new(config.clone()),
    source,
  })?;
  let mut scan = SourceScan {
    config:  config.clone(),
    entries: Vec::new(),
  };

  for entry in WalkBuilder::new(&config.root)
    .hidden(true)
    .git_ignore(true)
    .git_exclude(true)
    .parents(true)
    .build()
  {
    let observed_entry = match entry {
      Ok(observed_entry) => observed_entry,
      Err(source) => {
        return Err(ScanError::Walk {
          scan: Box::new(scan),
          source,
        });
      }
    };
    let metadata = match fs::metadata(observed_entry.path()) {
      Ok(metadata) => metadata,
      Err(source) => {
        return Err(ScanError::Metadata {
          scan: Box::new(scan),
          entry: Box::new(observed_entry),
          source,
        });
      }
    };
    let path = observed_entry.path();
    let selection = if !metadata.is_file() {
      SourceSelection::NotFile
    } else if !path.extension().is_some_and(|extension| {
      config
        .extensions
        .iter()
        .any(|configured| extension.as_encoded_bytes().eq_ignore_ascii_case(configured.as_bytes()))
    }) {
      SourceSelection::UnsupportedExtension
    } else {
      exclusion_with_set(path, &exclude_set, &config.exclude_patterns).map_or(SourceSelection::Included, SourceSelection::Excluded)
    };
    scan.entries.push(ScannedEntry {
      entry: observed_entry,
      metadata,
      selection,
    });
  }
  Ok(scan)
}

/// Classify whether a path is excluded, retaining the applicable rule.
///
/// # Errors
///
/// Returns the invalid pattern or glob-set compilation failure.
#[allow(
  clippy::single_call_fn,
  reason = "The public path classifier applies scanner exclusion rules without requiring a filesystem traversal."
)]
pub fn is_excluded(path: &Path, patterns: &[String]) -> Result<Option<PathExclusion>, ExclusionError> {
  let exclude_set = build_exclude_set(patterns)?;
  Ok(exclusion_with_set(path, &exclude_set, patterns))
}

/// Resolve the first applicable exclusion without decoding the native path.
fn exclusion_with_set(path: &Path, exclude_set: &GlobSet, patterns: &[String]) -> Option<PathExclusion> {
  if path.components().any(|component| component.as_os_str() == "target") {
    return Some(PathExclusion::BuildOutput);
  }
  if exclude_set.is_match(path) {
    return Some(PathExclusion::Glob);
  }
  let path_bytes = path.as_os_str().as_encoded_bytes();
  patterns
    .iter()
    .find(|pattern| {
      iter::successors(Some(path_bytes), |remaining| remaining.split_first().map(|(_, tail)| tail))
        .any(|suffix| suffix.starts_with(pattern.as_bytes()))
    })
    .map(|pattern| PathExclusion::Substring {
      pattern: pattern.clone()
    })
}

/// Build a glob set from configured exclude patterns.
fn build_exclude_set(patterns: &[String]) -> Result<GlobSet, ExclusionError> {
  let mut builder = GlobSetBuilder::new();
  let mut candidates = patterns
    .iter()
    .flat_map(|pattern| exclude_variants(pattern).into_iter().map(move |candidate| (pattern, candidate)));
  candidates
    .try_fold(&mut builder, |set, (pattern, candidate)| {
      Glob::new(&candidate)
        .map(|glob| set.add(glob))
        .map_err(|source| ExclusionError::Pattern {
          pattern: pattern.clone(),
          variant: candidate,
          source,
        })
    })?
    .build()
    .map_err(|source| ExclusionError::Set {
      patterns: patterns.to_vec(),
      source,
    })
}

/// Expand a user pattern into useful path-oriented glob variants.
#[allow(
  clippy::single_call_fn,
  reason = "Pattern expansion owns the distinction between explicit glob syntax and directory-name exclusions."
)]
fn exclude_variants(pattern: &str) -> Vec<String> {
  if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
    vec![pattern.to_owned()]
  } else {
    vec![
      pattern.to_owned(),
      format!("**/{pattern}"),
      format!("**/{pattern}/**"),
      format!("**/{pattern}/"),
    ]
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;
  #[cfg(unix)]
  use std::ffi::OsString;
  use std::fs;
  use std::io;
  #[cfg(unix)]
  use std::os::unix::ffi::OsStringExt as _;
  #[cfg(unix)]
  use std::os::unix::fs::symlink;
  use std::path::Path;
  use std::path::PathBuf;

  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;
  use thiserror::Error;

  use super::ExclusionError;
  use super::PathExclusion;
  use super::ScanConfig;
  use super::ScanError;
  use super::SourceScan;
  use super::SourceSelection;
  use super::is_excluded;
  use super::scan_files;

  /// Fixture and assertion failures from real filesystem discovery tests.
  #[derive(Debug, Error)]
  enum ScannerTestFailure {
    /// Temporary workspace allocation failed before fixture construction.
    #[error("cannot allocate a scanner fixture workspace")]
    Workspace(#[from] io::Error),
    /// A fixture entry could not be created or written.
    #[error("cannot prepare scanner fixture at {}", path.display())]
    Fixture {
      /// Native path of the entry being prepared.
      path:   PathBuf,
      /// Original filesystem failure.
      source: io::Error,
    },
    /// Discovery failed with its native cause and completed observations.
    #[error(transparent)]
    Scan(#[from] ScanError),
    /// A scan returned an unexpected result or lost native evidence.
    #[error("scan outcome expectation failed: {source}")]
    ScanExpectation {
      /// Complete result observed at the scanner boundary.
      outcome: Box<Result<SourceScan, ScanError>>,
      /// Assertion explaining the violated contract.
      source:  ConditionFailure,
    },
    /// An exclusion decision differed from the expected policy attribution.
    #[error("path exclusion expectation failed for {}: {source}; outcome: {outcome:?}", path.display())]
    PathExclusion {
      /// Native path supplied to the classifier.
      path:     PathBuf,
      /// Complete configured pattern list.
      patterns: Vec<String>,
      /// Expected exclusion attribution or absence.
      expected: Option<PathExclusion>,
      /// Complete returned decision or pattern-compilation failure.
      outcome:  Box<Result<Option<PathExclusion>, ExclusionError>>,
      /// Failed behavioral expectation.
      source:   Box<ConditionFailure>,
    },
  }

  /// Populate visible source, hidden source, build output, and a non-source file.
  fn create_test_tree(directory: &Path) -> Result<(), ScannerTestFailure> {
    for relative in ["src/utils", "target/debug", ".hidden"] {
      let path = directory.join(relative);
      fs::create_dir_all(&path).map_err(|source| ScannerTestFailure::Fixture {
        path,
        source,
      })?;
    }
    for (relative, contents) in [
      ("src/main.rs", "fn main() {}"),
      ("src/lib.rs", "pub mod utils;"),
      ("src/utils/helper.rs", "pub fn help() {}"),
      ("target/debug/build.rs", "fn build() {}"),
      (".hidden/secret.rs", "fn secret() {}"),
      ("src/readme.md", "# README"),
    ] {
      let path = directory.join(relative);
      fs::write(&path, contents).map_err(|source| ScannerTestFailure::Fixture {
        path,
        source,
      })?;
    }
    Ok(())
  }

  #[test]
  fn scan_finds_rust_files() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    create_test_tree(workspace.path())?;
    let config = ScanConfig::new(workspace.path().to_path_buf());
    let scan = scan_files(&config)?;
    let files = scan.files().map(Path::to_path_buf).collect::<BTreeSet<_>>();
    let expected = ["src/lib.rs", "src/main.rs", "src/utils/helper.rs"]
      .map(|relative| workspace.path().join(relative))
      .into_iter()
      .collect::<BTreeSet<_>>();
    ensure(
      files == expected
        && scan.entries.iter().any(|observed| {
          observed.entry.path() == workspace.path().join("src/readme.md")
            && observed.metadata.is_file()
            && observed.selection == SourceSelection::UnsupportedExtension
        }),
      "discover every visible Rust source and retain the non-source file observation",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(Ok(scan)),
      source,
    })
  }

  #[test]
  fn scan_skips_target_directory() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    create_test_tree(workspace.path())?;
    let config = ScanConfig::new(workspace.path().to_path_buf());
    let scan = scan_files(&config)?;
    ensure(
      scan.files().all(|path| !path.starts_with(workspace.path().join("target")))
        && scan.entries.iter().any(|observed| {
          observed.entry.path() == workspace.path().join("target/debug/build.rs")
            && observed.metadata.is_file()
            && observed.selection == SourceSelection::Excluded(PathExclusion::BuildOutput)
        }),
      "exclude build-output sources while retaining their native observations and exclusion decisions",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(Ok(scan)),
      source,
    })
  }

  #[test]
  fn scan_skips_hidden_directories() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    create_test_tree(workspace.path())?;
    let config = ScanConfig::new(workspace.path().to_path_buf());
    let scan = scan_files(&config)?;
    let visible = scan.files().all(|path| !path.starts_with(workspace.path().join(".hidden")));
    ensure(visible, "exclude source files beneath hidden directories")
      .map(drop)
      .map_err(|source| ScannerTestFailure::ScanExpectation {
        outcome: Box::new(Ok(scan)),
        source,
      })
  }

  #[test]
  fn scan_respects_exclude_patterns() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    create_test_tree(workspace.path())?;
    let config = ScanConfig::new(workspace.path().to_path_buf()).with_excludes(vec!["utils".to_owned()]);
    let scan = scan_files(&config)?;
    let files = scan.files().map(Path::to_path_buf).collect::<BTreeSet<_>>();
    let expected = ["src/lib.rs", "src/main.rs"]
      .map(|relative| workspace.path().join(relative))
      .into_iter()
      .collect::<BTreeSet<_>>();
    ensure(
      files == expected,
      "retain unexcluded source files while removing the matched directory",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(Ok(scan)),
      source,
    })
  }

  #[test]
  fn scan_empty_directory() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    let config = ScanConfig::new(workspace.path().to_path_buf());
    let scan = scan_files(&config)?;
    ensure(
      scan.files().next().is_none()
        && scan.entries.len() == 1
        && scan.entries.iter().all(|observed| {
          observed.entry.path() == workspace.path() && observed.metadata.is_dir() && observed.selection == SourceSelection::NotFile
        }),
      "an empty source selection retains the successfully observed root directory",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(Ok(scan)),
      source,
    })
  }

  #[test]
  fn is_excluded_works() -> Result<(), ScannerTestFailure> {
    let cases = [
      ("/foo/bar/tests/test.rs", ["tests"].as_slice(), Some(PathExclusion::Glob)),
      ("/foo/bar/tests/test.rs", &["benches"], None),
      ("/foo/target/test.rs", &[], Some(PathExclusion::BuildOutput)),
      (
        "/foo/testing.rs",
        &["test"],
        Some(PathExclusion::Substring {
          pattern: "test".to_owned(),
        }),
      ),
      ("/foo/bar/tests/test.rs", &[""], Some(PathExclusion::Glob)),
    ];
    for (input, configured, expected) in cases {
      let path = PathBuf::from(input);
      let patterns = configured.iter().map(|pattern| (*pattern).to_owned()).collect::<Vec<_>>();
      let outcome = is_excluded(&path, &patterns);
      ensure(
        outcome.as_ref().is_ok_and(|observed| *observed == expected),
        "classify glob, literal, and build-output exclusions while retaining unmatched paths",
      )
      .map(drop)
      .map_err(|source| ScannerTestFailure::PathExclusion {
        path,
        patterns,
        expected,
        outcome: Box::new(outcome),
        source: Box::new(source),
      })?;
    }
    Ok(())
  }

  #[test]
  fn invalid_exclusion_preserves_pattern_and_stops_before_walking() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    let config = ScanConfig::new(workspace.path().join("missing")).with_excludes(vec!["[".to_owned()]);
    let outcome = scan_files(&config);
    ensure(
      matches!(outcome, Err(ScanError::Exclusions {
        config: ref requested,
        source: ExclusionError::Pattern { ref pattern, ref variant, ref source },
      }) if **requested == config && pattern == "[" && variant == "[" && source.glob() == Some("[")),
      "invalid patterns retain the requested scan and exact rejected glob before any traversal",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  #[test]
  fn missing_root_retains_native_traversal_failure() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    let config = ScanConfig::new(workspace.path().join("missing"));
    let outcome = scan_files(&config);
    ensure(
      matches!(outcome, Err(ScanError::Walk { ref scan, ref source })
        if scan.config == config && scan.entries.is_empty()
          && source.io_error().is_some_and(|native| native.kind() == io::ErrorKind::NotFound)),
      "a missing root returns the original traversal failure with the requested scan and no invented observations",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  #[cfg(unix)]
  #[test]
  fn dangling_source_link_retains_completed_directory_observation() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    let link = workspace.path().join("dangling.rs");
    symlink("absent.rs", &link).map_err(|source| ScannerTestFailure::Fixture {
      path: link.clone(),
      source,
    })?;
    let outcome = scan_files(&ScanConfig::new(workspace.path().to_path_buf()));
    ensure(
      matches!(outcome, Err(ScanError::Metadata { ref scan, ref entry, ref source })
      if entry.path() == link && entry.path_is_symlink() && source.kind() == io::ErrorKind::NotFound
        && scan.entries.len() == 1 && scan.entries.iter().all(|observed| {
          observed.entry.path() == workspace.path() && observed.metadata.is_dir()
            && observed.selection == SourceSelection::NotFile
        })),
      "failed link-target metadata retains the native link entry, I/O failure, and earlier root observation",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  #[cfg(unix)]
  #[test]
  fn source_file_link_retains_link_identity_and_target_metadata() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    let root = workspace.path().join("sources");
    fs::create_dir_all(&root).map_err(|source| ScannerTestFailure::Fixture {
      path: root.clone(),
      source,
    })?;
    let target = workspace.path().join("outside.rs");
    fs::write(&target, "fn linked_source() {}\n").map_err(|source| ScannerTestFailure::Fixture {
      path: target.clone(),
      source,
    })?;
    let link = root.join("inside.rs");
    symlink(&target, &link).map_err(|source| ScannerTestFailure::Fixture {
      path: link.clone(),
      source,
    })?;
    let scan = scan_files(&ScanConfig::new(root))?;
    ensure(
      scan.files().collect::<Vec<_>>() == vec![link.as_path()]
        && scan.entries.iter().any(|observed| {
          observed.entry.path() == link
            && observed.entry.path_is_symlink()
            && observed.metadata.is_file()
            && observed.selection == SourceSelection::Included
        }),
      "a link to a source file remains selectable while retaining both link identity and resolved file metadata",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(Ok(scan)),
      source,
    })
  }

  #[cfg(unix)]
  #[test]
  fn native_paths_remain_selectable_without_lossy_pattern_matches() -> Result<(), ScannerTestFailure> {
    let workspace = TempDir::new()?;
    let root = workspace.path().join(OsString::from_vec(b"native\xFF".to_vec()));
    fs::create_dir_all(&root).map_err(|source| ScannerTestFailure::Fixture {
      path: root.clone(),
      source,
    })?;
    let path = root.join("source.RS");
    fs::write(&path, "fn native_source() {}\n").map_err(|source| ScannerTestFailure::Fixture {
      path: path.clone(),
      source,
    })?;
    let config = ScanConfig::new(root).with_excludes(vec!["\u{FFFD}".to_owned()]);
    let scan = scan_files(&config)?;
    ensure(
      scan.config == config && scan.files().collect::<Vec<_>>() == vec![path.as_path()],
      "native path bytes are preserved, replacement-character exclusions do not match them, and extension matching ignores ASCII case",
    )
    .map(drop)
    .map_err(|source| ScannerTestFailure::ScanExpectation {
      outcome: Box::new(Ok(scan)),
      source,
    })
  }
}
