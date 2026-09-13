//! Language auto-detection and explicit `--language` selection behavior of
//! the `code-dupes` binary.

#[cfg(test)]
mod tests {
  use std::fs;
  use std::path::Path;

  use dupes_cli_test_support::CliTestFailure;
  use dupes_cli_test_support::assert_path_success_stdout;
  use dupes_cli_test_support::code_dupes;
  use dupes_cli_test_support::code_fixture_path;
  use dupes_cli_test_support::run_for_path;
  use dupes_cli_test_support::rust_fixture_path;
  use dupes_cli_test_support::write_fixture;
  use predicates::str::contains;
  use tempfile::TempDir;

  /// A successful language command must render its expected section.
  fn assert_path_command_contains(path: &Path, command_args: &[&str], expected: &str) -> Result<(), CliTestFailure> {
    assert_path_success_stdout(code_dupes, path, command_args, &[expected])
  }

  /// Default language detection must run the stats workflow.
  fn assert_stats_success(path: &Path) -> Result<(), CliTestFailure> {
    assert_path_command_contains(path, &["stats"], "Total code units analyzed")
  }

  /// Explicit language selection must run the stats workflow.
  fn assert_language_stats_success(path: &Path, language: &str) -> Result<(), CliTestFailure> {
    assert_path_command_contains(path, &["--language", language, "stats"], "Total code units analyzed")
  }

  /// Invalid language inputs must return the user-facing exit status and diagnostic.
  fn assert_path_error(path: &Path, args: &[&str], expected: &str) -> Result<(), CliTestFailure> {
    run_for_path(code_dupes, path, args)?
      .try_code(2)?
      .try_stderr(contains(expected))
      .map(drop)
      .map_err(CliTestFailure::from)
  }

  /// Empty or ambiguous default language detection must report its cause.
  fn assert_stats_error(path: &Path, expected: &str) -> Result<(), CliTestFailure> {
    assert_path_error(path, &["stats"], expected)
  }

  /// Explicit language selection must preserve its error diagnostic.
  fn assert_language_stats_error(path: &Path, language: &str, expected: &str) -> Result<(), CliTestFailure> {
    assert_path_error(path, &["--language", language, "stats"], expected)
  }

  /// Python reports must identify the requested supported code-unit shape.
  fn assert_python_dupes_report_contains(expected: &str) -> Result<(), CliTestFailure> {
    assert_path_command_contains(
      &code_fixture_path("python_dupes")?,
      &["--language", "python", "--min-nodes", "1", "--min-lines", "1"],
      expected,
    )
  }

  /// Allocate an empty filesystem fixture and retain its native allocation error.
  fn empty_fixture() -> Result<TempDir, CliTestFailure> {
    TempDir::new().map_err(|source| CliTestFailure::TemporaryDirectory {
      source,
    })
  }

  /// The same mixed-language source tree exercises rejection and explicit selection.
  fn mixed_languages() -> Result<TempDir, CliTestFailure> {
    let directory = empty_fixture()?;
    write_fixture(&directory.path().join("lib.rs"), "pub fn hello() { println!(\"hello\"); }\n")?;
    write_fixture(&directory.path().join("example.py"), "def hello():\n    print('hello')\n")?;
    Ok(directory)
  }

  /// An explicit Rust selection uses the Rust statistics workflow.
  #[test]
  fn explicit_language_rust() -> Result<(), CliTestFailure> {
    assert_language_stats_success(&rust_fixture_path("exact_dupes")?, "rust")
  }

  /// Rust source files select the Rust analyzer automatically.
  #[test]
  fn auto_detect_rust_from_rs_files() -> Result<(), CliTestFailure> {
    // Fixture directories contain .rs files, so Rust should be auto-detected
    assert_stats_success(&rust_fixture_path("exact_dupes")?)
  }

  /// Completed discovery of an empty directory reports no recognized language.
  #[test]
  fn error_on_empty_directory() -> Result<(), CliTestFailure> {
    let directory = empty_fixture()?;
    assert_stats_error(directory.path(), "No recognized source files")
  }

  /// Unsupported extensions cannot select an analyzer.
  #[test]
  fn error_on_directory_with_unknown_files_only() -> Result<(), CliTestFailure> {
    let directory = empty_fixture()?;
    write_fixture(&directory.path().join("data.csv"), "a,b,c")?;
    write_fixture(&directory.path().join("blob.dat"), "hello")?;
    assert_stats_error(directory.path(), "No recognized source files")
  }

  /// Generic text files select line detection when no AST language is present.
  #[test]
  fn auto_detects_generic_text_duplicates() -> Result<(), CliTestFailure> {
    assert_path_command_contains(
      &code_fixture_path("text_dupes")?,
      &["--line-min-lines", "5", "report"],
      "Line Exact Duplicates",
    )
  }

  /// Unsupported explicit language values preserve the parser diagnostic.
  #[test]
  fn invalid_language_shows_error() -> Result<(), CliTestFailure> {
    assert_language_stats_error(&rust_fixture_path("exact_dupes")?, "unknown", "invalid value")
  }

  /// The standalone binary accepts shared commands directly.
  #[test]
  fn no_cargo_subcommand_arg_needed() -> Result<(), CliTestFailure> {
    // Unlike cargo-dupes, code-dupes should NOT require a hidden first arg
    run_for_path(code_dupes, rust_fixture_path("exact_dupes")?, &["stats"])?
      .try_success()
      .map(drop)
      .map_err(CliTestFailure::from)
  }

  /// Explicit Rust selection reaches source discovery even when the directory is empty.
  #[test]
  fn explicit_language_on_empty_dir_reports_no_source_files() -> Result<(), CliTestFailure> {
    let directory = empty_fixture()?;
    assert_language_stats_error(directory.path(), "rust", "No source files")
  }

  /// Additional generic and unsupported files do not override an unambiguous Rust selection.
  #[test]
  fn auto_detect_ignores_non_rust_files() -> Result<(), CliTestFailure> {
    // Directory with .rs + other files should still auto-detect Rust
    let directory = empty_fixture()?;
    let src = directory.path().join("src");
    fs::create_dir_all(&src).map_err(|source| CliTestFailure::Fixture {
      path: src.clone(),
      source,
    })?;
    write_fixture(
      &src.join("lib.rs"),
      "pub fn hello() { println!(\"hello\"); }\npub fn world() { println!(\"world\"); }\n",
    )?;
    write_fixture(&directory.path().join("readme.txt"), "some text")?;
    write_fixture(&directory.path().join("data.csv"), "a,b,c")?;
    assert_stats_success(directory.path())
  }

  /// Visible nested directories contribute source-language evidence.
  #[test]
  fn auto_detect_finds_deeply_nested_rs_files() -> Result<(), CliTestFailure> {
    let directory = empty_fixture()?;
    let deep = directory.path().join("a").join("b").join("c");
    fs::create_dir_all(&deep).map_err(|source| CliTestFailure::Fixture {
      path: deep.clone(),
      source,
    })?;
    write_fixture(&deep.join("lib.rs"), "pub fn deep() { println!(\"deep\"); }\n")?;
    assert_stats_success(directory.path())
  }

  /// An explicit Python selection uses the Python statistics workflow.
  #[test]
  fn explicit_language_python() -> Result<(), CliTestFailure> {
    assert_language_stats_success(&code_fixture_path("python_dupes")?, "python")
  }

  /// Python source files select the Python analyzer automatically.
  #[test]
  fn auto_detect_python_from_py_files() -> Result<(), CliTestFailure> {
    let directory = empty_fixture()?;
    write_fixture(
      &directory.path().join("example.py"),
      "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n",
    )?;
    assert_stats_success(directory.path())
  }

  /// The Python frontend renders exact duplicate groups from real source files.
  #[test]
  fn python_detects_exact_duplicates() -> Result<(), CliTestFailure> {
    assert_python_dupes_report_contains("Exact Duplicates")
  }

  /// Multiple supported AST languages require an explicit selection.
  #[test]
  fn ambiguous_language_detection_errors() -> Result<(), CliTestFailure> {
    // Directory with both .rs and .py files should report ambiguity
    let directory = mixed_languages()?;
    assert_stats_error(directory.path(), "Multiple languages detected")
  }

  /// An explicit language resolves a mixed-language directory.
  #[test]
  fn ambiguous_language_resolved_with_explicit_flag() -> Result<(), CliTestFailure> {
    // When multiple languages are present, --language resolves the ambiguity
    let directory = mixed_languages()?;
    assert_language_stats_success(directory.path(), "python")
  }

  /// Python lambda duplicates retain their closure classification in the report.
  #[test]
  fn python_detects_lambda_duplicates() -> Result<(), CliTestFailure> {
    assert_python_dupes_report_contains("closure")
  }

  /// Python class duplicates retain their class classification in the report.
  #[test]
  fn python_detects_class_duplicates() -> Result<(), CliTestFailure> {
    assert_python_dupes_report_contains("class")
  }

  /// Explicit Python selection reaches source discovery even when the directory is empty.
  #[test]
  fn python_explicit_language_on_empty_dir() -> Result<(), CliTestFailure> {
    let directory = empty_fixture()?;
    assert_language_stats_error(directory.path(), "python", "No source files")
  }
}
