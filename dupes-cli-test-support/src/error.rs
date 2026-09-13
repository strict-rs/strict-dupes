//! Concrete failures from CLI fixture preparation, execution, and assertions.

use std::io;
use std::path::PathBuf;
use std::string::FromUtf8Error;

use assert_cmd::Command;
use assert_cmd::assert::Assert;
use assert_cmd::assert::AssertError;
use serde_json::Value;
use strict_test_support::TestFailure;

/// Failure of a shared CLI test operation, preserving its native cause and inputs.
#[derive(Debug, thiserror::Error)]
pub enum CliTestFailure {
  /// Cargo did not provide the runtime artifact path for a requested test executable.
  #[error("Cargo runtime variable `{variable}` is unset for the `{binary}` test executable")]
  Binary {
    /// Requested workspace binary.
    binary:   &'static str,
    /// Exact environment variable whose absence prevented command preparation.
    variable: String,
  },
  /// A prepared command could not execute or be captured.
  #[error("could not execute the CLI test command: {source}")]
  Command {
    /// Prepared command, including its native program, arguments, and environment.
    command: Box<Command>,
    /// Original execution failure.
    source:  io::Error,
  },
  /// A native pipe for exercising process-output failures could not be created.
  #[error("could not create the CLI output pipe: {source}")]
  Pipe {
    /// Original operating-system pipe creation failure.
    source: io::Error,
  },
  /// A native process-output assertion failed.
  #[error(transparent)]
  Assertion(Box<AssertError>),
  /// Decoding failed after the command's status was checked.
  #[error("could not decode the captured command output: {source}")]
  Output {
    /// Complete captured stdout, stderr, status, and native assertion context.
    captured: Box<Assert>,
    /// Original decoding failure.
    source:   Box<Self>,
  },
  /// A captured byte stream was not valid UTF-8.
  #[error(transparent)]
  Utf8(#[from] FromUtf8Error),
  /// A captured document was not valid JSON.
  #[error("CLI output was not valid JSON: {source}")]
  Json {
    /// Complete input bytes passed to the JSON parser.
    input:  Vec<u8>,
    /// Original JSON parser failure.
    source: serde_json::Error,
  },
  /// A fixture filesystem operation failed.
  #[error("fixture operation failed for `{}`: {source}", path.display())]
  Fixture {
    /// Complete native path of the failed operation.
    path:   PathBuf,
    /// Original filesystem failure.
    source: io::Error,
  },
  /// A temporary fixture directory could not be allocated.
  #[error("could not allocate a temporary fixture: {source}")]
  TemporaryDirectory {
    /// Original allocation failure.
    source: io::Error,
  },
  /// The compiled manifest path does not have a workspace parent.
  #[error("test-support manifest directory `{}` has no parent", manifest.display())]
  WorkspaceRoot {
    /// Complete compiled manifest directory.
    manifest: PathBuf,
  },
  /// A text report had no copyable fingerprint of the requested kind.
  #[error("text report has no matching copyable fingerprint")]
  ReportFingerprint {
    /// Complete report examined by the parser.
    report:             String,
    /// Whether the requested fingerprint must belong to a near group.
    require_similarity: bool,
  },
  /// A parsed JSON document violated the report schema expected by a test.
  #[error("JSON report {context}")]
  JsonShape {
    /// Complete document or field with the invalid shape.
    document: Value,
    /// Expected schema property.
    context:  &'static str,
  },
  /// A required report field was absent.
  #[error("JSON report is missing `{field}`")]
  JsonField {
    /// Complete object inspected for the field.
    document: Value,
    /// Required field name.
    field:    String,
  },
  /// A consolidated source site still appeared in a visible duplicate group.
  #[error("{needle} {why}")]
  UnexpectedMember {
    /// Complete report containing the unexpected member.
    report:      Value,
    /// Source member name fragment being checked.
    needle:      String,
    /// Source-file fragment restricting the check.
    file_needle: String,
    /// Explanation of the supported consolidation invariant.
    why:         String,
  },
  /// A check failed while examining a complete parsed report.
  #[error("CLI report expectation failed: {source}")]
  Report {
    /// Complete parsed report retained with the failed check.
    document: Value,
    /// Original check failure.
    source:   Box<Self>,
  },
  /// A panic-free expectation from the shared test vocabulary failed.
  #[error(transparent)]
  Expectation(#[from] TestFailure),
}

impl From<AssertError> for CliTestFailure {
  fn from(source: AssertError) -> Self {
    Self::Assertion(Box::new(source))
  }
}
