//! Native source reads shared by the analysis pipeline and language adapters.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::string::FromUtf8Error;

/// A complete source read with its original file identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
  /// Native path used for the read.
  pub path:     PathBuf,
  /// Complete decoded source text.
  pub contents: String,
}

/// A source read that failed before producing UTF-8 text.
#[derive(Debug, thiserror::Error)]
pub enum SourceReadError {
  /// The operating system rejected the read.
  #[error("Failed to read {path}: {source}")]
  Read {
    /// Native identity of the requested file.
    path:   PathBuf,
    /// Original operating-system failure.
    source: io::Error,
  },
  /// The bytes were read successfully but could not be decoded as UTF-8.
  #[error("Failed to decode {path} as UTF-8: {source}")]
  Utf8 {
    /// Native identity of the file whose bytes were read.
    path:   PathBuf,
    /// Native decoding failure retaining the complete byte buffer.
    source: FromUtf8Error,
  },
}

impl SourceFile {
  /// Read a complete UTF-8 source file.
  ///
  /// # Errors
  ///
  /// Returns the native I/O or decoding error with its path and available bytes.
  pub fn read(path: &Path) -> Result<Self, SourceReadError> {
    let bytes = fs::read(path).map_err(|source| SourceReadError::Read {
      path: path.to_path_buf(),
      source,
    })?;
    let contents = String::from_utf8(bytes).map_err(|source| SourceReadError::Utf8 {
      path: path.to_path_buf(),
      source,
    })?;
    Ok(Self {
      path: path.to_path_buf(),
      contents,
    })
  }
}
