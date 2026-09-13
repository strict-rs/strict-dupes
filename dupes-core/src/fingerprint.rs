//! Deterministic content fingerprints over normalized nodes, hashed with
//! BLAKE3 and rendered as 16-digit hex identities.

use std::fmt;
use std::num::ParseIntError;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error;

use crate::node::NormalizedNode;

/// A fingerprint of a normalized AST node, wrapping a u64 hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(u64);

/// A hexadecimal fingerprint could not be represented as its native identity.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid fingerprint {input:?}: {source}")]
pub struct FingerprintParseError {
  /// Complete original spelling supplied to the parser.
  pub input:  String,
  /// Native integer parsing failure, including invalid digits or overflow.
  pub source: ParseIntError,
}

/// Original fingerprint text together with its complete interpretation.
///
/// Serialization preserves the original spelling, including malformed text.
/// Deserialization records parsing failures without rejecting the containing registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedFingerprint {
  /// The text supplied a representable hexadecimal identity.
  Parsed {
    /// Complete original spelling, including case and leading zeroes.
    input:       String,
    /// Native content identity recovered from that spelling.
    fingerprint: Fingerprint,
  },
  /// The text could not be interpreted as a native fingerprint.
  Invalid(FingerprintParseError),
}

impl RecordedFingerprint {
  /// Read recorded text while retaining either its identity or its native failure.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Recorded identity parsing preserves the original registry spelling and native parse outcome at one public boundary"
  )]
  pub fn parse(input: String) -> Self {
    match Fingerprint::from_hex(&input) {
      Ok(fingerprint) => Self::Parsed {
        input,
        fingerprint,
      },
      Err(source) => Self::Invalid(source),
    }
  }

  /// Borrow the complete original text independently of whether parsing succeeded.
  #[must_use]
  pub fn input(&self) -> &str {
    match *self {
      Self::Parsed {
        ref input, ..
      } => input,
      Self::Invalid(ref failure) => &failure.input,
    }
  }
}

impl From<Fingerprint> for RecordedFingerprint {
  /// Record an already-known identity using its canonical hexadecimal spelling.
  fn from(fingerprint: Fingerprint) -> Self {
    Self::Parsed {
      input: fingerprint.to_hex(),
      fingerprint,
    }
  }
}

impl fmt::Display for RecordedFingerprint {
  /// Render the original registry text, including an unparseable spelling.
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.input())
  }
}

impl Serialize for RecordedFingerprint {
  /// Preserve the recorded spelling as a string in the containing document.
  fn serialize<Encoder: Serializer>(&self, encoder: Encoder) -> Result<Encoder::Ok, Encoder::Error> {
    encoder.serialize_str(self.input())
  }
}

impl<'de> Deserialize<'de> for RecordedFingerprint {
  /// Retain malformed fingerprint text as a typed observation after string decoding.
  fn deserialize<Decoder: Deserializer<'de>>(decoder: Decoder) -> Result<Self, Decoder::Error> {
    String::deserialize(decoder).map(Self::parse)
  }
}

impl Fingerprint {
  /// Compute a deterministic fingerprint from bytes.
  #[must_use]
  pub fn from_bytes(bytes: &[u8]) -> Self {
    let digest = blake3::hash(bytes);
    let prefix = digest
      .as_bytes()
      .iter()
      .take(size_of::<u64>())
      .fold(0_u64, |prefix, &byte| prefix.rotate_left(u8::BITS) | u64::from(byte));
    Self(prefix)
  }

  /// Compute a fingerprint from a normalized node.
  #[must_use]
  pub fn from_node(node: &NormalizedNode) -> Self {
    Self::from_bytes(format!("{node:?}").as_bytes())
  }

  /// Compute a fingerprint from a signature + body pair.
  #[must_use]
  pub fn from_sig_and_body(sig: &NormalizedNode, body: &NormalizedNode) -> Self {
    Self::from_bytes(format!("{sig:?}\n{body:?}").as_bytes())
  }

  /// Compute a composite fingerprint from a set of fingerprints.
  /// Sorts by u64 value for order-independence, then hashes the sorted sequence.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Composite content identity is the shared contract used by duplicate grouping and external analyzers"
  )]
  pub fn from_fingerprints(fps: &[Self]) -> Self {
    let mut sorted: Vec<u64> = fps.iter().map(|fp| fp.0).collect();
    sorted.sort_unstable();
    Self::from_bytes(format!("{sorted:?}").as_bytes())
  }

  /// Get the raw u64 value.
  #[must_use]
  pub const fn value(self) -> u64 {
    self.0
  }

  /// Convert to hex string.
  #[must_use]
  pub fn to_hex(self) -> String {
    format!("{:016x}", self.0)
  }

  /// Parse the hexadecimal spelling accepted by the native unsigned integer parser.
  ///
  /// # Errors
  ///
  /// Returns the complete input and native parsing failure for empty text,
  /// invalid digits, or an identity exceeding `u64` capacity.
  pub fn from_hex(hex: &str) -> Result<Self, FingerprintParseError> {
    u64::from_str_radix(hex, 16).map(Self).map_err(|source| FingerprintParseError {
      input: hex.to_owned(),
      source,
    })
  }
}

impl fmt::Display for Fingerprint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:016x}", self.0)
  }
}

#[cfg(test)]
mod tests {
  use std::num::IntErrorKind;

  use strict_test_support::TestFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;
  use thiserror::Error;

  use super::Fingerprint;
  use super::FingerprintParseError;
  use super::RecordedFingerprint;

  /// A fingerprint expectation failed with the full parser result retained.
  #[derive(Debug, Error)]
  #[error("fingerprint parsing expectation failed: {source}; outcome: {outcome:?}")]
  struct FingerprintTestFailure {
    /// Complete successful identity or failed parsing operation.
    outcome: Result<Fingerprint, FingerprintParseError>,
    /// Failed behavioral expectation.
    source:  TestFailure,
  }

  /// Compare a parser result without discarding a successful identity or native error.
  fn check_parse(
    input: &str,
    check: impl FnOnce(&Result<Fingerprint, FingerprintParseError>) -> Result<(), TestFailure>,
  ) -> Result<(), FingerprintTestFailure> {
    let outcome = Fingerprint::from_hex(input);
    check(&outcome).map_err(|source| FingerprintTestFailure {
      outcome,
      source,
    })
  }

  /// Hexadecimal serialization and parsing preserve every fingerprint bit.
  #[test]
  fn hex_roundtrip() -> Result<(), FingerprintTestFailure> {
    let fp = Fingerprint(0xdead_beef_1234_5678);
    let hex = fp.to_hex();
    check_parse(&hex, |outcome| {
      ensure_eq(&hex.as_str(), &"deadbeef12345678", "hexadecimal content identity")?;
      ensure(*outcome == Ok(fp), "hexadecimal parsing preserves all fingerprint bits")
    })
  }

  /// Native hexadecimal parsing accepts short, uppercase, signed-positive, and boundary identities.
  #[test]
  fn from_hex_preserves_supported_spellings() -> Result<(), FingerprintTestFailure> {
    for (input, expected) in [
      ("0", Fingerprint(0)),
      ("42", Fingerprint(0x42)),
      ("+0000000000000042", Fingerprint(0x42)),
      ("DEADBEEF12345678", Fingerprint(0xdead_beef_1234_5678)),
      ("ffffffffffffffff", Fingerprint(u64::MAX)),
    ] {
      check_parse(input, |outcome| {
        ensure(*outcome == Ok(expected), "supported spelling preserves its native identity")
      })?;
    }
    Ok(())
  }

  /// Display includes all sixteen hexadecimal digits, including leading zeroes.
  #[test]
  fn display_format() -> Result<(), TestFailure> {
    let fp = Fingerprint(0x0000_0000_0000_0042);
    ensure_eq(
      &format!("{fp}").as_str(),
      &"0000000000000042",
      "display pads the complete hexadecimal identity",
    )
  }

  /// Rejected hexadecimal text retains both its original spelling and native error.
  #[test]
  fn from_hex_invalid() -> Result<(), FingerprintTestFailure> {
    for (input, kind) in [
      ("", IntErrorKind::Empty),
      ("not_hex", IntErrorKind::InvalidDigit),
      ("-1", IntErrorKind::InvalidDigit),
      (" 42", IntErrorKind::InvalidDigit),
      ("10000000000000000", IntErrorKind::PosOverflow),
    ] {
      check_parse(input, |outcome| {
        ensure(
          matches!(outcome, Err(failure) if failure.input == input && *failure.source.kind() == kind),
          "rejected text retains its complete input and native integer failure",
        )
      })?;
    }
    Ok(())
  }

  /// Recorded spellings remain distinct even when they describe the same identity.
  #[test]
  fn recorded_fingerprint_preserves_original_spelling() -> Result<(), TestFailure> {
    let recorded = RecordedFingerprint::parse("+00AB".to_owned());
    ensure_eq(
      &recorded,
      &RecordedFingerprint::Parsed {
        input:       "+00AB".to_owned(),
        fingerprint: Fingerprint(0xAB),
      },
      "recorded text retains its spelling and parsed identity together",
    )?;
    ensure_eq(
      &recorded.to_string(),
      &"+00AB".to_owned(),
      "display preserves the recorded spelling",
    )
  }

  /// Reordering members leaves a composite content identity unchanged.
  #[test]
  fn composite_fingerprint_order_independent() -> Result<(), TestFailure> {
    let fp1 = Fingerprint(1);
    let fp2 = Fingerprint(2);
    let fp3 = Fingerprint(3);
    ensure_eq(
      &Fingerprint::from_fingerprints(&[fp1, fp2, fp3]),
      &Fingerprint::from_fingerprints(&[fp3, fp1, fp2]),
      "composite identity is independent of member order",
    )
  }

  /// Changing members changes the composite content identity.
  #[test]
  fn composite_fingerprint_different_sets_differ() -> Result<(), TestFailure> {
    let fp1 = Fingerprint(1);
    let fp2 = Fingerprint(2);
    let fp3 = Fingerprint(3);
    ensure(
      Fingerprint::from_fingerprints(&[fp1, fp2]) != Fingerprint::from_fingerprints(&[fp2, fp3]),
      "changing members changes the composite identity",
    )
  }

  /// Repeated composition of the same identities is deterministic.
  #[test]
  fn composite_fingerprint_deterministic() -> Result<(), TestFailure> {
    let fp1 = Fingerprint(42);
    let fp2 = Fingerprint(99);
    let first = Fingerprint::from_fingerprints(&[fp1, fp2]);
    let repeated = Fingerprint::from_fingerprints(&[fp1, fp2]);
    ensure_eq(&first, &repeated, "repeated composition preserves content identity")
  }
}
