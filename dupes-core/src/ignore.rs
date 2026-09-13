//! The `.dupes-ignore.toml` registry: entry load/save, fingerprint and
//! member-subset matching, report-time group filtering, and stale-entry
//! detection for the cleanup command.

use std::collections::HashSet;
use std::fs;
use std::hash::BuildHasher;
use std::io;
use std::num::ParseIntError;
use std::path::Path;
use std::path::PathBuf;
use std::string::FromUtf8Error;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use toml::de::Error as TomlDecodeError;
use toml::ser::Error as TomlEncodeError;

use crate::fingerprint::Fingerprint;
use crate::fingerprint::RecordedFingerprint;
use crate::grouper::DuplicateGroup;

/// Registry filename beneath the analysis root.
const IGNORE_FILE_NAME: &str = ".dupes-ignore.toml";

/// An entry in the ignore file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgnoreEntry {
  /// The original group identity spelling and its complete parsing outcome.
  pub fingerprint:         RecordedFingerprint,
  /// Optional reason for ignoring.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub reason:              Option<String>,
  /// Member descriptions used for documentation and advisory successor lookup.
  ///
  /// Writers use `name (path:start-end)`; the legacy `token window path:start-end`
  /// form is also understood. Malformed locations remain typed observations and
  /// do not determine whether this entry is live or stale.
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub members:             Vec<String>,
  /// Content fingerprints of the group's member units when recorded.
  ///
  /// Group fingerprints change when a group's membership drifts (a new
  /// near member joins) even though the registered duplicate relationship
  /// persists. An entry whose recorded member fingerprints all still
  /// appear together in one group keeps matching that group, so it
  /// survives membership drift; it stops matching only when the recorded
  /// content itself changes.
  ///
  /// Malformed recorded spellings retain their native parse failures. Matching
  /// continues to use the nonempty set of usable recorded identities.
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub member_fingerprints: Vec<RecordedFingerprint>,
}

impl IgnoreEntry {
  /// Interpret every recorded member description without discarding malformed locations.
  #[must_use]
  pub fn member_locations(&self) -> Vec<IgnoreMemberObservation> {
    self
      .members
      .iter()
      .map(|description| IgnoreMemberObservation {
        description: description.clone(),
        location:    parse_member_location(description),
      })
      .collect()
  }

  /// Borrow usable member identities while all native parse outcomes remain in the entry.
  fn recorded_member_fingerprints(&self) -> impl Iterator<Item = &Fingerprint> {
    self.member_fingerprints.iter().filter_map(|recorded| match *recorded {
      RecordedFingerprint::Parsed {
        ref fingerprint, ..
      } => Some(fingerprint),
      RecordedFingerprint::Invalid(_) => None,
    })
  }

  /// True when every recorded member fingerprint appears in `member_set`.
  fn members_all_in(&self, member_set: &HashSet<Fingerprint, impl BuildHasher>) -> bool {
    let mut recorded = self.recorded_member_fingerprints();
    let Some(first) = recorded.next() else {
      return false;
    };
    member_set.contains(first) && recorded.all(|fingerprint| member_set.contains(fingerprint))
  }
}

/// One recorded member description and its complete location parsing outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreMemberObservation {
  /// Original registry text, including the member label and location spelling.
  pub description: String,
  /// Parsed source location or the failure reached while interpreting this description.
  pub location:    Result<IgnoreMemberLocation, IgnoreMemberLocationError>,
}

/// A source location recovered from one registry member description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreMemberLocation {
  /// Complete recorded path, including whitespace and punctuation.
  pub path:  PathBuf,
  /// First source line recorded for the member.
  pub start: usize,
  /// Last source line recorded for the member.
  pub end:   usize,
}

/// A member description could not supply a usable successor-search location.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IgnoreMemberLocationError {
  /// The description has neither a parenthesized location nor the legacy token-window prefix.
  #[error("expected a parenthesized location or a legacy token-window description")]
  DescriptionFormat,
  /// The location does not separate its path and source span with a colon.
  #[error("the recorded location has no source-line span")]
  MissingSpan,
  /// The source span has no preceding file path.
  #[error("the recorded location has an empty path")]
  EmptyPath,
  /// The source span does not contain both endpoints.
  #[error("the recorded source span has no end-line separator")]
  MissingEnd {
    /// Path recovered before the incomplete span was encountered.
    path: PathBuf,
  },
  /// The first endpoint could not be parsed as a native source-line count.
  #[error("invalid start line: {source}")]
  Start {
    /// Complete path recovered before parsing the start line.
    path:   PathBuf,
    /// Native integer parsing failure.
    source: ParseIntError,
  },
  /// The last endpoint could not be parsed after the first endpoint succeeded.
  #[error("invalid end line after start line {start}: {source}")]
  End {
    /// Complete path recovered before parsing either endpoint.
    path:   PathBuf,
    /// Native start-line count parsed successfully before this failure.
    start:  usize,
    /// Native integer parsing failure.
    source: ParseIntError,
  },
  /// Both endpoints parsed, but their ordering cannot describe a source interval.
  #[error("recorded end line {end} precedes start line {start}")]
  Reversed {
    /// Complete recorded file path.
    path:  PathBuf,
    /// Successfully parsed first endpoint.
    start: usize,
    /// Successfully parsed last endpoint.
    end:   usize,
  },
}

/// Parse the two registry description grammars while preserving the complete path.
#[allow(
  clippy::single_call_fn,
  reason = "Registry description parsing owns both persisted grammars while each observation retains its original input."
)]
fn parse_member_location(description: &str) -> Result<IgnoreMemberLocation, IgnoreMemberLocationError> {
  let location = description
    .strip_suffix(')')
    .map_or_else(
      || description.strip_prefix("token window "),
      |parenthesized| parenthesized.split_once(" (").map(|(_, location)| location),
    )
    .ok_or(IgnoreMemberLocationError::DescriptionFormat)?;
  let (path_text, span) = location.rsplit_once(':').ok_or(IgnoreMemberLocationError::MissingSpan)?;
  if path_text.is_empty() {
    return Err(IgnoreMemberLocationError::EmptyPath);
  }
  let path = PathBuf::from(path_text);
  let (start_text, end_text) = span.split_once('-').ok_or_else(|| IgnoreMemberLocationError::MissingEnd {
    path: path.clone()
  })?;
  let start = start_text.parse().map_err(|source| IgnoreMemberLocationError::Start {
    path: path.clone(),
    source,
  })?;
  let end = end_text.parse().map_err(|source| IgnoreMemberLocationError::End {
    path: path.clone(),
    start,
    source,
  })?;
  if end < start {
    return Err(IgnoreMemberLocationError::Reversed {
      path,
      start,
      end,
    });
  }
  Ok(IgnoreMemberLocation {
    path,
    start,
    end,
  })
}

/// The ignore file structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct IgnoreFile {
  /// The registered `[[ignore]]` entries.
  #[serde(default)]
  pub ignore: Vec<IgnoreEntry>,
}

/// The registry model and the native observation that supplied it.
#[derive(Debug)]
pub struct IgnoreFileLoad {
  /// Exact registry path read by the loader.
  pub path:        PathBuf,
  /// Parsed entries, or the library's empty default for an absent registry.
  pub registry:    IgnoreFile,
  /// File contents or the native absence observation.
  pub observation: IgnoreFileObservation,
}

/// Evidence from loading an optional ignore registry.
#[derive(Debug)]
pub enum IgnoreFileObservation {
  /// The loader read and parsed these complete contents.
  Read {
    /// Original text supplied to the TOML decoder.
    contents: String,
  },
  /// The optional registry was absent, so the loader supplied an empty model.
  Absent {
    /// Native not-found result returned by the filesystem.
    source: io::Error,
  },
}

/// Complete input supplied to one registry write, retained with its native outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreFileWrite {
  /// Exact destination supplied to the filesystem.
  pub path:     PathBuf,
  /// Complete registry model supplied to the encoder.
  pub registry: IgnoreFile,
  /// Complete encoded document supplied to the filesystem.
  pub contents: String,
}

/// The complete result of registering one requested ignore entry in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreEntryRegistration {
  /// A new identity was appended to the registry.
  Added {
    /// Native content identity supplied by the caller.
    fingerprint: Fingerprint,
    /// Complete entry appended to the registry.
    entry:       IgnoreEntry,
  },
  /// The identity already existed, so its original metadata remained authoritative.
  AlreadyRegistered {
    /// Native content identity supplied by the caller.
    fingerprint: Fingerprint,
    /// Complete requested entry, including metadata that was not applied.
    requested:   IgnoreEntry,
    /// Complete existing entry that remained in the registry.
    registered:  IgnoreEntry,
  },
}

/// A registry operation failed with its native cause and available input evidence.
#[derive(Debug, Error)]
pub enum IgnoreFileError {
  /// Reading the registry failed for a reason other than its absence.
  #[error("failed to read ignore registry {}: {source}", path.display())]
  Read {
    /// Registry path that could not be read.
    path:   PathBuf,
    /// Native filesystem error.
    source: io::Error,
  },
  /// The complete file bytes could not be decoded as UTF-8 text.
  #[error("ignore registry {} is not UTF-8: {source}", path.display())]
  Utf8 {
    /// Registry path that supplied the invalid text bytes.
    path:   PathBuf,
    /// Native decoding failure, including the complete input bytes.
    source: FromUtf8Error,
  },
  /// The complete file was read but its TOML could not be decoded.
  #[error("failed to parse ignore registry {}: {source}", path.display())]
  Decode {
    /// Registry path that supplied the invalid document.
    path:     PathBuf,
    /// Complete original document, retained for caller inspection.
    contents: String,
    /// Native TOML decoding error.
    source:   Box<TomlDecodeError>,
  },
  /// Encoding failed before any file write was attempted.
  #[error("failed to encode ignore registry {}: {source}", path.display())]
  Encode {
    /// Intended registry destination.
    path:     PathBuf,
    /// Complete model the encoder could not serialize.
    registry: IgnoreFile,
    /// Native TOML encoding error.
    source:   TomlEncodeError,
  },
  /// Writing failed; the error does not imply that the destination is unchanged.
  #[error("failed to write ignore registry {}: {source}", write.path.display())]
  Write {
    /// Complete destination, model, and document supplied to the failed write.
    write:  IgnoreFileWrite,
    /// Native filesystem error.
    source: io::Error,
  },
}

/// Get the path to the ignore file for a project root.
#[must_use]
pub fn ignore_file_path(root: &Path) -> PathBuf {
  root.join(IGNORE_FILE_NAME)
}

/// Load the ignore file from disk.
///
/// An absent optional registry yields an empty model and retains the native
/// not-found observation. Other read failures and malformed documents fail.
///
/// # Errors
///
/// Returns the native read, UTF-8, or TOML decoding failure, with the path
/// and all contents read before the failure.
pub fn load_ignore_file(root: &Path) -> Result<IgnoreFileLoad, IgnoreFileError> {
  let path = ignore_file_path(root);
  let bytes = match fs::read(&path) {
    Ok(bytes) => bytes,
    Err(source) if source.kind() == io::ErrorKind::NotFound => {
      return Ok(IgnoreFileLoad {
        path,
        registry: IgnoreFile::default(),
        observation: IgnoreFileObservation::Absent {
          source,
        },
      });
    }
    Err(source) => {
      return Err(IgnoreFileError::Read {
        path,
        source,
      });
    }
  };
  let contents = String::from_utf8(bytes).map_err(|source| IgnoreFileError::Utf8 {
    path: path.clone(),
    source,
  })?;
  match toml::from_str(&contents) {
    Ok(registry) => Ok(IgnoreFileLoad {
      path,
      registry,
      observation: IgnoreFileObservation::Read {
        contents,
      },
    }),
    Err(source) => Err(IgnoreFileError::Decode {
      path,
      contents,
      source: Box::new(source),
    }),
  }
}

/// Save the ignore file to disk and return the complete successful write input.
///
/// # Errors
///
/// Returns the native encoding or filesystem failure, retaining the model
/// when encoding fails and the encoded document when writing fails.
pub fn save_ignore_file(root: &Path, ignore_file: &IgnoreFile) -> Result<IgnoreFileWrite, IgnoreFileError> {
  let path = ignore_file_path(root);
  let contents = toml::to_string_pretty(ignore_file).map_err(|source| IgnoreFileError::Encode {
    path: path.clone(),
    registry: ignore_file.clone(),
    source,
  })?;
  let write = IgnoreFileWrite {
    path,
    registry: ignore_file.clone(),
    contents,
  };
  match fs::write(&write.path, &write.contents) {
    Ok(()) => Ok(write),
    Err(source) => Err(IgnoreFileError::Write {
      write,
      source,
    }),
  }
}

/// Register an ignore entry and preserve whether existing metadata prevented its insertion.
pub fn add_ignore(
  ignore_file: &mut IgnoreFile,
  fingerprint: Fingerprint,
  reason: Option<String>,
  members: Vec<String>,
) -> IgnoreEntryRegistration {
  add_ignore_with_member_fingerprints(ignore_file, fingerprint, reason, members, Vec::new())
}

/// Register an entry with member identities, retaining the request and any existing entry.
pub fn add_ignore_with_member_fingerprints(
  ignore_file: &mut IgnoreFile,
  fingerprint: Fingerprint,
  reason: Option<String>,
  members: Vec<String>,
  member_fingerprints: Vec<RecordedFingerprint>,
) -> IgnoreEntryRegistration {
  let requested = IgnoreEntry {
    fingerprint: RecordedFingerprint::from(fingerprint),
    reason,
    members,
    member_fingerprints,
  };
  if let Some(registered) = ignore_file
    .ignore
    .iter()
    .find(|entry| entry.fingerprint.input() == requested.fingerprint.input())
  {
    return IgnoreEntryRegistration::AlreadyRegistered {
      fingerprint,
      requested,
      registered: registered.clone(),
    };
  }
  ignore_file.ignore.push(requested.clone());
  IgnoreEntryRegistration::Added {
    fingerprint,
    entry: requested,
  }
}

/// Remove and return every entry with the requested fingerprint spelling, in registry order.
///
/// Unmatched entries retain their order and complete metadata. An unmatched request
/// returns an empty collection without changing the registry.
#[allow(
  clippy::single_call_fn,
  reason = "Public removal owns exact recorded-identity matching and returns every removed entry without losing its metadata or order."
)]
pub fn remove_ignore(ignore_file: &mut IgnoreFile, fingerprint: &str) -> Vec<IgnoreEntry> {
  ignore_file
    .ignore
    .extract_if(.., |entry| entry.fingerprint.input() == fingerprint)
    .collect()
}

/// Check if a fingerprint is ignored.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Direct fingerprint matching is the registry contract used before membership-drift matching"
)]
pub fn is_ignored(ignore_file: &IgnoreFile, fingerprint: Fingerprint) -> bool {
  let fingerprint_hex = fingerprint.to_hex();
  ignore_file
    .ignore
    .iter()
    .any(|entry| entry.fingerprint.input() == fingerprint_hex)
}

/// Partition groups into visible findings and complete ignored findings.
///
/// A group is ignored when its group fingerprint matches an entry, or when
/// an entry's recorded member fingerprints all still appear in the group
/// (the registered relationship persists despite membership drift).
#[must_use]
pub fn filter_ignored(groups: Vec<DuplicateGroup>, ignore_file: &IgnoreFile, ignored: &mut Vec<DuplicateGroup>) -> Vec<DuplicateGroup> {
  let mut visible = Vec::new();
  for group in groups {
    if group_is_ignored(ignore_file, &group) {
      ignored.push(group);
    } else {
      visible.push(group);
    }
  }
  visible
}

/// Match a group's identity or its retained registered member relationship.
#[allow(
  clippy::single_call_fn,
  reason = "Ignore matching combines exact identity and membership drift at the registry owner before report filtering."
)]
fn group_is_ignored(ignore_file: &IgnoreFile, group: &DuplicateGroup) -> bool {
  if is_ignored(ignore_file, group.fingerprint) {
    return true;
  }
  let member_set: HashSet<Fingerprint> = group.members.iter().map(|member| member.fingerprint).collect();
  ignore_file.ignore.iter().any(|entry| entry.members_all_in(&member_set))
}

/// Return whether an entry still matches the current analysis.
///
/// Live means the entry's group fingerprint is among the live group
/// fingerprints, or its recorded member fingerprints all appear together in
/// one live group's member set.
fn entry_is_live<Hasher: BuildHasher>(
  entry: &IgnoreEntry,
  live_fingerprints: &HashSet<Fingerprint, Hasher>,
  live_member_sets: &[HashSet<Fingerprint, Hasher>],
) -> bool {
  // An unusable group identity can still retain a live recorded member relationship.
  if matches!(entry.fingerprint, RecordedFingerprint::Parsed { fingerprint, .. } if live_fingerprints.contains(&fingerprint)) {
    return true;
  }
  live_member_sets.iter().any(|set| entry.members_all_in(set))
}

/// Find ignore entries that no longer match any live group.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Read-only stale-entry discovery is distinct from the registry mutation performed by cleanup"
)]
pub fn find_stale_entries<'a, Hasher: BuildHasher>(
  ignore_file: &'a IgnoreFile,
  live_fingerprints: &HashSet<Fingerprint, Hasher>,
  live_member_sets: &[HashSet<Fingerprint, Hasher>],
) -> Vec<&'a IgnoreEntry> {
  ignore_file
    .ignore
    .iter()
    .filter(|entry| !entry_is_live(entry, live_fingerprints, live_member_sets))
    .collect()
}

/// Remove and return stale ignore entries.
#[allow(
  clippy::single_call_fn,
  reason = "Registry cleanup owns removal while returning every original stale entry to its caller"
)]
pub fn remove_stale_entries<Hasher: BuildHasher>(
  ignore_file: &mut IgnoreFile,
  live_fingerprints: &HashSet<Fingerprint, Hasher>,
  live_member_sets: &[HashSet<Fingerprint, Hasher>],
) -> Vec<IgnoreEntry> {
  ignore_file
    .ignore
    .extract_if(.., |entry| !entry_is_live(entry, live_fingerprints, live_member_sets))
    .collect()
}

#[cfg(test)]
mod tests {
  use std::collections::HashSet;
  use std::fs;
  use std::io;
  use std::io::ErrorKind;
  use std::num::IntErrorKind;
  use std::path::Path;
  use std::path::PathBuf;

  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;
  use thiserror::Error;

  use super::IgnoreEntry;
  use super::IgnoreEntryRegistration;
  use super::IgnoreFile;
  use super::IgnoreFileError;
  use super::IgnoreFileLoad;
  use super::IgnoreFileObservation;
  use super::IgnoreFileWrite;
  use super::IgnoreMemberLocation;
  use super::IgnoreMemberLocationError;
  use super::IgnoreMemberObservation;
  use super::TomlEncodeError;
  use super::add_ignore;
  use super::add_ignore_with_member_fingerprints;
  use super::filter_ignored;
  use super::find_stale_entries;
  use super::ignore_file_path;
  use super::is_ignored;
  use super::load_ignore_file;
  use super::remove_ignore;
  use super::remove_stale_entries;
  use super::save_ignore_file;
  use crate::code_unit::CodeUnit;
  use crate::code_unit::CodeUnitKind;
  use crate::code_unit::DetectionDimension;
  use crate::duplicate_group;
  use crate::fingerprint::Fingerprint;
  use crate::fingerprint::RecordedFingerprint;
  use crate::grouper::DuplicateGroup;
  use crate::grouper::MatchKind;
  use crate::node::LiteralKind;
  use crate::node::NodeKind;
  use crate::node::NormalizedNode;
  use crate::text_units::window_unit;

  /// Native fixture and behavioral failures from registry tests.
  #[derive(Debug, Error)]
  enum IgnoreTestFailure {
    /// A filesystem fixture operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Loading or saving the registry failed with its typed input evidence.
    #[error(transparent)]
    Registry(#[from] IgnoreFileError),
    /// Constructing an expected encoded document failed with its native cause.
    #[error(transparent)]
    Encode(#[from] TomlEncodeError),
    /// A registry behavior assertion failed.
    #[error(transparent)]
    Assertion(#[from] ConditionFailure),
    /// A rejected load did not preserve the expected native failure evidence.
    #[error("registry load expectation failed: {source}")]
    LoadExpectation {
      /// Complete result observed at the loader boundary.
      outcome: Box<Result<IgnoreFileLoad, IgnoreFileError>>,
      /// Assertion explaining the violated contract.
      source:  ConditionFailure,
    },
    /// Malformed documents lost their original bytes or native decoding outcomes.
    #[error("registry document expectations failed for {path:?}: {source}; inputs: {inputs:?}; outcomes: {outcomes:?}")]
    DocumentLoads {
      /// Exact registry path read for each supplied document.
      path:     PathBuf,
      /// Complete original TOML and invalid UTF-8 byte sequences.
      inputs:   Box<[Vec<u8>; 2]>,
      /// Complete load outcomes in document order.
      outcomes: Vec<Result<IgnoreFileLoad, IgnoreFileError>>,
      /// Native assertion failure.
      source:   ConditionFailure,
    },
    /// A rejected write did not preserve its model and native failure evidence.
    #[error("registry save expectation failed: {source}")]
    SaveExpectation {
      /// Complete result observed at the persistence boundary.
      outcome: Box<Result<IgnoreFileWrite, IgnoreFileError>>,
      /// Assertion explaining the violated contract.
      source:  ConditionFailure,
    },
    /// Persistence and subsequent loading disagree about the complete registry document.
    #[error("registry roundtrip expectation failed: {source}; write: {write:?}; loaded: {loaded:?}")]
    RoundtripExpectation {
      /// Complete successful persistence input.
      write:  Box<IgnoreFileWrite>,
      /// Complete native load used to observe the persisted registry.
      loaded: Box<IgnoreFileLoad>,
      /// Failed behavioral expectation.
      source: ConditionFailure,
    },
    /// Registration changed existing metadata or lost a complete insertion decision.
    #[error("registry registration expectation failed: {source}; registry: {registry:?}; registrations: {registrations:?}")]
    RegistrationExpectation {
      /// Complete registry after the requested registrations.
      registry:      IgnoreFile,
      /// Complete decisions returned by the insertion operations, in order.
      registrations: Vec<IgnoreEntryRegistration>,
      /// Failed behavioral expectation.
      source:        ConditionFailure,
    },
    /// Removal changed unrelated entries or discarded a matching entry's metadata.
    #[error(
      "registry removal expectation failed for {fingerprint}: {source}; original: {original:?}; registry: {registry:?}; removed: \
       {removed:?}; expected removed: {expected_removed:?}; expected retained: {expected_retained:?}"
    )]
    RemovalExpectation {
      /// Original fingerprint spelling supplied to the removal operation.
      fingerprint:       String,
      /// Complete registry before removal.
      original:          Box<IgnoreFile>,
      /// Complete registry after removal.
      registry:          Box<IgnoreFile>,
      /// Every entry returned by the operation, in removal order.
      removed:           Vec<IgnoreEntry>,
      /// Complete expected removed population, in registry order.
      expected_removed:  Vec<IgnoreEntry>,
      /// Complete expected retained population, in registry order.
      expected_retained: Vec<IgnoreEntry>,
      /// Failed behavioral expectation.
      source:            Box<ConditionFailure>,
    },
    /// Member-location parsing lost input descriptions, parsed fields, or native failures.
    #[error("member location expectation failed: {source}; entry: {entry:?}; observations: {observations:?}")]
    MemberLocations {
      /// Complete registry entry submitted to the parser.
      entry:        Box<IgnoreEntry>,
      /// Every successful or failed member interpretation, in registry order.
      observations: Vec<IgnoreMemberObservation>,
      /// Failed behavioral expectation.
      source:       ConditionFailure,
    },
    /// Registry matching lost its original parsing evidence or changed the recorded-member policy.
    #[error(
      "fingerprint matching expectation failed: {source}; registry: {registry:?}; visible: {visible:?}; ignored: {ignored:?}; stale: \
       {stale:?}"
    )]
    FingerprintMatching {
      /// Complete registry load, including native fingerprint parsing outcomes.
      registry: Box<IgnoreFileLoad>,
      /// Complete groups that remained visible.
      visible:  Vec<DuplicateGroup>,
      /// Complete groups hidden by their retained member relationship.
      ignored:  Vec<DuplicateGroup>,
      /// Complete entries whose recorded identities did not match.
      stale:    Vec<IgnoreEntry>,
      /// Failed behavioral expectation.
      source:   Box<ConditionFailure>,
    },
  }

  /// Complete registry, group populations, and independent expectations for ignore filtering.
  #[derive(Debug, Error)]
  #[error(
    "group filtering expectation failed: {source}; registry: {registry:?}; input: {input:?}; visible: {visible:?}; ignored: {ignored:?}; \
     expected visible: {expected_visible:?}; expected ignored: {expected_ignored:?}"
  )]
  struct GroupFilterFailure {
    /// Full registry supplied to the filtering operation.
    registry:         IgnoreFile,
    /// Complete original group population in source order.
    input:            Vec<DuplicateGroup>,
    /// Complete groups returned for presentation.
    visible:          Vec<DuplicateGroup>,
    /// Complete groups retained as ignored evidence.
    ignored:          Vec<DuplicateGroup>,
    /// Independently specified visible groups in order.
    expected_visible: Vec<DuplicateGroup>,
    /// Independently specified ignored groups in order.
    expected_ignored: Vec<DuplicateGroup>,
    /// Native assertion failure.
    source:           ConditionFailure,
  }

  /// Supply a repeatable content identity for registry examples.
  fn test_fingerprint() -> Fingerprint {
    Fingerprint::from_node(&NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)))
  }

  /// Describe an identity-only registry entry independently of the insertion operation.
  fn unannotated_entry(fingerprint: Fingerprint) -> IgnoreEntry {
    IgnoreEntry {
      fingerprint:         RecordedFingerprint::from(fingerprint),
      reason:              None,
      members:             Vec::new(),
      member_fingerprints: Vec::new(),
    }
  }

  /// Check location behavior while retaining every original member description and outcome.
  fn check_member_locations(
    members: Vec<String>,
    check: impl FnOnce(&[IgnoreMemberObservation]) -> Result<(), ConditionFailure>,
  ) -> Result<(), IgnoreTestFailure> {
    let entry = IgnoreEntry {
      members,
      ..unannotated_entry(test_fingerprint())
    };
    let observations = entry.member_locations();
    ensure(
      observations
        .iter()
        .map(|observed| &observed.description)
        .eq(entry.members.iter()),
      "every original member description remains attached to its parsing outcome in registry order",
    )
    .map(drop)
    .and_then(|()| check(&observations))
    .map_err(|source| IgnoreTestFailure::MemberLocations {
      entry: Box::new(entry),
      observations,
      source,
    })
  }

  /// Both persisted grammars retain complete paths, punctuation, and source spans.
  #[test]
  fn member_locations_preserve_registry_paths_and_spans() -> Result<(), IgnoreTestFailure> {
    let scenarios = [
      (
        "closure body (dupes-treesitter/src/normalizer.rs:422-425)",
        "dupes-treesitter/src/normalizer.rs",
        422,
        425,
      ),
      (
        "token window dupes-rust/tests/core_with_syn_tests.rs:325-346",
        "dupes-rust/tests/core_with_syn_tests.rs",
        325,
        346,
      ),
      (
        "line window (src/shared widgets/a (copy), [v2].rs:10-14)",
        "src/shared widgets/a (copy), [v2].rs",
        10,
        14,
      ),
      (
        "token window src/shared widgets/a (copy), [v2].rs:10-14",
        "src/shared widgets/a (copy), [v2].rs",
        10,
        14,
      ),
      (r"method (C:\work area\source.rs:7-9)", r"C:\work area\source.rs", 7, 9),
    ];
    let members = scenarios.iter().map(|&(description, ..)| description.to_owned()).collect();
    let expected = scenarios
      .into_iter()
      .map(|(description, path, start, end)| IgnoreMemberObservation {
        description: description.to_owned(),
        location:    Ok(IgnoreMemberLocation {
          path: PathBuf::from(path),
          start,
          end,
        }),
      })
      .collect::<Vec<_>>();
    check_member_locations(members, |observations| {
      ensure(
        observations == expected,
        "both registry grammars preserve the full path and independently specified line interval",
      )
      .map(drop)
    })
  }

  /// Malformed and reversed locations retain their last successfully interpreted fields.
  #[test]
  fn member_locations_retain_structural_failures() -> Result<(), IgnoreTestFailure> {
    let scenarios = [
      ("member without a location", IgnoreMemberLocationError::DescriptionFormat),
      ("member (src/file.rs)", IgnoreMemberLocationError::MissingSpan),
      ("member (:1-2)", IgnoreMemberLocationError::EmptyPath),
      ("member (src/file.rs:1)", IgnoreMemberLocationError::MissingEnd {
        path: PathBuf::from("src/file.rs"),
      }),
      ("member (src/file.rs:9-7)", IgnoreMemberLocationError::Reversed {
        path:  PathBuf::from("src/file.rs"),
        start: 9,
        end:   7,
      }),
    ];
    let members = scenarios.iter().map(|&(description, _)| description.to_owned()).collect();
    let expected = scenarios
      .into_iter()
      .map(|(description, failure)| IgnoreMemberObservation {
        description: description.to_owned(),
        location:    Err(failure),
      })
      .collect::<Vec<_>>();
    check_member_locations(members, |observations| {
      ensure(
        observations == expected,
        "unusable member syntax retains each typed failure and any path or endpoints already parsed",
      )
      .map(drop)
    })
  }

  /// Endpoint failures retain the native cause, full path, and any successfully parsed start.
  #[test]
  fn member_locations_retain_native_endpoint_failures() -> Result<(), IgnoreTestFailure> {
    let overflow = format!("{}0", usize::MAX);
    for (text, kind) in [
      ("", IntErrorKind::Empty),
      ("ten", IntErrorKind::InvalidDigit),
      (overflow.as_str(), IntErrorKind::PosOverflow),
    ] {
      let members = vec![
        format!("member (src/shared widgets/file.rs:{text}-20)"),
        format!("member (src/shared widgets/file.rs:7-{text})"),
      ];
      check_member_locations(members, |observations| {
        ensure(
          matches!(observations, &[
            IgnoreMemberObservation {
              location: Err(IgnoreMemberLocationError::Start { path: ref first_path, source: ref first_error }), ..
            },
            IgnoreMemberObservation {
              location: Err(IgnoreMemberLocationError::End { path: ref last_path, start: 7, source: ref last_error }), ..
            },
          ] if first_path == Path::new("src/shared widgets/file.rs")
            && last_path == first_path && *first_error.kind() == kind && *last_error.kind() == kind),
          "each endpoint retains its native failure and full path, and an end failure retains the parsed start",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// An absent optional registry supplies an empty model with its native not-found observation.
  #[test]
  fn load_nonexistent_returns_default() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let loaded = load_ignore_file(workspace.path())?;
    ensure(
      loaded.registry == IgnoreFile::default()
        && loaded.path == ignore_file_path(workspace.path())
        && matches!(loaded.observation, IgnoreFileObservation::Absent { ref source } if source.kind() == ErrorKind::NotFound),
      "an absent optional registry retains its native observation and supplies the empty model",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::LoadExpectation {
      outcome: Box::new(Ok(loaded)),
      source,
    })
  }

  /// Persistence and loading preserve the complete registry, source path, and encoded document.
  #[test]
  fn roundtrip_save_and_load() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let fingerprint = test_fingerprint();
    let registry = IgnoreFile {
      ignore: vec![IgnoreEntry {
        reason: Some("test reason".to_owned()),
        members: vec!["first".to_owned(), "second".to_owned()],
        ..unannotated_entry(fingerprint)
      }],
    };
    let write = save_ignore_file(workspace.path(), &registry)?;
    let expected_path = ignore_file_path(workspace.path());
    let expected_contents = fs::read_to_string(&expected_path)?;
    let loaded = load_ignore_file(workspace.path())?;
    ensure(
      write.registry == registry
        && write.path == expected_path
        && write.contents == expected_contents
        && loaded.registry == registry
        && loaded.path == expected_path
        && matches!(loaded.observation, IgnoreFileObservation::Read { ref contents } if *contents == expected_contents),
      "registry roundtrip preserves every entry together with the exact read path and document",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::RoundtripExpectation {
      write: Box::new(write),
      loaded: Box::new(loaded),
      source,
    })
  }

  /// Malformed TOML and invalid UTF-8 retain their original documents and distinct native failures.
  #[test]
  fn malformed_registry_documents_retain_native_decoding_evidence() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let path = ignore_file_path(workspace.path());
    let inputs = [b"[[ignore]\nfingerprint = \"unfinished\"\n".to_vec(), vec![
      0xFF_u8, 0xFE_u8, b'a',
    ]];
    let mut outcomes = Vec::new();
    for bytes in &inputs {
      fs::write(&path, bytes)?;
      outcomes.push(load_ignore_file(workspace.path()));
    }
    let [ref toml_bytes, ref utf8_bytes] = inputs;
    ensure(
      matches!(outcomes.as_slice(), [
        Err(IgnoreFileError::Decode { path: toml_path, contents, .. }),
        Err(IgnoreFileError::Utf8 { path: utf8_path, source }),
      ] if toml_path == &path && utf8_path == &path
        && contents.as_bytes() == toml_bytes && source.as_bytes() == utf8_bytes
        && source.utf8_error().valid_up_to() == 0 && source.utf8_error().error_len() == Some(1)),
      "each rejected document retains its exact bytes, registry path, and the native decoder failure for that input",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::DocumentLoads {
      path,
      inputs: Box::new(inputs),
      outcomes,
      source,
    })
  }

  /// An occupied non-file path returns a read failure instead of an empty registry.
  #[test]
  fn unreadable_registry_is_not_treated_as_absent() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let path = ignore_file_path(workspace.path());
    fs::create_dir_all(&path)?;
    let outcome = load_ignore_file(workspace.path());
    ensure(
      matches!(outcome, Err(IgnoreFileError::Read { path: ref observed_path, ref source })
        if *observed_path == path && source.kind() != ErrorKind::NotFound),
      "a directory occupying the registry path returns its native read failure",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::LoadExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Failed persistence retains the intended model, encoded document, path, and native cause.
  #[test]
  fn failed_registry_write_retains_model_and_encoded_document() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let path = ignore_file_path(workspace.path());
    fs::create_dir_all(&path)?;
    let registry = IgnoreFile {
      ignore: vec![entry_with_member_fingerprints(&["alpha", "bravo"])],
    };
    let expected_contents = toml::to_string_pretty(&registry)?;
    let outcome = save_ignore_file(workspace.path(), &registry);
    ensure(
      matches!(outcome, Err(IgnoreFileError::Write { ref write, ref source })
        if write.path == path && write.registry == registry && write.contents == expected_contents && source.kind() != ErrorKind::NotFound),
      "write failure preserves the full model, encoded document, destination, and native I/O cause",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::SaveExpectation {
      outcome: Box::new(outcome),
      source,
    })
  }

  /// Repeated registration preserves the original entry without appending a duplicate.
  #[test]
  fn add_ignore_deduplicates() -> Result<(), IgnoreTestFailure> {
    let fingerprint = test_fingerprint();
    let mut registry = IgnoreFile::default();
    let registered = IgnoreEntry {
      reason: Some("original reason".to_owned()),
      members: vec!["original member".to_owned()],
      ..unannotated_entry(fingerprint)
    };
    let requested = IgnoreEntry {
      reason: Some("replacement reason".to_owned()),
      members: vec!["replacement member".to_owned()],
      member_fingerprints: vec![RecordedFingerprint::from(Fingerprint::from_bytes(b"replacement content"))],
      ..unannotated_entry(fingerprint)
    };
    let added = add_ignore(&mut registry, fingerprint, registered.reason.clone(), registered.members.clone());
    let repeated = add_ignore_with_member_fingerprints(
      &mut registry,
      fingerprint,
      requested.reason.clone(),
      requested.members.clone(),
      requested.member_fingerprints.clone(),
    );
    let registrations = vec![added, repeated];
    ensure(
      registry.ignore == vec![registered.clone()]
        && registrations
          == vec![
            IgnoreEntryRegistration::Added {
              fingerprint,
              entry: registered.clone(),
            },
            IgnoreEntryRegistration::AlreadyRegistered {
              fingerprint,
              requested,
              registered,
            },
          ],
      "repeated registration preserves the original entry and returns all unapplied requested metadata",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::RegistrationExpectation {
      registry,
      registrations,
      source,
    })
  }

  /// Removal preserves all matching metadata and the order of retained and removed entries.
  #[test]
  fn remove_ignore_preserves_complete_entries() -> Result<(), IgnoreTestFailure> {
    let fingerprint = test_fingerprint();
    let first = IgnoreEntry {
      reason: Some("first occurrence".to_owned()),
      members: vec!["first (src/first.rs:1-3)".to_owned()],
      member_fingerprints: vec![RecordedFingerprint::parse("invalid member".to_owned())],
      ..unannotated_entry(fingerprint)
    };
    let second = IgnoreEntry {
      reason: Some("later occurrence".to_owned()),
      ..first.clone()
    };
    let kept = IgnoreEntry {
      fingerprint: RecordedFingerprint::from(Fingerprint::from_bytes(b"unrelated group")),
      ..entry_with_member_fingerprints(&["kept content"])
    };
    for (entries, requested, expected_removed, expected_retained) in [
      (vec![first.clone()], fingerprint.to_hex(), vec![first.clone()], Vec::new()),
      (vec![first.clone()], "unregistered".to_owned(), Vec::new(), vec![first.clone()]),
      (
        vec![first.clone(), kept.clone(), second.clone()],
        fingerprint.to_hex(),
        vec![first, second],
        vec![kept],
      ),
    ] {
      let original = IgnoreFile {
        ignore: entries
      };
      let mut registry = original.clone();
      let removed = remove_ignore(&mut registry, &requested);
      ensure(
        removed == expected_removed && registry.ignore == expected_retained,
        "removal returns all matching entries in order and preserves every unmatched entry",
      )
      .map(drop)
      .map_err(|source| IgnoreTestFailure::RemovalExpectation {
        fingerprint: requested,
        original: Box::new(original),
        registry: Box::new(registry),
        removed,
        expected_removed,
        expected_retained,
        source: Box::new(source),
      })?;
    }
    Ok(())
  }

  /// A fingerprint becomes ignored only after its identity has been registered.
  #[test]
  fn is_ignored_works() -> Result<(), IgnoreTestFailure> {
    let fingerprint = test_fingerprint();
    let mut registry = IgnoreFile::default();
    ensure(!is_ignored(&registry, fingerprint), "an unregistered fingerprint remains visible").map(drop)?;
    let registration = add_ignore(&mut registry, fingerprint, None, Vec::new());
    ensure(
      registration
        == IgnoreEntryRegistration::Added {
          fingerprint,
          entry: unannotated_entry(fingerprint),
        }
        && is_ignored(&registry, fingerprint),
      "a successful insertion retains its complete entry and makes its identity ignored",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::RegistrationExpectation {
      registry,
      registrations: vec![registration],
      source,
    })
  }

  /// Exact and near filtering retain every registered or visible group without changing their order
  /// or contents.
  #[test]
  fn fingerprint_filtering_preserves_complete_group_populations() -> Result<(), Box<GroupFilterFailure>> {
    let fingerprint = test_fingerprint();
    let registry = IgnoreFile {
      ignore: vec![unannotated_entry(fingerprint)],
    };
    for (match_kind, similarity) in [(MatchKind::Exact, 1.0), (MatchKind::Near, 0.85)] {
      let matching = duplicate_group(DetectionDimension::Ast, match_kind, fingerprint, similarity, vec![
        member_unit("alpha"),
        member_unit("bravo"),
      ]);
      let unmatched = DuplicateGroup {
        fingerprint: Fingerprint::from_bytes(b"unregistered group"),
        ..matching.clone()
      };
      for (input, expected_visible, expected_ignored) in [
        (vec![matching.clone()], Vec::new(), vec![matching.clone()]),
        (vec![unmatched.clone()], vec![unmatched.clone()], Vec::new()),
        (vec![matching.clone(), unmatched.clone(), matching.clone()], vec![unmatched], vec![
          matching.clone(),
          matching,
        ]),
      ] {
        let mut ignored = Vec::new();
        let visible = filter_ignored(input.clone(), &registry, &mut ignored);
        ensure(
          visible == expected_visible && ignored == expected_ignored,
          "registry filtering preserves complete matching and unmatched groups, including members, similarity, and population order",
        )
        .map(drop)
        .map_err(|source| GroupFilterFailure {
          registry: registry.clone(),
          input,
          visible,
          ignored,
          expected_visible,
          expected_ignored,
          source,
        })
        .map_err(Box::new)?;
      }
    }
    Ok(())
  }

  /// Stale-entry discovery returns only entries whose identity is no longer live.
  #[test]
  fn find_stale_entries_identifies_stale_vs_live() -> Result<(), ConditionFailure> {
    let live_fingerprint = test_fingerprint();
    let stale_fingerprint = Fingerprint::from_node(&NormalizedNode::with_children(NodeKind::Block, Vec::new()));
    let stale_entry = IgnoreEntry {
      fingerprint:         RecordedFingerprint::from(stale_fingerprint),
      reason:              Some("stale".to_owned()),
      members:             Vec::new(),
      member_fingerprints: Vec::new(),
    };
    let mut registry = IgnoreFile {
      ignore: vec![IgnoreEntry {
        reason: Some("live".to_owned()),
        ..unannotated_entry(live_fingerprint)
      }],
    };
    registry.ignore.push(stale_entry.clone());
    let stale = find_stale_entries(&registry, &HashSet::from([live_fingerprint]), &[]);
    ensure(stale == vec![&stale_entry], "stale detection returns only the full unmatched entry").map(drop)
  }

  /// Cleanup returns complete stale entries while preserving all live registrations.
  #[test]
  fn remove_stale_entries_removes_only_stale() -> Result<(), ConditionFailure> {
    let live_fingerprint = test_fingerprint();
    let stale_fingerprint = Fingerprint::from_node(&NormalizedNode::with_children(NodeKind::Block, Vec::new()));
    let mut registry = IgnoreFile {
      ignore: vec![IgnoreEntry {
        reason: Some("live".to_owned()),
        ..unannotated_entry(live_fingerprint)
      }],
    };
    let expected_live = registry.clone();
    let stale_entry = IgnoreEntry {
      fingerprint:         RecordedFingerprint::from(stale_fingerprint),
      reason:              Some("stale".to_owned()),
      members:             Vec::new(),
      member_fingerprints: Vec::new(),
    };
    registry.ignore.push(stale_entry.clone());
    let removed = remove_stale_entries(&mut registry, &HashSet::from([live_fingerprint]), &[]);
    ensure(removed == vec![stale_entry], "cleanup returns the complete removed entries").map(drop)?;
    ensure(registry == expected_live, "cleanup retains the complete live entries").map(drop)
  }

  /// Registry lookup uses the declared filename beneath the supplied project root.
  #[test]
  fn ignore_file_path_is_correct() -> Result<(), ConditionFailure> {
    let path = ignore_file_path(Path::new("/project"));
    ensure(
      path == Path::new("/project/.dupes-ignore.toml"),
      "the registry is rooted at the project directory",
    )
    .map(drop)
  }

  /// Construct a line window whose content identity comes from the supplied seed.
  fn member_unit(seed: &str) -> CodeUnit {
    window_unit(Path::new("member.rs"), "member", CodeUnitKind::LineWindow, 1, 2, &[seed.to_owned()])
  }

  /// Record a near-group relationship independently of its later group identity.
  fn entry_with_member_fingerprints(seeds: &[&str]) -> IgnoreEntry {
    IgnoreEntry {
      member_fingerprints: seeds
        .iter()
        .map(|seed| RecordedFingerprint::from(member_unit(seed).fingerprint))
        .collect(),
      ..unannotated_entry(test_fingerprint())
    }
  }

  /// Recorded member identities keep a near-group relationship live when new members join.
  #[test]
  fn member_subset_matching_survives_membership_drift() -> Result<(), ConditionFailure> {
    // The group gained a member, so its composite fingerprint no longer
    // matches the entry; the recorded members still appear together, so
    // the entry keeps suppressing the group and stays live.
    let entry = entry_with_member_fingerprints(&["alpha", "bravo"]);
    let registry = IgnoreFile {
      ignore: vec![entry]
    };
    let drifted_group = duplicate_group(
      DetectionDimension::Ast,
      MatchKind::Near,
      Fingerprint::from_bytes(b"drifted composite"),
      0.92,
      vec![member_unit("alpha"), member_unit("bravo"), member_unit("charlie")],
    );
    let member_set: HashSet<Fingerprint> = drifted_group.members.iter().map(|member| member.fingerprint).collect();

    let mut ignored = Vec::new();
    ensure(
      filter_ignored(vec![drifted_group.clone()], &registry, &mut ignored).is_empty(),
      "registered members remain ignored after membership growth",
    )
    .map(drop)?;
    ensure(
      ignored == vec![drifted_group],
      "membership matching preserves the whole expanded group",
    )
    .map(drop)?;
    ensure(
      find_stale_entries(&registry, &HashSet::new(), &[member_set]).is_empty(),
      "the retained member relationship keeps its registry entry live",
    )
    .map(drop)
  }

  /// Editing recorded member content restores the finding and makes its prior registration stale.
  #[test]
  fn member_subset_matching_resurfaces_edited_members() -> Result<(), ConditionFailure> {
    // One recorded member's content changed, so the registered
    // relationship must come back for review: the group is reported and
    // the entry is stale.
    let entry = entry_with_member_fingerprints(&["alpha", "bravo"]);
    let registry = IgnoreFile {
      ignore: vec![entry.clone()],
    };
    let edited_group = duplicate_group(
      DetectionDimension::Ast,
      MatchKind::Near,
      Fingerprint::from_bytes(b"edited composite"),
      0.91,
      vec![member_unit("alpha"), member_unit("bravo edited")],
    );
    let member_set: HashSet<Fingerprint> = edited_group.members.iter().map(|member| member.fingerprint).collect();

    let mut ignored = Vec::new();
    ensure(
      filter_ignored(vec![edited_group.clone()], &registry, &mut ignored) == vec![edited_group],
      "edited registered content resurfaces as a complete group",
    )
    .map(drop)?;
    ensure(
      ignored.is_empty(),
      "an edited recorded member is no longer hidden by the prior relationship",
    )
    .map(drop)?;
    ensure(
      find_stale_entries(&registry, &HashSet::new(), &[member_set]) == vec![&entry],
      "editing a recorded member makes the complete prior entry stale",
    )
    .map(drop)
  }

  /// Malformed identities retain their causes while usable recorded members keep their existing
  /// matching role.
  #[test]
  fn malformed_fingerprints_retain_native_failures_through_registry_matching() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let member = member_unit("retained content");
    let member_set = HashSet::from([member.fingerprint]);
    let group = duplicate_group(
      DetectionDimension::Ast,
      MatchKind::Near,
      Fingerprint::from_bytes(b"new composite"),
      0.9,
      vec![member.clone()],
    );
    let document = format!(
      "[[ignore]]\nfingerprint = \"not_hex\"\nmember_fingerprints = [\"{}\", \"10000000000000000\"]\n\n[[ignore]]\nfingerprint = \
       \"also_invalid\"\nmember_fingerprints = [\"invalid_member\"]\n",
      member.fingerprint,
    );
    fs::write(ignore_file_path(workspace.path()), &document)?;
    let registry = load_ignore_file(workspace.path())?;
    let mut ignored = Vec::new();
    let visible = filter_ignored(vec![group.clone()], &registry.registry, &mut ignored);
    let stale = find_stale_entries(&registry.registry, &HashSet::new(), &[member_set])
      .into_iter()
      .cloned()
      .collect::<Vec<_>>();
    let recorded = registry.registry.ignore.as_slice();
    ensure(
      matches!(recorded, [IgnoreEntry { fingerprint: RecordedFingerprint::Invalid(group_error), member_fingerprints, .. }, last]
        if group_error.input == "not_hex" && *group_error.source.kind() == IntErrorKind::InvalidDigit
          && matches!(member_fingerprints.as_slice(), [RecordedFingerprint::Parsed { input, fingerprint }, RecordedFingerprint::Invalid(member_error)]
            if *input == member.fingerprint.to_hex() && *fingerprint == member.fingerprint
              && member_error.input == "10000000000000000" && *member_error.source.kind() == IntErrorKind::PosOverflow)
          && matches!(last.member_fingerprints.as_slice(), [RecordedFingerprint::Invalid(source)]
            if source.input == "invalid_member" && *source.source.kind() == IntErrorKind::InvalidDigit)
          && stale == vec![last.clone()])
        && visible.is_empty() && ignored == vec![group]
        && matches!(registry.observation, IgnoreFileObservation::Read { ref contents } if *contents == document),
      "matching retains each native parse failure, permits the existing nonempty usable-member fallback, and rejects an all-invalid member set",
    ).map(drop).map_err(|source| IgnoreTestFailure::FingerprintMatching { registry: Box::new(registry), visible, ignored, stale, source: Box::new(source) })
  }

  /// Registry persistence preserves recorded member content identities and their metadata.
  #[test]
  fn member_fingerprints_roundtrip_through_the_ignore_file() -> Result<(), IgnoreTestFailure> {
    let workspace = TempDir::new()?;
    let fingerprint = test_fingerprint();
    let registry = IgnoreFile {
      ignore: vec![IgnoreEntry {
        reason: Some("near family".to_owned()),
        members: vec!["first".to_owned(), "second".to_owned()],
        member_fingerprints: vec![
          RecordedFingerprint::parse("aaaa".to_owned()),
          RecordedFingerprint::parse("bbbb".to_owned()),
          RecordedFingerprint::parse("+00AA".to_owned()),
          RecordedFingerprint::parse("not_hex".to_owned()),
          RecordedFingerprint::parse("10000000000000000".to_owned()),
        ],
        ..unannotated_entry(fingerprint)
      }],
    };
    let write = save_ignore_file(workspace.path(), &registry)?;
    let loaded = load_ignore_file(workspace.path())?;
    ensure(
      write.registry == registry
        && loaded.registry == registry
        && loaded.path == write.path
        && matches!(loaded.observation, IgnoreFileObservation::Read { ref contents } if *contents == write.contents),
      "registry roundtrip preserves original spellings, successful identities, native parsing failures, and metadata",
    )
    .map(drop)
    .map_err(|source| IgnoreTestFailure::RoundtripExpectation {
      write: Box::new(write),
      loaded: Box::new(loaded),
      source,
    })
  }
}
