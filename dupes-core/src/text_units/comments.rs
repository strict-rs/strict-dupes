//! Source-context classification of comments and quoted continuations, independent of token
//! identity.

use std::collections::BTreeSet;
use std::iter::Peekable;
use std::str::Chars;

use super::QuoteProfile;
use super::char_literal_tail;
use super::consume_quoted;

/// Source lines whose lexical context changes declaration or comment classification.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct SourceLines {
  /// Complete `//` comment lines outside quoted literals.
  pub(super) comments:             BTreeSet<usize>,
  /// Lines reached after a newline inside a quoted literal, including its closing line.
  pub(super) quoted_continuations: BTreeSet<usize>,
}

/// Find complete `//` comment lines and quoted continuations without changing token identities.
///
/// This view never changes tokenization or window boundaries. Block comments
/// are traversed only to distinguish their contents from subsequent code.
#[allow(
  clippy::single_call_fn,
  reason = "The source-context view separates comment classification from fingerprint-preserving tokenization."
)]
pub(super) fn classify(source: &str, profile: QuoteProfile) -> SourceLines {
  let mut lines = SourceLines::default();
  let mut chars = source.chars().peekable();
  let mut line = 1_usize;
  let mut whitespace_only = true;
  while let Some(glyph) = chars.next() {
    match glyph {
      '\n' => {
        line = line.saturating_add(1);
        whitespace_only = true;
      }
      space if space.is_whitespace() => {}
      '/' if chars.next_if_eq(&'/').is_some() => {
        if whitespace_only {
          lines.comments.extend([line]);
        }
        while chars.next_if(|&next| next != '\n').is_some() {}
      }
      '/' if chars.next_if_eq(&'*').is_some() => {
        skip_block_comment(&mut chars, &mut line, &mut whitespace_only);
      }
      'r' if profile.rust_ticks => {
        if let Some(hashes) = raw_quote_opener(&mut chars) {
          let first_continuation = line.saturating_add(1);
          skip_raw_quote(&mut chars, hashes, &mut line);
          lines.quoted_continuations.extend(first_continuation..=line);
        }
        whitespace_only = false;
      }
      '"' | '`' | '\'' if glyph != '\'' || !profile.rust_ticks || char_literal_tail(chars.clone()).is_some() => {
        let first_continuation = line.saturating_add(1);
        let quoted = consume_quoted(glyph, &mut chars);
        line = line.saturating_add(quoted.chars().filter(|&ch| ch == '\n').count());
        lines.quoted_continuations.extend(first_continuation..=line);
        whitespace_only = false;
      }
      _ => whitespace_only = false,
    }
  }
  lines
}

/// Traverse balanced block comments without interpreting their quotes or line markers.
#[allow(
  clippy::single_call_fn,
  reason = "Nested block-comment traversal has a separate delimiter and line-state contract."
)]
fn skip_block_comment(chars: &mut Peekable<Chars<'_>>, line: &mut usize, whitespace_only: &mut bool) {
  let mut depth = 1_usize;
  while let Some(glyph) = chars.next() {
    match glyph {
      '\n' => {
        *line = line.saturating_add(1);
        *whitespace_only = true;
      }
      '/' if chars.next_if_eq(&'*').is_some() => depth = depth.saturating_add(1),
      '*' if chars.next_if_eq(&'/').is_some() => {
        depth = depth.saturating_sub(1);
        if depth == 0 {
          break;
        }
      }
      _ => {}
    }
  }
}

/// Consume a Rust raw-string opener only when its complete delimiter is present.
#[allow(
  clippy::single_call_fn,
  reason = "Tentative raw-delimiter recognition must leave non-literal source unconsumed."
)]
fn raw_quote_opener(chars: &mut Peekable<Chars<'_>>) -> Option<usize> {
  let mut tail = chars.clone();
  let mut hashes = 0_usize;
  while tail.next_if_eq(&'#').is_some() {
    hashes = hashes.saturating_add(1);
  }
  if tail.next() != Some('"') {
    return None;
  }
  *chars = tail;
  Some(hashes)
}

/// Traverse a raw literal until the matching quote and hash delimiter, retaining its line span.
#[allow(
  clippy::single_call_fn,
  reason = "Raw-string traversal preserves comment-shaped contents until the exact closing delimiter."
)]
fn skip_raw_quote(chars: &mut Peekable<Chars<'_>>, hashes: usize, line: &mut usize) {
  while let Some(glyph) = chars.next() {
    match glyph {
      '\n' => *line = line.saturating_add(1),
      '"' => {
        let mut tail = chars.clone();
        if (0..hashes).all(|_| tail.next_if_eq(&'#').is_some()) {
          *chars = tail;
          break;
        }
      }
      _ => {}
    }
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;

  use strict_test_support::PredicateFailure;
  use strict_test_support::ensure_that;

  use super::QuoteProfile;
  use super::SourceLines;
  use super::classify;

  /// Complete source, quote profile, and expected and observed comment-line populations.
  type CommentObservation = (&'static str, QuoteProfile, BTreeSet<usize>, SourceLines);

  /// Observe lexical context and preserve every scenario's native input and output.
  #[test]
  fn comment_lines_respect_quotes_blocks_and_executable_prefixes() -> Result<(), PredicateFailure<Vec<CommentObservation>>> {
    let rust = QuoteProfile {
      rust_ticks: true
    };
    let cases = [
      (
        "// Copyright: example\n// See: https://example.test/license\n// for all callers\n",
        rust,
        vec![1, 2, 3],
      ),
      ("\n  // comment\nlet value = 2; // code first\n// trailing comment\n", rust, vec![
        2, 4,
      ]),
      ("// An unmatched \" or /* is prose\nlet value = 2;\n// still a comment", rust, vec![
        1, 3,
      ]),
      ("let text = \"first\n// quoted contents\nlast\";\n// outside", rust, vec![4]),
      (
        "let text = r##\"first \"\n// raw contents: \"#\n// still raw contents\n\"##;\n// outside",
        rust,
        vec![5],
      ),
      ("let text = br\"first\n// byte literal\n\";\n// outside", rust, vec![4]),
      ("let text = cr#\"first\n// C literal\n\"#;\n// outside", rust, vec![4]),
      ("let text = r#\"unterminated\n// raw contents", rust, vec![]),
      ("let text = \"escaped \\\"\n// quoted contents\n\";\n// outside", rust, vec![4]),
      ("/* outer\n/* nested */\n// inside block\n*/\n// outside", rust, vec![5]),
      ("/* unterminated\n// inside block", rust, vec![]),
      ("fn borrow<'a>(text: &'a str) {\n// lifetime is not a quote\n}", rust, vec![2]),
      ("let quote = '\"';\nlet tick = '\\'';\n// outside characters", rust, vec![3]),
      (
        "let ratio = alpha / beta;\nlet reference = r#ident;\n// after operators",
        rust,
        vec![3],
      ),
      (
        "text = 'first\n// string contents\nlast'\n// outside",
        QuoteProfile::default(),
        vec![4],
      ),
      (
        "text = `first\n// template contents\nlast`\n// outside",
        QuoteProfile::default(),
        vec![4],
      ),
    ];
    let observed = cases
      .into_iter()
      .map(|(source, profile, expected)| (source, profile, expected.into_iter().collect(), classify(source, profile)))
      .collect();
    ensure_that(
      observed,
      "only complete line comments outside literals and block comments are classified",
      |outcomes: &Vec<CommentObservation>| outcomes.iter().all(|outcome| outcome.2 == outcome.3.comments),
    )
    .map(drop)
  }
}
