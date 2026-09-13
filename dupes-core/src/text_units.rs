//! Generic token and line duplicate detection.
//!
//! Tokenization uses per-language quote profiles and anchored raw and normalized
//! token windows. Structural line windows support stanza coalescing; both grains
//! retain their suppression and admission tags.

use std::iter::Peekable;
use std::path::Path;
use std::str::Chars;

use crate::code_unit::CodeUnit;
use crate::code_unit::CodeUnitKind;
use crate::code_unit::DetectionDimension;
use crate::config::Config;
use crate::fingerprint::Fingerprint;
use crate::node::NodeKind;
use crate::node::NormalizedNode;
use crate::split_runs_by;
use crate::suppression::RuleId;
use crate::suppression::SuppressionPolicy;

/// Generic token and line units extracted from a text-like file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextUnits {
  /// Identifier/literal-normalized token windows.
  pub normalized_tokens: Vec<CodeUnit>,
  /// Raw token windows.
  pub raw_tokens:        Vec<CodeUnit>,
  /// Normalized line windows.
  pub lines:             Vec<CodeUnit>,
}

/// Extract generic token and line units from a source file.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "This public boundary composes all text dimensions for the analysis pipeline."
)]
pub fn extract(path: &Path, source: &str, config: &Config) -> TextUnits {
  let tokens = tokenize(source, QuoteProfile::for_path(path));
  let normalized_tokens = token_windows_if_enabled(config, path, &tokens, TokenMode::Normalized);
  let raw_tokens = token_windows_if_enabled(config, path, &tokens, TokenMode::Raw);
  let lines = if config.dimension_enabled(DetectionDimension::Line) {
    line_windows(path, source, config.line_min_lines, &config.suppression)
  } else {
    Vec::new()
  };
  TextUnits {
    normalized_tokens,
    raw_tokens,
    lines,
  }
}

/// Token representation with source line information.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
  /// Whitespace-insensitive source token.
  raw:        String,
  /// Identifier/literal-normalized token.
  normalized: String,
  /// One-based source line.
  line:       usize,
  /// One-based line of the token's last character (differs from `line`
  /// only for multi-line string tokens).
  end_line:   usize,
}

impl Token {
  /// True when `next` begins on the same or the immediately following
  /// source line, so no token-free line separates the two tokens.
  #[allow(
    clippy::single_call_fn,
    reason = "The named adjacency rule preserves blank-line boundaries when token spans cross lines."
  )]
  const fn adjoins(&self, next: &Self) -> bool {
    next.line <= self.end_line.saturating_add(1)
  }
}

/// Token window extraction mode.
#[derive(Debug, Clone, Copy)]
enum TokenMode {
  /// Use normalized tokens.
  Normalized,
  /// Use raw tokens.
  Raw,
}

/// Quote lexing profile, selected by file extension.
///
/// The default pairs `"`, `'`, and `` ` `` naively.
///
/// Rust sources lex `'` as
/// a quoted token only for char-literal shapes that close on the same line
/// (`'X'`, `'\n'`, `'\u{10FFFF}'`); any other tick — lifetimes, loop labels,
/// prose apostrophes in comments — is punctuation. Without this, one
/// unpaired apostrophe opens a phantom multi-line "string" that runs to the
/// next apostrophe anywhere in the file, bridging blank lines and silently
/// swallowing whole spans out of token segmentation.
#[derive(Debug, Clone, Copy, Default)]
struct QuoteProfile {
  /// Lex `'` per Rust char-literal rules instead of naive pairing.
  rust_ticks: bool,
}

impl QuoteProfile {
  /// Select Rust tick handling for the source format declared by the path.
  #[allow(
    clippy::single_call_fn,
    reason = "Source-format selection belongs to the quote profile independently of token consumption."
  )]
  fn for_path(path: &Path) -> Self {
    Self {
      rust_ticks: path.extension().is_some_and(|ext| ext == "rs"),
    }
  }
}

/// Length in chars of a char-literal tail following an opening `'`
/// (the body plus closing quote), or `None` when the tick does not open a
/// char literal. Literals close on the same line within a small bound:
/// `'X'`, `'\n'`, `'\''`, `'\u{10FFFF}'`.
#[allow(
  clippy::single_call_fn,
  reason = "The bounded Rust character-literal recognizer prevents lifetime ticks from consuming later source."
)]
fn char_literal_tail(mut tail: impl Iterator<Item = char>) -> Option<usize> {
  /// Maximum escape-body length including its closing quote.
  const MAX_TAIL: usize = 11;
  let first = tail.next()?;
  if first == '\\' {
    let escaped = tail.next()?;
    if escaped == '\n' {
      return None;
    }
    tail
      .take(MAX_TAIL.saturating_sub(2))
      .take_while(|&glyph| glyph != '\n')
      .position(|glyph| glyph == '\'')
      .map(|offset| offset.saturating_add(3))
  } else if first != '\'' && first != '\n' && tail.next() == Some('\'') {
    Some(2)
  } else {
    None
  }
}

/// Convert source into coarse language-agnostic tokens.
#[allow(
  clippy::single_call_fn,
  reason = "The lexer owns character consumption and source spans independently of window extraction."
)]
fn tokenize(source: &str, profile: QuoteProfile) -> Vec<Token> {
  let mut tokens = Vec::new();
  let mut chars = source.chars().peekable();
  let mut line = 1_usize;

  while let Some(ch) = chars.next() {
    if ch == '\n' {
      line = line.saturating_add(1);
      continue;
    }
    if ch.is_whitespace() {
      continue;
    }

    if ch == '_' || ch.is_ascii_alphabetic() {
      let mut raw = String::from(ch);
      consume_peeked_while(&mut chars, &mut raw, is_ident_continue);
      let normalized = if is_keyword(&raw) {
        raw.clone()
      } else {
        "IDENT".to_owned()
      };
      tokens.push(Token {
        raw,
        normalized,
        line,
        end_line: line,
      });
      continue;
    }

    if ch.is_ascii_digit() {
      let mut raw = String::from(ch);
      consume_peeked_while(&mut chars, &mut raw, |next| {
        next.is_ascii_alphanumeric() || matches!(next, '_' | '.')
      });
      tokens.push(Token {
        raw,
        normalized: "NUMBER".to_owned(),
        line,
        end_line: line,
      });
      continue;
    }

    let naive_quote = match ch {
      '"' | '`' => true,
      '\'' => !profile.rust_ticks,
      _ => false,
    };
    if naive_quote {
      let start_line = line;
      let raw = consume_quoted(ch, &mut chars);
      line = line.saturating_add(raw.chars().filter(|&glyph| glyph == '\n').count());
      tokens.push(Token {
        raw,
        normalized: "STRING".to_owned(),
        line: start_line,
        end_line: line,
      });
      continue;
    }

    // Rust tick: char literals pair like strings; any other tick
    // (lifetime, loop label, prose apostrophe in a comment) falls
    // through to the punctuation arm below.
    if ch == '\''
      && let Some(tail_len) = char_literal_tail(chars.clone())
    {
      let mut raw = String::from(ch);
      raw.extend(chars.by_ref().take(tail_len));
      tokens.push(Token {
        raw,
        normalized: "STRING".to_owned(),
        line,
        end_line: line,
      });
      continue;
    }

    let raw = String::from(ch);
    tokens.push(Token {
      raw: raw.clone(),
      normalized: raw,
      line,
      end_line: line,
    });
  }

  tokens
}

/// Append peeked characters to `raw` while `keep` accepts them.
fn consume_peeked_while(chars: &mut Peekable<Chars<'_>>, raw: &mut String, mut keep: impl FnMut(char) -> bool) {
  while let Some(next) = chars.next_if(|&glyph| keep(glyph)) {
    raw.push(next);
  }
}

/// Consume a quoted span after its opener, preserving escapes and all source text.
fn consume_quoted(quote: char, chars: &mut impl Iterator<Item = char>) -> String {
  let mut raw = String::from(quote);
  while let Some(glyph) = chars.next() {
    raw.push(glyph);
    match glyph {
      '\\' => raw.extend(chars.next()),
      closing if closing == quote => break,
      _ => {}
    }
  }
  raw
}

/// Return true if `ch` can continue an identifier-like token.
const fn is_ident_continue(ch: char) -> bool {
  ch == '_' || ch == '-' || ch.is_ascii_alphanumeric()
}

/// Keep common language keywords structurally meaningful in normalized tokens.
#[allow(
  clippy::single_call_fn,
  reason = "The keyword classifier names the normalization policy without embedding its vocabulary in the lexer loop."
)]
fn is_keyword(token: &str) -> bool {
  matches!(
    token,
    "as"
      | "async"
      | "await"
      | "break"
      | "class"
      | "const"
      | "continue"
      | "def"
      | "else"
      | "enum"
      | "false"
      | "fn"
      | "for"
      | "from"
      | "if"
      | "impl"
      | "import"
      | "in"
      | "let"
      | "loop"
      | "match"
      | "mod"
      | "mut"
      | "pub"
      | "return"
      | "self"
      | "static"
      | "struct"
      | "trait"
      | "true"
      | "type"
      | "use"
      | "where"
      | "while"
      | "yield"
  )
}

/// Build token windows for one mode, or nothing when its dimension is off.
fn token_windows_if_enabled(config: &Config, path: &Path, tokens: &[Token], mode: TokenMode) -> Vec<CodeUnit> {
  let dimension = match mode {
    TokenMode::Normalized => DetectionDimension::TokenNormalized,
    TokenMode::Raw => DetectionDimension::TokenRaw,
  };
  if config.dimension_enabled(dimension) {
    token_windows(
      path, tokens, config.token_min_tokens, config.token_min_lines, mode, &config.suppression,
    )
  } else {
    Vec::new()
  }
}

/// Build token windows.
///
/// One window is anchored at the start of each segment (a contiguous run of
/// token-bearing source lines; blank lines separate segments unless bridged
/// by a multi-line string token). Anchoring to concept starts keeps token
/// matching stable when unrelated code earlier in the file shifts, and makes
/// each window represent a complete test case, function, or data stanza
/// rather than an arbitrary mid-concept boilerplate slice.
#[allow(
  clippy::single_call_fn,
  reason = "Token-window construction shares stable anchoring across the raw and normalized dimensions."
)]
fn token_windows(
  path: &Path,
  tokens: &[Token],
  min_tokens: usize,
  min_lines: usize,
  mode: TokenMode,
  policy: &SuppressionPolicy,
) -> Vec<CodeUnit> {
  if min_tokens == 0 || tokens.len() < min_tokens {
    return Vec::new();
  }
  let mut units = Vec::new();
  for segment in token_segments(tokens) {
    let Some(slice) = anchored_window(segment, min_tokens, min_lines) else {
      continue;
    };
    let line_start = slice.first().map_or(1, |token| token.line);
    let line_end = slice.last().map_or(1, |token| token.end_line);
    let suppressed = classify_token_window(segment, slice, mode, policy);
    let values: Vec<String> = slice
      .iter()
      .map(|token| match mode {
        TokenMode::Normalized => token.normalized.clone(),
        TokenMode::Raw => token.raw.clone(),
      })
      .collect();
    let mut unit = window_unit(
      path,
      match mode {
        TokenMode::Normalized => "normalized token window",
        TokenMode::Raw => "raw token window",
      },
      CodeUnitKind::TokenWindow,
      line_start,
      line_end,
      &values,
    );
    unit.suppressed = suppressed;
    units.push(unit);
  }
  units
}

/// The shortest segment prefix satisfying both token and line minimums.
///
/// The prefix is a deterministic function of the segment content alone, so
/// identical duplicated segments always produce identical windows.
#[allow(
  clippy::single_call_fn,
  reason = "The shortest qualifying prefix is the content-identity invariant for token windows."
)]
fn anchored_window(segment: &[Token], min_tokens: usize, min_lines: usize) -> Option<&[Token]> {
  let line_start = segment.first()?.line;
  let (end, _) = segment
    .iter()
    .enumerate()
    .skip(min_tokens.checked_sub(1)?)
    .find(|&(_, token)| token.end_line.saturating_sub(line_start).saturating_add(1) >= min_lines)?;
  segment.get(..=end)
}

/// Split a token stream into segments separated by token-free source lines.
#[allow(
  clippy::single_call_fn,
  reason = "Token segmentation names the concept boundary before window selection applies its minimums."
)]
fn token_segments(tokens: &[Token]) -> Vec<&[Token]> {
  split_runs_by(tokens, Token::adjoins)
}

/// Build normalized line windows.
///
/// Windows slide within contiguous content-line segments only; a blank line
/// (or a line emptied by block-comment stripping) is a concept boundary that
/// no window may cross. Windows are also rejected when they end on a
/// block-opening line or start on a closing-delimiter line, so signature or
/// skeleton fragments cut mid-concept never become standalone units.
#[allow(
  clippy::single_call_fn,
  reason = "The line dimension owns comment normalization, stanza coalescing, and aligned sliding windows."
)]
fn line_windows(path: &Path, source: &str, min_lines: usize, policy: &SuppressionPolicy) -> Vec<CodeUnit> {
  if min_lines == 0 {
    return Vec::new();
  }
  let mut in_block_comment = false;
  let normalized: Vec<(usize, String)> = source
    .lines()
    .enumerate()
    .filter_map(|(index, line)| {
      let without_block_comments = strip_block_comments(line, &mut in_block_comment);
      let trimmed = without_block_comments.split_whitespace().collect::<Vec<_>>().join(" ");
      if trimmed.is_empty() {
        None
      } else {
        Some((index.saturating_add(1), trimmed))
      }
    })
    .collect();
  if normalized.len() < min_lines {
    return Vec::new();
  }
  let mut units = Vec::new();
  for segment in coalesce_stanza_segments(line_segments(&normalized)) {
    let mut remaining = segment.as_slice();
    while let Some((_, tail)) = remaining.split_first() {
      let Some((slice, continuation)) = remaining.split_at_checked(min_lines) else {
        break;
      };
      remaining = tail;
      if !line_window_is_aligned(slice) {
        continue;
      }
      let suppressed = classify_line_window(slice, continuation.iter(), policy);
      let values: Vec<String> = slice.iter().map(|entry| entry.1.clone()).collect();
      let mut unit = window_unit(
        path,
        "line window",
        CodeUnitKind::LineWindow,
        slice.first().map_or(1, |&(line, _)| line),
        slice.last().map_or(1, |&(line, _)| line),
        &values,
      );
      unit.suppressed = suppressed;
      units.push(unit);
    }
  }
  units
}

/// Split normalized lines into segments of consecutive source lines.
#[allow(
  clippy::single_call_fn,
  reason = "Source-line segmentation defines blank-line boundaries separately from the declaration-stanza exception."
)]
fn line_segments(normalized: &[(usize, String)]) -> Vec<&[(usize, String)]> {
  split_runs_by(normalized, |previous, current| current.0 <= previous.0.saturating_add(1))
}

/// Merge adjacent blank-separated segments when both sides are uniform
/// declaration stanzas, so clap-style option blocks and blank-spread field
/// tables can form windows. A blank line stays a hard concept boundary
/// everywhere else.
#[allow(
  clippy::single_call_fn,
  reason = "Coalescing is a distinct operation that retains complete declaration rows and original source positions."
)]
fn coalesce_stanza_segments(segments: Vec<&[(usize, String)]>) -> Vec<Vec<(usize, String)>> {
  let mut merged: Vec<Vec<(usize, String)>> = Vec::new();
  for segment in segments {
    if let Some(last) = merged.last_mut()
      && segments_form_one_stanza_block(last, segment)
    {
      last.extend(segment.iter().cloned());
    } else {
      merged.push(segment.to_vec());
    }
  }
  merged
}

/// One blank line apart, both sides uniform stanzas inside an unfinished declaration.
#[allow(
  clippy::single_call_fn,
  reason = "This guard defines the exact gap and structural conditions that permit crossing a blank line."
)]
fn segments_form_one_stanza_block(previous: &[(usize, String)], next: &[(usize, String)]) -> bool {
  let Some(&(previous_end, ref previous_line)) = previous.last() else {
    return false;
  };
  let Some(&(next_start, _)) = next.first() else {
    return false;
  };
  previous_line.trim() != "}"
    && previous_end.checked_add(2) == Some(next_start)
    && segment_is_declaration_stanza(previous)
    && segment_is_declaration_stanza(next)
}

/// The structural anatomy of a declaration block: a comment/attribute
/// prelude, at most one type-header row, uniform stanza rows, and at most
/// one trailing lone `}`. Prelude-only segments (comment banners, bare
/// attributes) and lone braces never qualify.
fn segment_is_declaration_stanza(slice: &[(usize, String)]) -> bool {
  let mut rows = slice;
  while let Some((first, rest)) = rows.split_first()
    && (line_is_comment(&first.1) || line_is_attribute(&first.1))
  {
    rows = rest;
  }
  let has_header = rows.first().is_some_and(|entry| line_is_type_header(&entry.1));
  if let Some((_, rest)) = rows.split_first()
    && has_header
  {
    rows = rest;
  }
  if let Some((last, rest)) = rows.split_last()
    && last.1.trim() == "}"
  {
    rows = rest;
  }
  rows.iter().all(|entry| line_is_stanza_shaped(&entry.1)) && (has_header || rows.iter().any(|entry| line_is_structured_data(&entry.1)))
}

/// A type declaration's opening row (`pub struct Cli {`-style).
#[allow(
  clippy::single_call_fn,
  reason = "Recognizing a type header is a distinct step in the declaration-block anatomy."
)]
fn line_is_type_header(line: &str) -> bool {
  let trimmed = line.trim_start();
  starts_with_any(trimmed, &[
    "struct ", "pub struct ", "pub(crate) struct ", "enum ", "pub enum ", "union ",
  ]) && trimmed.trim_end().ends_with('{')
}

/// Reject windows that are the opening rows of a `fn` *declaration*.
///
/// Rust forces implementors to restate trait method signatures verbatim, so
/// a declaration's parameter rows always duplicate every implementation's
/// rows without describing duplicated behavior. The signature's terminator
/// decides which side of that pairing a window is on: looking ahead in the
/// segment, `;` marks the declaration (rejected) while a `{` body marks an
/// implementation (kept, so deliberate signature parity across implementors
/// stays visible).
#[allow(
  clippy::single_call_fn,
  reason = "Signature lookahead distinguishes a trait declaration from an implementation without consuming window contents."
)]
fn line_window_is_declaration_signature_prefix<'a>(
  slice: &[(usize, String)],
  mut continuation: impl Iterator<Item = &'a (usize, String)>,
) -> bool {
  let starts_like_fn = slice.first().is_some_and(|entry| {
    let trimmed = entry.1.trim_start();
    trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") || trimmed.starts_with("pub(crate) fn ")
  });
  if !starts_like_fn {
    return false;
  }
  if slice
    .iter()
    .any(|entry| entry.1.contains('{') || entry.1.trim_end().ends_with(';'))
  {
    // The signature is terminated inside the window: a complete shape.
    return false;
  }
  continuation
    .find_map(|entry| {
      if entry.1.contains('{') {
        Some(false)
      } else if entry.1.trim_end().ends_with(';') {
        Some(true)
      } else {
        None
      }
    })
    .unwrap_or(false)
}

/// Reject windows whose edges are misaligned with concept boundaries.
#[allow(
  clippy::single_call_fn,
  reason = "The alignment guard prevents standalone windows from cutting into adjacent block bodies."
)]
fn line_window_is_aligned(slice: &[(usize, String)]) -> bool {
  let Some(first) = slice.first() else {
    return false;
  };
  let Some(last) = slice.last() else {
    return false;
  };
  !line_is_closing_only(&first.1) && !last.1.trim_end().ends_with(['{', '(', '[', ':'])
}

/// Return true for lines made only of closing delimiters and punctuation.
#[allow(
  clippy::single_call_fn,
  reason = "Closing-only lines are an explicit invalid window start, distinct from general delimiter-only lines."
)]
fn line_is_closing_only(line: &str) -> bool {
  !line.is_empty()
    && line
      .chars()
      .all(|ch| ch.is_whitespace() || matches!(ch, ')' | ']' | '}' | ';' | ','))
}

/// Strip `/* ... */` block-comment spans from one line, tracking open-comment
/// state across lines.
///
/// Comment markers are honored only outside quoted literals and line comments:
/// a quote span that closes on the same line is content, and `//` or `#`
/// turns the rest of the line into prose. Without this, a quoted `"/*"` (such
/// as the one in this function's own source) would open a phantom block
/// comment and blind line windowing to everything before the next stray `*/`.
#[allow(
  clippy::single_call_fn,
  reason = "Comment stripping owns cross-line comment state while preserving quoted and prose markers."
)]
fn strip_block_comments(line: &str, in_block_comment: &mut bool) -> String {
  let mut output = String::new();
  let mut chars = line.chars().peekable();

  while let Some(ch) = chars.next() {
    if *in_block_comment {
      if ch == '*' && chars.next_if_eq(&'/').is_some() {
        *in_block_comment = false;
      }
      continue;
    }
    match ch {
      '"' | '\'' if quote_span_closes_on_line(chars.clone(), ch) => {
        output.push_str(&consume_quoted(ch, &mut chars));
      }
      '/' if chars.next_if_eq(&'*').is_some() => {
        *in_block_comment = true;
      }
      '/' | '#' if ch == '#' || chars.peek() == Some(&'/') => {
        output.push(ch);
        output.extend(chars);
        break;
      }
      _ => output.push(ch),
    }
  }
  output
}

/// Whether the quote span preceding `chars` closes on this line
/// (backslash escapes skipped). Unclosed openers — lifetimes, labels, prose
/// apostrophes, multi-line string heads — stay ordinary punctuation.
#[allow(
  clippy::single_call_fn,
  reason = "Quote lookahead protects literal markers without consuming an unclosed quote as a string."
)]
fn quote_span_closes_on_line(mut chars: impl Iterator<Item = char>, quote: char) -> bool {
  while let Some(ch) = chars.next() {
    match ch {
      '\\' if chars.next().is_none() => return false,
      '\\' => {}
      closing if closing == quote => return true,
      _ => {}
    }
  }
  false
}

/// Apply structural token rules before the fallback content score.
///
/// The first matching shape owns attribution. Disabling that shape's rule
/// leaves its candidate visible instead of applying a later suppression.
#[allow(
  clippy::single_call_fn,
  reason = "Rule ordering and attribution belong to the token classifier rather than window construction."
)]
fn classify_token_window(segment: &[Token], slice: &[Token], mode: TokenMode, policy: &SuppressionPolicy) -> Option<RuleId> {
  if token_window_is_import_or_module_scaffold(slice) {
    return policy.allow(RuleId::TokenImportScaffold);
  }
  if token_window_is_chain_tail(slice) {
    return policy.allow(RuleId::TokenChainTail);
  }
  if token_window_is_declaration_scaffold(slice) {
    return policy.allow(RuleId::TokenDeclarationScaffold);
  }
  if token_window_is_signature_prefix(slice) {
    return policy.allow(RuleId::TokenSignaturePrefix);
  }
  if token_window_cuts_match_table_prefix(segment, slice.len()) {
    return policy.allow(RuleId::TokenMatchTablePrefix);
  }
  if token_window_scores_low_signal(slice, mode) {
    return policy.allow(RuleId::TokenLowSignal);
  }
  None
}

/// The meaningful/unique/behavior scoring fall-through of window eligibility.
#[allow(
  clippy::single_call_fn,
  reason = "The fallback score is a named suppression rule applied only after the structural rules."
)]
fn token_window_scores_low_signal(slice: &[Token], mode: TokenMode) -> bool {
  let meaningful = slice
    .iter()
    .filter(|token| is_meaningful_token(token_value(token, mode)))
    .count();
  if meaningful < 5 || meaningful < slice.len().div_ceil(3) {
    return true;
  }

  let structured_data = token_window_has_structured_data(slice);
  let unique_values = unique_count(
    slice
      .iter()
      .map(|token| token_value(token, mode))
      .filter(|token| is_meaningful_token(token)),
  );
  if unique_values < 3 && !structured_data {
    return true;
  }

  let has_behavior = slice.iter().any(token_has_behavior);
  match mode {
    TokenMode::Normalized => !(has_behavior || structured_data),
    TokenMode::Raw => !(has_behavior || structured_data || unique_values >= 5),
  }
}

/// Borrow the token spelling selected for the detection dimension.
fn token_value(token: &Token, mode: TokenMode) -> &str {
  match mode {
    TokenMode::Normalized => &token.normalized,
    TokenMode::Raw => &token.raw,
  }
}

/// Recognize import or module declarations without executable content.
#[allow(
  clippy::single_call_fn,
  reason = "Import scaffolding is an independently attributed token suppression shape."
)]
fn token_window_is_import_or_module_scaffold(slice: &[Token]) -> bool {
  let has_import_or_module_line = window_token_lines(slice)
    .iter()
    .any(|line| line_starts_with(line, |token| matches!(token, "use" | "import" | "from" | "mod" | "pub" | "extern")));
  has_import_or_module_line && !slice.iter().any(token_has_behavior)
}

/// Recognize detached chain fragments occupying at least half the token lines.
#[allow(
  clippy::single_call_fn,
  reason = "The chain-tail predicate names its suppression boundary and protects behavior-bearing windows."
)]
fn token_window_is_chain_tail(slice: &[Token]) -> bool {
  let lines = window_token_lines(slice);
  let chain_tail_lines = lines
    .iter()
    .filter(|line| line_starts_with(line, |token| matches!(token, "." | ")" | "]")))
    .count();
  lines.len() >= 2 && chain_tail_lines >= lines.len().div_ceil(2) && !slice.iter().any(token_has_behavior)
}

/// True when the line's first raw token satisfies `starts`.
fn line_starts_with(line: &[Token], starts: impl Fn(&str) -> bool) -> bool {
  line.first().is_some_and(|token| starts(&token.raw))
}

/// Reject windows that stop part-way through a `match` arm table.
///
/// A minimum-satisfying prefix that cuts a long arm table pairs tables by
/// their shared opening rows even when the remaining arms differ; the table
/// is one concept and a prefix of it is not a reportable unit.
#[allow(
  clippy::single_call_fn,
  reason = "Match-table lookahead protects complete tables while identifying truncated table prefixes."
)]
fn token_window_cuts_match_table_prefix(segment: &[Token], window_len: usize) -> bool {
  let Some((window, continuation)) = segment.split_at_checked(window_len) else {
    return false;
  };
  // Only `match` keyword tables of single-line `pattern => value,` rows:
  // arrow rows in macro invocations are complete data stanzas, and arms
  // that open blocks (`=> {`) are bodies rather than table rows.
  window.iter().any(|token| token.raw == "match")
    && window_token_lines(window).iter().any(|line| line_is_match_table_row(line))
    && window_token_lines(continuation)
      .iter()
      .any(|line| line_is_match_table_row(line))
}

/// A one-line `pattern => value,` match-table row.
fn line_is_match_table_row(line: &[Token]) -> bool {
  line.last().is_some_and(|token| token.raw == ",")
    && line
      .iter()
      .zip(line.iter().skip(1))
      .any(|(left, right)| left.raw == "=" && right.raw == ">" && left.line == right.line)
}

/// Reject windows that are mostly doc comments and an unfinished signature.
///
/// A documented multi-line `fn` signature tokenizes almost identically for
/// unrelated functions; a window must include real body content to stand for
/// a duplicate.
#[allow(
  clippy::single_call_fn,
  reason = "Documented signature prefixes have a dedicated rule with body-content counterexamples."
)]
fn token_window_is_signature_prefix(slice: &[Token]) -> bool {
  // Only documented declarations: the window must begin at a doc comment
  // or attribute line. Windows that begin at code (imports, impl headers,
  // undocumented signatures) describe real adjacent content.
  if !slice.first().is_some_and(|token| token.raw == "/" || token.raw == "#") {
    return false;
  }
  if !slice.iter().any(|token| token.raw == "fn") {
    return false;
  }
  // Only multi-line doc/parameter scaffolding counts; functions that open
  // their body on the signature line keep their windows.
  slice
    .split(|token| token.raw == "{")
    .next()
    .is_some_and(|scaffold| scaffold.len() >= slice.len().div_ceil(2) && window_token_lines(scaffold).len() >= 3)
}

/// Reject windows that are only a type declaration's field scaffolding.
///
/// Visibility-qualified field rows remain declaration scaffolding. Line
/// comments contribute to token identities but do not describe executable
/// behavior or establish a type header for this classification.
#[allow(
  clippy::single_call_fn,
  reason = "Declaration classification must use its comment-free view without changing the token identities."
)]
fn token_window_is_declaration_scaffold(slice: &[Token]) -> bool {
  let code_lines: Vec<Vec<&Token>> = window_token_lines(slice)
    .into_iter()
    .map(|line| {
      let comment_start = line
        .iter()
        .zip(line.iter().skip(1))
        .position(|(first, second)| first.raw == "/" && second.raw == "/");
      line.iter().take(comment_start.unwrap_or(line.len())).collect()
    })
    .collect();
  let has_type_header = code_lines
    .iter()
    .flatten()
    .any(|token| matches!(token.raw.as_str(), "struct" | "enum" | "trait" | "union"));
  if !has_type_header {
    return false;
  }
  let field_lines = code_lines.iter().filter(|line| line_is_field_like(line)).count();
  field_lines >= 2 && !code_lines.iter().flatten().any(|token| token_is_runtime_behavior(token))
}

/// `name: Type,` declaration rows, optionally prefixed by Rust visibility.
#[allow(
  clippy::single_call_fn,
  reason = "Field-row recognition owns visibility parsing independently of the surrounding declaration classifier."
)]
fn line_is_field_like(line: &[&Token]) -> bool {
  let mut tokens = line.iter().copied().peekable();
  if tokens.next_if(|token| token.raw == "pub").is_some()
    && tokens.next_if(|token| token.raw == "(").is_some()
    && !tokens.any(|token| token.raw == ")")
  {
    return false;
  }
  tokens.next().is_some_and(|token| token.normalized == "IDENT")
    && tokens.next().is_some_and(|token| token.raw == ":")
    && tokens.last().is_some_and(|token| token.raw == ",")
}

/// Tokens that indicate executable behavior rather than declaration shape.
#[allow(
  clippy::single_call_fn,
  reason = "The declaration rule uses a narrower runtime vocabulary than the general token scorer."
)]
fn token_is_runtime_behavior(token: &Token) -> bool {
  matches!(
    token.raw.as_str(),
    "fn" | "return" | "if" | "match" | "for" | "while" | "loop" | "let" | "=" | "+" | "*" | "%"
  )
}

/// Recognize a keyword or operator that contributes executable behavior.
fn token_has_behavior(token: &Token) -> bool {
  BEHAVIOR_KEYWORDS.contains(&token.raw.as_str()) || BEHAVIOR_OPERATORS.contains(&token.raw.as_str())
}

/// Recognize repeated key-and-value rows in a token window.
#[allow(
  clippy::single_call_fn,
  reason = "Repeated structured rows provide content signal independently of executable tokens."
)]
fn token_window_has_structured_data(slice: &[Token]) -> bool {
  window_token_lines(slice)
    .iter()
    .filter(|line| line_has_structured_tokens(line))
    .count()
    >= 2
}

/// Group a token window into per-source-line token runs.
fn window_token_lines(slice: &[Token]) -> Vec<&[Token]> {
  split_runs_by(slice, |previous, current| previous.line == current.line)
}

/// Recognize a colon with meaningful content on both sides of the same line.
#[allow(
  clippy::single_call_fn,
  reason = "A complete structured row requires content on both sides of its separator."
)]
fn line_has_structured_tokens(tokens: &[Token]) -> bool {
  let mut tail = tokens.iter().skip_while(|token| !is_meaningful_token(&token.normalized));
  tail.next().is_some() && tail.any(|token| token.raw == ":") && tail.any(|token| is_meaningful_token(&token.normalized))
}

/// Distinguish content tokens from delimiters that carry no content alone.
fn is_meaningful_token(token: &str) -> bool {
  !STRUCTURAL_TOKENS.contains(&token)
}

/// Tokens that are pure delimiters or punctuation with no content of their own.
const STRUCTURAL_TOKENS: &[&str] = &["{", "}", "(", ")", "[", "]", ",", ";", ":", ".", "#", "@", "\\"];

/// Operator tokens whose presence indicates computation rather than data.
const BEHAVIOR_OPERATORS: &[&str] = &["=", "+", "-", "*", "/", "%", "<", ">", "!", "&", "|", "^", "?"];

/// Keywords that mark a token or line as behavior rather than data; shared by
/// the token-window scorer and both line classifiers.
const BEHAVIOR_KEYWORDS: &[&str] = &[
  "async", "await", "break", "class", "const", "continue", "def", "else", "enum", "fn", "for", "if", "impl", "let", "loop", "match",
  "return", "static", "struct", "trait", "type", "where", "while", "yield",
];

/// Count distinct spellings while borrowing the original terms.
fn unique_count<'a>(values: impl Iterator<Item = &'a str>) -> usize {
  let mut seen = Vec::new();
  for term in values {
    if !seen.contains(&term) {
      seen.push(term);
    }
  }
  seen.len()
}

/// Admit complete line stanzas and builder runs before considering suppression.
///
/// Other windows use their earliest matching line rule. Its disabled state
/// makes the window visible; enabled rules return their attribution tag.
#[allow(
  clippy::single_call_fn,
  reason = "Admission precedence and suppression attribution belong to the line classifier."
)]
fn classify_line_window<'a>(
  slice: &[(usize, String)],
  continuation: impl Iterator<Item = &'a (usize, String)>,
  policy: &SuppressionPolicy,
) -> Option<RuleId> {
  // Admission rules first: a named carve-out turns an otherwise-rejected
  // window shape into a fully visible candidate; disabling the rule lets
  // the window fall through to its base suppression.
  if policy.is_enabled(RuleId::LineDeclarationStanza) && line_window_is_declaration_stanza(slice) {
    return None;
  }
  if policy.is_enabled(RuleId::LineBuilderChainRun) && line_window_is_builder_chain_run(slice) {
    return None;
  }
  if line_window_is_import_or_module_scaffold(slice) {
    return policy.allow(RuleId::LineImportScaffold);
  }
  if line_window_is_chain_tail(slice) {
    return policy.allow(RuleId::LineChainTail);
  }
  if line_window_is_declaration_signature_prefix(slice, continuation) {
    return policy.allow(RuleId::LineDeclarationSignaturePrefix);
  }
  if line_window_scores_low_signal(slice) {
    return policy.allow(RuleId::LineLowSignal);
  }
  None
}

/// A window made entirely of doc/attr/field declaration stanza lines with
/// real field content: cross-file copy-paste of clap-style option blocks and
/// derive field tables is duplication signal even though no line carries
/// behavior.
#[allow(
  clippy::single_call_fn,
  reason = "Declaration-stanza admission is a named exception with its own structural and content requirements."
)]
fn line_window_is_declaration_stanza(slice: &[(usize, String)]) -> bool {
  let structured_lines = slice.iter().filter(|entry| line_is_structured_data(&entry.1)).count();
  structured_lines >= 2 && unique_terms_in_lines(slice) >= 4 && slice.iter().all(|entry| line_is_stanza_shaped(&entry.1))
}

/// Declaration-stanza line shapes: doc comments, attributes, and field rows.
/// Block punctuation (a lone `{` or `}`) is never a stanza row.
///
/// Documentation and attributes describe the declaration even when their text
/// contains behavior keywords. Remaining field rows are checked by word rather
/// than `line_has_behavior`, which would confuse declaration syntax with computation.
fn line_is_stanza_shaped(line: &str) -> bool {
  if line_is_comment(line) || line_is_attribute(line) {
    return true;
  }
  if line_is_import_or_module_scaffold(line) {
    return false;
  }
  if matches!(line.trim(), "{" | "}") {
    return false;
  }
  if contains_word(line, BEHAVIOR_KEYWORDS) {
    return false;
  }
  line_is_structured_data(line)
}

/// A window made entirely of complete single-line builder steps
/// (`.ident(args)` with balanced parens); detached fragments mixing other
/// lines keep their chain-tail suppression.
#[allow(
  clippy::single_call_fn,
  reason = "Complete builder-step runs have a dedicated admission rule distinct from detached chain tails."
)]
fn line_window_is_builder_chain_run(slice: &[(usize, String)]) -> bool {
  !slice.is_empty() && slice.iter().all(|entry| line_is_builder_step(&entry.1))
}

/// A complete `.ident(...)` builder step on one line, optionally `,` or `;`
/// terminated.
#[allow(
  clippy::single_call_fn,
  reason = "Balanced arguments and the permitted terminator define a complete builder step."
)]
fn line_is_builder_step(line: &str) -> bool {
  let trimmed = line.trim();
  let Some(rest) = trimmed.strip_prefix('.') else {
    return false;
  };
  let after_ident = rest.trim_start_matches(is_ident_continue);
  if after_ident.len() == rest.len() {
    return false;
  }
  let Some(arguments) = after_ident.strip_prefix('(') else {
    return false;
  };
  let mut depth = 1_usize;
  let mut chars = arguments.chars();
  while let Some(ch) = chars.next() {
    match ch {
      '(' => depth = depth.saturating_add(1),
      ')' => {
        depth = depth.saturating_sub(1);
        if depth == 0 {
          return matches!(chars.as_str(), "" | "," | ";");
        }
      }
      _ => {}
    }
  }
  false
}

/// The meaningful/behavior/unique-terms scoring fall-through of eligibility.
#[allow(
  clippy::single_call_fn,
  reason = "The line fallback score stays separate from structural admission and suppression precedence."
)]
fn line_window_scores_low_signal(slice: &[(usize, String)]) -> bool {
  let meaningful_lines = slice.iter().filter(|entry| is_meaningful_line(&entry.1)).count();
  if meaningful_lines < 2 {
    return true;
  }

  let behavior_lines = slice.iter().filter(|entry| line_has_behavior(&entry.1)).count();
  let prose_lines = slice.iter().filter(|entry| line_is_prose(&entry.1)).count();
  let structured_lines = slice.iter().filter(|entry| line_is_structured_data(&entry.1)).count();

  !((behavior_lines > 0 || prose_lines >= 2 || structured_lines >= 2) && unique_terms_in_lines(slice) >= 4)
}

/// Recognize windows containing only imports, modules, and low-information lines.
#[allow(
  clippy::single_call_fn,
  reason = "Import-window suppression has a distinct whole-window shape and rule attribution."
)]
fn line_window_is_import_or_module_scaffold(slice: &[(usize, String)]) -> bool {
  let import_or_module_lines = slice.iter().filter(|entry| line_is_import_or_module_scaffold(&entry.1)).count();
  import_or_module_lines > 0
    && slice
      .iter()
      .all(|entry| line_is_import_or_module_scaffold(&entry.1) || line_is_low_info(&entry.1))
}

/// Recognize detached chain tails without executable behavior in the window.
#[allow(
  clippy::single_call_fn,
  reason = "The line chain-tail rule must preserve windows containing executable behavior."
)]
fn line_window_is_chain_tail(slice: &[(usize, String)]) -> bool {
  let chain_tail_lines = slice.iter().filter(|entry| line_is_chain_tail(&entry.1)).count();
  chain_tail_lines >= 2 && chain_tail_lines >= slice.len().div_ceil(2) && !slice.iter().any(|entry| line_has_behavior(&entry.1))
}

/// Recognize a line contributing behavior, prose, or structured data.
#[allow(
  clippy::single_call_fn,
  reason = "Meaningful-line classification applies the low-information exclusions before content scoring."
)]
fn is_meaningful_line(line: &str) -> bool {
  !line_is_low_info(line) && (line_has_behavior(line) || line_is_prose(line) || line_is_structured_data(line))
}

/// Classify scaffolding and detached fragments before scoring line content.
fn line_is_low_info(line: &str) -> bool {
  line_is_comment(line)
    || line_is_attribute(line)
    || line_is_delimiter_only(line)
    || line_is_import_or_module_scaffold(line)
    || line_is_chain_tail(line)
}

/// Recognize the supported line-comment and block-comment prefixes.
fn line_is_comment(line: &str) -> bool {
  let trimmed = line.trim_start();
  trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("# ")
}

/// Recognize Rust attributes and decorator-style lines.
fn line_is_attribute(line: &str) -> bool {
  let trimmed = line.trim_start();
  trimmed.starts_with("#[") || trimmed.starts_with("#!") || trimmed.starts_with('@')
}

/// Recognize lines containing only whitespace and structural punctuation.
#[allow(
  clippy::single_call_fn,
  reason = "Delimiter-only content is an explicit low-information category in line scoring."
)]
fn line_is_delimiter_only(line: &str) -> bool {
  line
    .chars()
    .all(|ch| ch.is_whitespace() || matches!(ch, '{' | '}' | '[' | ']' | '(' | ')' | ';' | ','))
}

/// Recognize an import or module declaration from its normalized line prefix.
fn line_is_import_or_module_scaffold(line: &str) -> bool {
  let trimmed = line.trim_start();
  starts_with_any(trimmed, &[
    "use ", "pub use ", "import ", "from ", "mod ", "pub mod ", "extern crate ",
  ])
}

/// Recognize a fluent-chain continuation or detached closing tail.
fn line_is_chain_tail(line: &str) -> bool {
  let trimmed = line.trim_start();
  trimmed.starts_with('.') || matches!(trimmed, ")" | "};" | "});" | "];")
}

/// Recognize behavior keywords or computational operators within a line.
fn line_has_behavior(line: &str) -> bool {
  let trimmed = line.trim_start();
  contains_word(trimmed, BEHAVIOR_KEYWORDS) || trimmed.contains(['=', '+', '-', '*', '/', '%'])
}

/// Recognize a colon-separated row carrying both a key and a value.
fn line_is_structured_data(line: &str) -> bool {
  let trimmed = line.trim_start();
  let Some((key, contents)) = trimmed.split_once(':') else {
    return false;
  };
  key
    .chars()
    .any(|ch| matches!(ch, '"' | '\'' | '_') || ch.is_ascii_alphanumeric())
    && contents
      .chars()
      .any(|ch| matches!(ch, '"' | '\'' | '#' | '/' | '.' | '_') || ch.is_ascii_alphanumeric())
}

/// Recognize a prose-like line containing several words and no code delimiters.
fn line_is_prose(line: &str) -> bool {
  !line.contains(['{', '}', ';', '='])
    && line
      .split(|ch: char| !ch.is_ascii_alphabetic())
      .filter(|word| word.len() >= 3)
      .count()
      >= 4
}

/// Match a normalized spelling against the declared leading forms.
fn starts_with_any(text: &str, prefixes: &[&str]) -> bool {
  prefixes.iter().any(|prefix| text.starts_with(prefix))
}

/// Split a line into identifier-like word parts.
fn wordish_parts(text: &str) -> impl Iterator<Item = &str> {
  text.split(|ch: char| ch != '_' && !ch.is_ascii_alphanumeric())
}

/// Match whole identifier-like words rather than substrings of identifiers.
fn contains_word(text: &str, words: &[&str]) -> bool {
  wordish_parts(text).any(|part| words.contains(&part))
}

/// Count distinct content terms across all source lines of a window.
fn unique_terms_in_lines(slice: &[(usize, String)]) -> usize {
  unique_count(
    slice
      .iter()
      .flat_map(|entry| wordish_parts(&entry.1).filter(|term| term.len() >= 2)),
  )
}

/// Return the text values of a generic window unit, if it is one.
///
/// Window bodies are flat blocks of token leaves; any other body shape
/// (for example synthetic test units) returns `None`.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "This decoder is the text dimension's boundary for borrowing complete token leaves from a code unit."
)]
pub(crate) fn window_values(unit: &CodeUnit) -> Option<Vec<&str>> {
  if !matches!(unit.body.kind, NodeKind::Block) {
    return None;
  }
  unit
    .body
    .children
    .iter()
    .map(|child| {
      if let NodeKind::Token(ref spelling) = child.kind
        && child.children.is_empty()
      {
        Some(spelling.as_str())
      } else {
        None
      }
    })
    .collect()
}

/// Build a code unit from generic text values.
pub(crate) fn window_unit(path: &Path, name: &str, kind: CodeUnitKind, line_start: usize, line_end: usize, values: &[String]) -> CodeUnit {
  let body = NormalizedNode::with_children(
    NodeKind::Block,
    values
      .iter()
      .map(|spelling| NormalizedNode::leaf(NodeKind::Token(spelling.clone())))
      .collect(),
  );
  CodeUnit {
    suppressed: None,
    parent_chain: None,
    kind,
    name: name.to_owned(),
    file: path.to_path_buf(),
    line_start,
    line_end,
    signature: NormalizedNode::leaf(NodeKind::Opaque),
    fingerprint: Fingerprint::from_node(&body),
    node_count: values.len(),
    body,
    parent_name: None,
    is_test: false,
  }
}

/// Behavioral evidence for token identities, window boundaries, and rule attribution.
#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;
  use std::fmt::Debug;
  use std::path::PathBuf;
  use std::vec::IntoIter;

  use strict_test_support::CheckBatchFailure;
  use strict_test_support::ComparisonFailure;
  use strict_test_support::ConditionFailure;
  use strict_test_support::PredicateFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_all;
  use strict_test_support::ensure_eq;
  use strict_test_support::ensure_that;

  use super::*;
  use crate::suppression::SuppressionWarning;

  /// A complete match table whose opening arm rows can be cut by a token minimum.
  const MATCH_TABLE: &str = "\
fn map_binary(op: &Op) -> Kind {
    match op {
        Op::Add(_) => Kind::Add,
        Op::Sub(_) => Kind::Sub,
        Op::Mul(_) => Kind::Mul,
        Op::Div(_) => Kind::Div,
        Op::Rem(_) => Kind::Rem,
    }
}
";

  /// A derive-headed field table used at distinct token-window cutoff positions.
  const DECLARATION_SCAFFOLD: &str = "\
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct DimensionConfig {
    ast: Option<bool>,
    sub_ast: Option<bool>,
    token_normalized: Option<bool>,
    token_raw: Option<bool>,
}
";

  /// Executable source shared by token, line, and content-identity scenarios.
  const COMPUTATION_BLOCK: &str = "\
fn total(values: &[i32]) -> i32 {
    let mut sum = 0;
    for value in values {
        sum = sum + value;
    }
    return sum;
}
";

  /// Five substantive prose rows, also used as the prefix of the sliding-window scenario.
  const PROSE_BLOCK: &str = "\
alpha computes the total from account rows
bravo validates the threshold before export
charlie records the result for the caller
delta emits the summary into the report
echo preserves the fallback for empty input
";

  /// An unfinished documented signature whose prefix remains identical when a body follows it.
  const DOCUMENTED_SIGNATURE: &str = "\
/// Normalize one construct from the parse tree rows.
/// Produces a normalized node for the duplicate pipeline.
fn normalize_construct(
    node: tree_sitter::Node,
    source: &[u8],
    mapping: &NodeMapping,
    ctx: &mut NormalizationContext,
) -> NormalizedNode {
";

  /// Source, extraction configuration, and complete windows retained when a behavioral expectation
  /// fails.
  #[derive(Debug, thiserror::Error)]
  #[error(
    "window expectation failed for {path:?}: {source}; document: {document:?}; config: {config:?}; expected: {expected:?}; units: \
     {units:?}"
  )]
  struct WindowTestFailure<Expected, Failure = ConditionFailure> {
    /// Source path selecting the lexer profile and window identity.
    path:     PathBuf,
    /// Complete original source text supplied to extraction.
    document: String,
    /// Complete extraction configuration, including enabled dimensions and rule policy.
    config:   Config,
    /// Independently specified expectation supplied to the assertion.
    expected: Expected,
    /// Complete extracted population across every text dimension.
    units:    TextUnits,
    /// Native assertion failure.
    source:   Failure,
  }

  /// A checked window scenario retaining its complete extraction evidence on failure.
  type WindowTestResult<Expected, Failure = ConditionFailure> = Result<(), Box<WindowTestFailure<Expected, Failure>>>;

  /// A declaration-policy check batch retains its accepted prefix and unattempted checks.
  type DeclarationChecksFailure = CheckBatchFailure<(bool, &'static str), ConditionFailure, IntoIter<(bool, &'static str)>>;

  /// A declaration-policy comparison retains both configurations, populations, and resolution
  /// warnings.
  type DeclarationWindowTestResult = WindowTestResult<(TextUnits, Config, Vec<SuppressionWarning>), DeclarationChecksFailure>;

  /// Run an extraction scenario without losing unprojected units or inputs when its assertion
  /// fails.
  fn check_windows<Expected: Debug, Failure>(
    source_path: &str,
    document: &str,
    config: Config,
    expected: Expected,
    check: impl FnOnce(&TextUnits, &Expected) -> Result<(), Failure>,
  ) -> WindowTestResult<Expected, Failure> {
    let path = Path::new(source_path);
    let units = extract(path, document, &config);
    check(&units, &expected).map_err(|source| {
      Box::new(WindowTestFailure {
        path: path.to_path_buf(),
        document: document.to_owned(),
        config,
        expected,
        units,
        source,
      })
    })
  }

  /// Require the complete ordered population of visible line spans for one source segment scenario.
  fn check_visible_line_spans(
    path: &str,
    document: &str,
    line_min_lines: usize,
    expected: Vec<(usize, usize)>,
  ) -> WindowTestResult<Vec<(usize, usize)>> {
    let config = Config {
      line_min_lines,
      ..Config::default()
    };
    check_windows(path, document, config, expected, |units, spans| {
      ensure(
        units
          .lines
          .iter()
          .map(|unit| (unit.line_start, unit.line_end))
          .eq(spans.iter().copied())
          && units.lines.iter().all(|unit| unit.suppressed.is_none()),
        "line extraction retains every expected visible span in source order",
      )
      .map(drop)
    })
  }

  /// Describe the complete expected token, including its original source span.
  fn expected_token(raw: &str, normalized: &str, line: usize, end_line: usize) -> Token {
    Token {
      raw: raw.to_owned(),
      normalized: normalized.to_owned(),
      line,
      end_line,
    }
  }

  /// Complete lexer input and token populations when an identity or span differs.
  #[derive(Debug, thiserror::Error)]
  #[error("tokenization expectation failed: {source}; document: {document:?}; profile: {profile:?}")]
  struct TokenizationTestFailure {
    /// Original unmodified lexer input.
    document: String,
    /// Language-specific quote handling used for the input.
    profile:  QuoteProfile,
    /// Native comparison retaining complete actual and expected tokens with their spans.
    source:   ComparisonFailure<Vec<Token>, Vec<Token>>,
  }

  /// Compare complete token sequences while retaining the lexer inputs and outputs.
  fn check_tokens(document: &str, profile: QuoteProfile, expected: Vec<Token>) -> Result<(), Box<TokenizationTestFailure>> {
    ensure_eq(
      tokenize(document, profile),
      expected,
      "tokenization preserves raw and normalized spellings with their source spans",
    )
    .map(drop)
    .map_err(|source| {
      Box::new(TokenizationTestFailure {
        document: document.to_owned(),
        profile,
        source,
      })
    })
  }

  #[test]
  fn tokenize_preserves_spellings_and_source_spans() -> Result<(), Box<TokenizationTestFailure>> {
    for (document, expected) in [
      ("alpha_2 beta-x 31.5_f32", vec![
        expected_token("alpha_2", "IDENT", 1, 1),
        expected_token("beta-x", "IDENT", 1, 1),
        expected_token("31.5_f32", "NUMBER", 1, 1),
      ]),
      ("\"\u{03b1}\\\"\u{03b2}\\\n\u{03b3}\" tail", vec![
        expected_token("\"\u{03b1}\\\"\u{03b2}\\\n\u{03b3}\"", "STRING", 1, 2),
        expected_token("tail", "IDENT", 2, 2),
      ]),
      ("x = 'hello world'", vec![
        expected_token("x", "IDENT", 1, 1),
        expected_token("=", "=", 1, 1),
        expected_token("'hello world'", "STRING", 1, 1),
      ]),
    ] {
      check_tokens(document, QuoteProfile::default(), expected)?;
    }
    Ok(())
  }

  #[test]
  fn unterminated_quotes_retain_the_complete_remaining_source() -> Result<(), Box<TokenizationTestFailure>> {
    for (source, end_line) in [("\"unfinished\\", 1), ("'partial\n\u{96ea}", 2), ("`one\nnext", 2)] {
      check_tokens(source, QuoteProfile::default(), vec![expected_token(source, "STRING", 1, end_line)])?;
    }
    Ok(())
  }

  #[test]
  fn rust_character_literal_tails_require_a_bounded_same_line_close() -> Result<(), ConditionFailure> {
    for (tail, expected) in [
      ("\u{96ea}'", Some(2)),
      ("\\u{10FFFF}'", Some(11)),
      ("", None),
      ("'", None),
      ("\\", None),
      ("\\\n'", None),
      ("ab'", None),
      ("x\n'", None),
      ("\\u{12345678901}'", None),
    ] {
      ensure(
        char_literal_tail(tail.chars()) == expected,
        "Rust character-literal recognition requires the supported body and a same-line closing tick",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn rust_ticks_lex_char_literals_and_leave_lifetimes_as_punctuation() -> Result<(), PredicateFailure<Vec<Token>>> {
    let rust = QuoteProfile {
      rust_ticks: true
    };
    let mut tokens = tokenize("fn f<'a>(x: &'a str) -> char { 'x' }", rust);
    tokens = ensure_that(tokens, "only the character literal forms a quoted token", |observed| {
      observed
        .iter()
        .filter(|token| token.normalized == "STRING")
        .map(|token| token.raw.as_str())
        .collect::<Vec<_>>()
        == vec!["'x'"]
    })?;
    ensure_that(tokens, "both lifetime ticks remain punctuation", |observed| {
      observed.iter().filter(|token| token.raw == "'").count() == 2
    })
    .map(drop)
  }

  #[test]
  fn rust_ticks_pair_escaped_char_literals() -> Result<(), Box<TokenizationTestFailure>> {
    let rust = QuoteProfile {
      rust_ticks: true
    };
    for literal in ["'\\n'", "'\\''", "'\\u{1F600}'"] {
      check_tokens(literal, rust, vec![expected_token(literal, "STRING", 1, 1)])?;
    }
    Ok(())
  }

  #[test]
  fn comment_apostrophes_do_not_bridge_token_segments() -> Result<(), PredicateFailure<Vec<Token>>> {
    // The defect the Rust profile fixes: an unpaired tick (lifetime or
    // prose apostrophe) used to open a phantom multi-line string that
    // bridged blank lines and swallowed all later segments.
    let rust = QuoteProfile {
      rust_ticks: true
    };
    let mut tokens = tokenize("// doesn't pair\nlet a = 1;\n\nlet b = 2;\n", rust);
    tokens = ensure_that(tokens, "a prose apostrophe must not open a multiline token", |observed| {
      observed.iter().all(|token| token.line == token.end_line)
    })?;
    ensure_that(tokens, "the blank line remains a token-segment boundary", |observed| {
      token_segments(observed).len() == 2
    })
    .map(drop)
  }

  #[test]
  fn lifetime_ticks_do_not_blind_token_windows() -> Result<(), ConditionFailure> {
    // Three ticks (two lifetimes, one comment apostrophe) precede the
    // duplicated segments; the old naive pairing left one tick unpaired
    // and swallowed everything after it out of token segmentation.
    let source = "\
fn keep<'a>(x: &'a str) -> String {
    // it doesn't allocate much
    x.to_string()
}

fn alpha(items: &[u32]) -> Vec<u32> {
    items.iter().map(|v| v + 1).collect()
}

fn beta(items: &[u32]) -> Vec<u32> {
    items.iter().map(|v| v + 1).collect()
}
";
    let config = Config {
      token_min_tokens: 10,
      token_min_lines: 2,
      ..Config::default()
    };
    let units = extract(Path::new("src/lib.rs"), source, &config);
    let starts: Vec<usize> = units.normalized_tokens.iter().map(|unit| unit.line_start).collect();
    ensure(
      starts.contains(&6) && starts.contains(&10),
      "windows must cover both segments after the lifetime and prose ticks",
    )
    .map(drop)
  }

  #[test]
  fn wordish_parts_split_on_non_word_characters() -> Result<(), ConditionFailure> {
    let parts: Vec<_> = wordish_parts("alpha_one,beta.two(three)")
      .filter(|part| !part.is_empty())
      .collect();
    ensure(
      parts == vec!["alpha_one", "beta", "two", "three"],
      "punctuation splits terms while underscores remain in identifiers",
    )
    .map(drop)
  }

  #[test]
  fn structured_data_counts_the_final_window_line() -> Result<(), ConditionFailure> {
    // The last line of a window participates in per-line aggregation
    // exactly like interior lines.
    let tokens = tokenize("alpha: 1\nbeta: 2", QuoteProfile::default());
    ensure(
      token_window_has_structured_data(&tokens),
      "the final token line contributes a complete structured row",
    )
    .map(drop)
  }

  #[test]
  fn structured_token_rows_require_content_on_both_sides_of_the_colon() -> Result<(), ConditionFailure> {
    for (source, expected) in [
      ("alpha: 42", true),
      ("alpha: :beta", true),
      ("alpha:", false),
      (":beta", false),
      ("alpha beta", false),
      (":::", false),
    ] {
      let tokens = tokenize(source, QuoteProfile::default());
      ensure(
        line_has_structured_tokens(&tokens) == expected,
        "a separator alone or a missing key or value cannot form a structured row",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn empty_source_and_zero_window_minimums_produce_no_candidates() -> Result<(), ConditionFailure> {
    let disabled = Config {
      token_min_tokens: 0,
      line_min_lines: 0,
      ..Config::default()
    };
    ensure(
      extract(Path::new("empty.rs"), "", &Config::default()) == TextUnits::default(),
      "empty source produces no candidates in any text dimension",
    )
    .map(drop)?;
    ensure(
      extract(Path::new("disabled.rs"), COMPUTATION_BLOCK, &disabled) == TextUnits::default(),
      "zero window minimums disable extraction without slicing an empty window",
    )
    .map(drop)
  }

  #[test]
  fn disabled_token_dimensions_produce_no_token_windows() -> Result<(), ConditionFailure> {
    let config = Config {
      token_min_tokens: 8,
      token_min_lines: 1,
      enabled_dimensions: BTreeSet::from([DetectionDimension::Line]),
      ..Config::default()
    };
    let units = extract(Path::new("sample.rs"), "fn a() {\nlet x = 1;\nreturn x + 1;\n}", &config);
    ensure(
      units.normalized_tokens.is_empty() && units.raw_tokens.is_empty(),
      "disabled token dimensions emit no candidates",
    )
    .map(drop)
  }

  /// Require actual candidates and the expected rule on every retained unit.
  #[track_caller]
  fn ensure_all_tagged(units: &[CodeUnit], rule: RuleId) -> Result<(), ConditionFailure> {
    ensure(!units.is_empty(), "windows must exist to carry the tag").map(drop)?;
    for unit in units {
      ensure(
        unit.suppressed == Some(rule),
        "every retained window carries the expected suppression rule",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn token_scaffolds_retain_candidates_and_rule_attribution() -> WindowTestResult<RuleId> {
    let complete_signature = format!("{DOCUMENTED_SIGNATURE}    normalize(node, source, mapping, ctx)\n}}\n");
    for (min_tokens, document, rule) in [
      (40, MATCH_TABLE, RuleId::TokenMatchTablePrefix),
      (30, DOCUMENTED_SIGNATURE, RuleId::TokenSignaturePrefix),
      (30, complete_signature.as_str(), RuleId::TokenSignaturePrefix),
      (20, DECLARATION_SCAFFOLD, RuleId::TokenLowSignal),
      (35, DECLARATION_SCAFFOLD, RuleId::TokenDeclarationScaffold),
    ] {
      let config = Config {
        token_min_tokens: min_tokens,
        token_min_lines: 2,
        ..Config::default()
      };
      check_windows("sample.rs", document, config, rule, |units, &expected| {
        ensure_all_tagged(&units.normalized_tokens, expected)
      })?;
    }
    Ok(())
  }

  /// Raw vocabulary can carry signal even when identifier normalization removes its distinctions.
  #[test]
  fn raw_token_signal_requires_five_distinct_meaningful_values() -> WindowTestResult<Option<RuleId>> {
    for (document, raw_rule) in [
      ("alpha bravo charlie delta echo foxtrot", None),
      ("alpha bravo charlie delta echo alpha", None),
      ("alpha bravo charlie delta alpha bravo", Some(RuleId::TokenLowSignal)),
    ] {
      let config = Config {
        token_min_tokens: 6,
        token_min_lines: 1,
        ..Config::default()
      };
      check_windows("sample.txt", document, config, raw_rule, |units, &expected_raw| {
        ensure(
          matches!(units.raw_tokens.as_slice(), [raw] if raw.suppressed == expected_raw)
            && matches!(units.normalized_tokens.as_slice(), [normalized]
              if normalized.suppressed == Some(RuleId::TokenLowSignal)),
          "raw vocabulary below the distinct-value floor remains suppressed while normalized identifier-only windows stay low-signal",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// Extract both token dimensions over the complete supplied declaration or body.
  fn declaration_window_units(source: &str, suppression: SuppressionPolicy) -> TextUnits {
    extract(
      Path::new("declarations.rs"),
      source,
      &declaration_window_config(source, suppression),
    )
  }

  /// Configure both token dimensions over one complete declaration with the selected rule policy.
  fn declaration_window_config(source: &str, suppression: SuppressionPolicy) -> Config {
    Config {
      token_min_tokens: 1,
      token_min_lines: source.lines().count(),
      enabled_dimensions: BTreeSet::from([DetectionDimension::TokenNormalized, DetectionDimension::TokenRaw]),
      suppression,
      ..Config::default()
    }
  }

  #[test]
  fn declaration_windows_recognize_visibility_and_ignore_comment_behavior_words() -> Result<(), ConditionFailure> {
    for visibility in ["", "pub ", "pub(crate) ", "pub(super) ", "pub(in crate::owner) "] {
      let source = format!(
        "/// Values for callers; fn, if, let, and return describe their use.\n#[derive(Debug)]\npub struct State {{\n/// First value for \
         callers.\n{visibility}first: u8, // if a caller needs it\n/// Second value for callers.\n{visibility}second: u16, // return this \
         value\n}}"
      );
      let units = declaration_window_units(&source, SuppressionPolicy::default());
      ensure(
        (units.normalized_tokens.len(), units.raw_tokens.len()) == (1, 1),
        "classification must retain the complete candidate in both token dimensions",
      )
      .map(drop)?;
      for unit in units.normalized_tokens.iter().chain(&units.raw_tokens) {
        ensure(
          unit.suppressed == Some(RuleId::TokenDeclarationScaffold),
          "field visibility and documentation must not turn declaration scaffolding into executable behavior",
        )
        .map(drop)?;
      }
    }
    Ok(())
  }

  #[test]
  fn declaration_suppression_preserves_tokens_fingerprints_and_source_identity() -> DeclarationWindowTestResult {
    let source = "/// State for callers.\npub struct State {\n    pub first: u8,\n    pub(crate) second: u16,\n}";
    let (disabled, warnings) = SuppressionPolicy::resolve(&["token.declaration-scaffold".to_owned()], &[]);
    let disabled_config = declaration_window_config(source, disabled);
    let visible = extract(Path::new("declarations.rs"), source, &disabled_config);
    check_windows(
      "declarations.rs",
      source,
      declaration_window_config(source, SuppressionPolicy::default()),
      (visible, disabled_config, warnings),
      |tagged, expected| {
        let visible_units = &expected.0;
        let resolution_warnings = &expected.2;
        let mut checks = vec![
          (resolution_warnings.is_empty(), "the declaration rule must resolve without warnings"),
          (
            (
              tagged.normalized_tokens.len(),
              tagged.raw_tokens.len(),
              visible_units.normalized_tokens.len(),
              visible_units.raw_tokens.len(),
            ) == (1, 1, 1, 1),
            "both policies must retain one candidate per token dimension",
          ),
        ];
        for (suppressed, unsuppressed) in tagged
          .normalized_tokens
          .iter()
          .chain(&tagged.raw_tokens)
          .zip(visible_units.normalized_tokens.iter().chain(&visible_units.raw_tokens))
        {
          checks.extend([
            (
              suppressed.suppressed == Some(RuleId::TokenDeclarationScaffold) && unsuppressed.suppressed.is_none(),
              "the rule toggle must change presentation classification",
            ),
            (
              (suppressed.fingerprint, suppressed.node_count, window_values(suppressed))
                == (unsuppressed.fingerprint, unsuppressed.node_count, window_values(unsuppressed)),
              "classification must preserve all window tokens and their content identity",
            ),
            (
              (
                &suppressed.file, &suppressed.name, &suppressed.kind, suppressed.line_start, suppressed.line_end,
              ) == (
                &unsuppressed.file, &unsuppressed.name, &unsuppressed.kind, unsuppressed.line_start, unsuppressed.line_end,
              ),
              "classification must preserve the complete window location and identity",
            ),
          ]);
        }
        ensure_all(checks).map(drop)
      },
    )
  }

  #[test]
  fn declaration_windows_keep_executable_counterexamples_visible() -> Result<(), ConditionFailure> {
    for source in [
      "pub struct State {\n    pub first: u8,\n    pub second: u16,\n}\nimpl State {\n    fn total(&self) -> u16 {\n        \
       u16::from(self.first) + self.second\n    }\n}",
      "pub struct State {\n    pub first: [u8; 2 + 3],\n    pub second: u16,\n}",
      "// A struct with fields is only mentioned here.\nfn build() -> State {\n    State {\n        first: 1,\n        second: 2,\n    \
       }\n}",
      "pub struct State {\n    pub(crate first: u8,\n    pub second: u16,\n}",
    ] {
      let units = declaration_window_units(source, SuppressionPolicy::default());
      ensure(
        (units.normalized_tokens.len(), units.raw_tokens.len()) == (1, 1),
        "counterexample windows must exist in both dimensions",
      )
      .map(drop)?;
      for unit in units.normalized_tokens.iter().chain(&units.raw_tokens) {
        ensure(
          unit.suppressed.is_none(),
          "runtime code, computed fields, comment-only type headers, and incomplete visibility must remain reportable",
        )
        .map(drop)?;
      }
    }
    Ok(())
  }

  #[test]
  fn token_windows_keep_behavior_bearing_scaffold_counterexamples() -> WindowTestResult<Option<RuleId>> {
    let block_arms = "\
fn map_binary(op: Op, value: i32) -> Kind {
    match op {
        Op::Add => {
            let next = value + 1;
            Kind::Add(next)
        }
        Op::Sub => {
            let next = value - 1;
            Kind::Sub(next)
        }
    }
}
";
    let declaration_with_impl = "\
struct Counter {
    total: i32,
    limit: i32,
}

impl Counter {
    fn clamp(&self, input: i32) -> i32 {
        let bounded = input + self.total;
        if bounded > self.limit { self.limit } else { bounded }
    }
}
";
    let complete_chain = "\
fn collect_names(items: &[Item]) -> Vec<String> {
    let names = items
        .iter()
        .map(|item| item.name.to_string())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    names
}
";

    for (source, min_tokens, label) in [
      (block_arms, 30, "match arms with block bodies carry behavior"),
      (declaration_with_impl, 25, "declaration-adjacent runtime behavior stays eligible"),
      (complete_chain, 30, "complete callback chains stay eligible as token windows"),
    ] {
      let config = Config {
        token_min_tokens: min_tokens,
        token_min_lines: 2,
        ..Config::default()
      };
      check_windows("sample.rs", source, config, None, |units, &expected| {
        ensure(
          !units.normalized_tokens.is_empty() && units.normalized_tokens.iter().all(|unit| unit.suppressed == expected),
          label,
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  #[test]
  fn line_windows_split_declaration_and_impl_signatures() -> Result<(), ConditionFailure> {
    // Rust forces implementors to restate trait signatures, so only the
    // declaration side (terminated by `;`) loses its window; the
    // implementation side (a `{` body follows) keeps deliberate parity
    // visible.
    let declaration = "\
trait Reporter {
    fn report_groups(
        &self,
        groups: &[DuplicateGroup],
        writer: &mut dyn Write,
        section: ReportSection,
    ) -> Result<()>;
}
";
    let implementation = "\
fn parse_file(
    &self,
    path: &Path,
    source: &str,
    config: &AnalysisConfig,
) -> Result<Vec<CodeUnit>, Error> {
    parse_source(path, source, config.min_nodes, config.min_lines)
}
";
    let config = Config {
      line_min_lines: 5,
      ..Config::default()
    };
    let declaration_units = extract(Path::new("decl.rs"), declaration, &config);
    let implementation_units = extract(Path::new("impl.rs"), implementation, &config);
    ensure(
      declaration_units
        .lines
        .iter()
        .any(|unit| unit.line_start == 2 && unit.suppressed == Some(RuleId::LineDeclarationSignaturePrefix)),
      "the declaration's `fn` row window must exist and carry the prefix tag",
    )
    .map(drop)?;
    ensure(
      implementation_units
        .lines
        .iter()
        .any(|unit| unit.line_start == 1 && unit.suppressed.is_none()),
      "implementation signature rows keep their window visible",
    )
    .map(drop)
  }

  #[test]
  fn token_windows_keep_complete_code_stanzas() -> WindowTestResult<Option<RuleId>> {
    // Arrow rows inside a macro invocation are a complete data stanza,
    // and windows that begin at code (an undocumented impl signature)
    // describe real content; neither is scaffolding.
    let macro_arrow_table = "\
support_tests! {
    common::binary;
    check_passes_with_defaults => support::check_passes_with_defaults;
    check_fails_with_duplicates => support::check_fails_with_duplicates;
    check_reports_thresholds => support::check_reports_thresholds;
    check_handles_empty_input => support::check_handles_empty_input;
}
";
    let undocumented_signature = "\
fn parse_file(
    &self,
    path: &Path,
    source: &str,
    config: &AnalysisConfig,
) -> Result<Vec<CodeUnit>, Error> {
    parser::parse_source(path, source, config.min_nodes, config.min_lines)
}
";
    for source in [macro_arrow_table, undocumented_signature] {
      let config = Config {
        token_min_tokens: 30,
        token_min_lines: 2,
        ..Config::default()
      };
      check_windows("sample.rs", source, config, None, |units, &expected| {
        ensure(
          !units.normalized_tokens.is_empty() && units.normalized_tokens.iter().all(|unit| unit.suppressed == expected),
          "complete code stanzas keep their candidate windows visible",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  #[test]
  fn normalized_tokens_ignore_identifier_names() -> Result<(), ConditionFailure> {
    let first = tokenize("fn alpha(x: i32) { let beta = x + 1; }", QuoteProfile::default());
    let second = tokenize("fn gamma(y: i32) { let delta = y + 1; }", QuoteProfile::default());
    let first_norm: Vec<_> = first.iter().map(|token| token.normalized.as_str()).collect();
    let second_norm: Vec<_> = second.iter().map(|token| token.normalized.as_str()).collect();
    ensure(
      first_norm == second_norm,
      "identifier renaming preserves the normalized token stream",
    )
    .map(drop)
  }

  #[test]
  fn token_window_spans_respect_line_and_segment_boundaries() -> WindowTestResult<Vec<(usize, usize)>> {
    for (source, min_tokens, min_lines, spans) in [
      ("fn a() {\nlet x = 1;\nreturn x + 1;\n}", 8, 1, vec![(1, 2)]),
      ("fn a() { let x = 1; let y = 2; let z = x + y; }", 8, 2, Vec::new()),
      (
        "\
let total = first + second;
let result = total * scale;

let shifted = value + offset;
let scaled = shifted * factor;
",
        16,
        2,
        Vec::new(),
      ),
    ] {
      let config = Config {
        token_min_tokens: min_tokens,
        token_min_lines: min_lines,
        ..Config::default()
      };
      check_windows("sample.rs", source, config, spans, |units, expected| {
        ensure(
          units
            .normalized_tokens
            .iter()
            .map(|unit| (unit.line_start, unit.line_end))
            .eq(expected.iter().copied())
            && units
              .raw_tokens
              .iter()
              .map(|unit| (unit.line_start, unit.line_end))
              .eq(expected.iter().copied()),
          "token windows retain their source spans without crossing blank segments or admitting an insufficient line span",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  #[test]
  fn line_windows_normalize_whitespace() -> Result<(), ConditionFailure> {
    let config = Config {
      line_min_lines: 2,
      ..Config::default()
    };
    let units = extract(
      Path::new("README.md"),
      "alpha computes the totals today\n bravo records the outputs tomorrow \n",
      &config,
    );
    let windows: Vec<_> = units
      .lines
      .iter()
      .map(|unit| (unit.line_start, unit.line_end, window_values(unit)))
      .collect();
    ensure(
      windows
        == vec![(
          1,
          2,
          Some(vec!["alpha computes the totals today", "bravo records the outputs tomorrow"]),
        )],
      "line windows preserve source spans and normalize the complete line contents",
    )
    .map(drop)
  }

  #[test]
  fn line_windows_do_not_cross_blank_line_boundaries() -> WindowTestResult<Vec<(usize, usize)>> {
    // Two unrelated concepts: the tail of the first and the head of the
    // second must not be stitched into one window across the blank line.
    let source = "\
alpha computes the totals from rows
bravo validates the threshold value

charlie records the result for callers
delta emits the summary into reports
";
    let declarations = "\
struct First {
    first: usize,
}

struct Second {
    second: usize,
}
";
    for (path, document) in [("sample.txt", source), ("types.rs", declarations)] {
      check_visible_line_spans(path, document, 4, Vec::new())?;
    }
    Ok(())
  }

  /// Documentation words remain part of field stanzas across the permitted single blank line.
  #[test]
  fn line_windows_keep_documentation_words_inside_declaration_stanzas() -> WindowTestResult<Vec<(usize, usize)>> {
    let source = "\
struct Settings {
    first: usize,
    /// A value for callers that return.
    #[doc = \"match and fn are documentation words\"]
    second: usize,

    /// Another value while callers run.
    third: usize,
}
";
    check_visible_line_spans("settings.rs", source, 6, vec![(1, 7), (2, 8), (3, 9)])
  }

  /// Build a segment slice of consecutive numbered lines.
  fn numbered_lines(start: usize, lines: &[&str]) -> Vec<(usize, String)> {
    lines
      .iter()
      .enumerate()
      .map(|(offset, &line)| (start.saturating_add(offset), line.to_owned()))
      .collect()
  }

  /// Complete numbered segments before or after declaration-stanza coalescing.
  type LineSegments = Vec<Vec<(usize, String)>>;

  /// Original segments and full expected and actual coalescing results.
  #[derive(Debug, thiserror::Error)]
  #[error("stanza coalescing expectation failed: {source}; segments: {segments:?}")]
  struct StanzaCoalescingFailure {
    /// Complete source segments with their original line numbers.
    segments: LineSegments,
    /// Native comparison retaining complete actual and expected joined or separate segments.
    source:   ComparisonFailure<LineSegments, LineSegments>,
  }

  /// Compare coalescing results without dropping the source segments or rejected result.
  fn check_stanza_coalescing(segments: LineSegments, expected: LineSegments) -> Result<(), Box<StanzaCoalescingFailure>> {
    ensure_eq(
      coalesce_stanza_segments(segments.iter().map(Vec::as_slice).collect()),
      expected,
      "coalescing preserves every source row and only joins the expected declaration segments",
    )
    .map(drop)
    .map_err(|source| {
      Box::new(StanzaCoalescingFailure {
        segments,
        source,
      })
    })
  }

  #[test]
  fn stanza_segment_accepts_attribute_prelude_before_header() -> Result<(), ConditionFailure> {
    // The real clap/derive shape: doc and derive rows sit above the type
    // header.
    let segment = numbered_lines(1, &[
      "/// Spread option table.", "#[derive(Debug, Default)]", "pub struct SpreadA {", "pub alpha: usize,",
    ]);
    ensure(
      segment_is_declaration_stanza(&segment),
      "attributes and documentation can precede a declaration header",
    )
    .map(drop)
  }

  #[test]
  fn stanza_segment_accepts_trailing_close_brace_row() -> Result<(), ConditionFailure> {
    // The final stanza of a declaration block carries the block's `}`.
    let segment = numbered_lines(10, &["/// Final option.", "#[arg(long)]", "pub omega: bool,", "}"]);
    ensure(
      segment_is_declaration_stanza(&segment),
      "a final declaration stanza can include its closing brace",
    )
    .map(drop)
  }

  #[test]
  fn stanza_segment_rejects_lone_close_brace() -> Result<(), ConditionFailure> {
    let segment = numbered_lines(20, &["}"]);
    ensure(
      !segment_is_declaration_stanza(&segment),
      "a closing brace alone is not a declaration stanza",
    )
    .map(drop)
  }

  #[test]
  fn stanza_segment_rejects_comment_banner_without_rows() -> Result<(), ConditionFailure> {
    let segment = numbered_lines(1, &[
      "// ------------------------------------",
      "// Configuration",
      "// ------------------------------------",
    ]);
    ensure(
      !segment_is_declaration_stanza(&segment),
      "a comment banner needs declaration rows to form a stanza",
    )
    .map(drop)
  }

  #[test]
  fn stanza_segment_rejects_import_rows() -> Result<(), ConditionFailure> {
    let segment = numbered_lines(1, &["use std::collections::BTreeMap;", "use std::path::PathBuf;"]);
    ensure(
      !segment_is_declaration_stanza(&segment),
      "import rows remain outside declaration stanzas",
    )
    .map(drop)
  }

  #[test]
  fn stanza_blocks_merge_across_attribute_preludes_and_final_closing_rows() -> Result<(), Box<StanzaCoalescingFailure>> {
    for (first, second) in [
      (
        numbered_lines(1, &[
          "/// Spread option table.", "#[derive(Debug, Default)]", "pub struct SpreadA {", "pub alpha: usize,",
        ]),
        numbered_lines(6, &["pub beta: usize,", "}"]),
      ),
      (
        numbered_lines(1, &["/// First option.", "#[arg(long)]", "pub alpha: usize,"]),
        numbered_lines(5, &["/// Final option.", "#[arg(long)]", "pub omega: bool,", "}"]),
      ),
    ] {
      let expected = vec![first.iter().chain(&second).cloned().collect()];
      check_stanza_coalescing(vec![first, second], expected)?;
    }
    Ok(())
  }

  #[test]
  fn stanza_blocks_remain_separate_across_larger_gaps_or_executable_rows() -> Result<(), Box<StanzaCoalescingFailure>> {
    let first = numbered_lines(1, &["first: usize,"]);
    for second in [
      numbered_lines(4, &["second: usize,"]),
      numbered_lines(3, &["let total = first + second;"]),
      numbered_lines(3, &["/// Compute a total for callers.", "let total = first + second;"]),
    ] {
      let segments = vec![first.clone(), second];
      check_stanza_coalescing(segments.clone(), segments)?;
    }
    Ok(())
  }

  #[test]
  fn builder_steps_require_balanced_arguments_and_a_complete_terminator() -> Result<(), ConditionFailure> {
    for (line, expected) in [
      (".compute(outer(inner()));", true),
      ("  .arg(\"\u{96ea}\"),  ", true),
      (".step()", true),
      ("step()", false),
      (".()", false),
      (".step(", false),
      (".step(inner()", false),
      (".step())", false),
      (".step() trailing", false),
    ] {
      ensure(
        line_is_builder_step(line) == expected,
        "builder-step admission requires one complete balanced call with only a supported terminator",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn stanza_window_rejects_brace_only_lines() -> Result<(), ConditionFailure> {
    // Block punctuation inside a window is not a declaration row, so the
    // window must not be admitted as a stanza.
    let window = numbered_lines(1, &["pub alpha: usize,", "pub beta: usize,", "}"]);
    ensure(
      !line_window_is_declaration_stanza(&window),
      "a brace inside the window prevents declaration-stanza admission",
    )
    .map(drop)
  }

  #[test]
  fn line_windows_anchor_to_concept_segments() -> WindowTestResult<Vec<(usize, usize)>> {
    let source = "\
let total = first + second;
let result = total * scale;
return result + offset;

alpha computes the totals from rows
bravo validates the threshold value
charlie records the result for callers
";
    check_visible_line_spans("sample.rs", source, 3, vec![(1, 3), (5, 7)])
  }

  #[test]
  fn line_windows_do_not_end_on_block_opening_lines() -> Result<(), ConditionFailure> {
    let config = Config {
      line_min_lines: 3,
      ..Config::default()
    };
    // A window ending on the `fn ... {` line would cut into a body that
    // diverges immediately after the signature.
    let source = "\
let total = first + second;
let result = total * scale;
fn helper(value: i32) -> i32 {
let shifted = value + offset;
return shifted * scale;
}
";
    let units = extract(Path::new("sample.rs"), source, &config);
    ensure(
      units.lines.iter().all(|unit| unit.line_end != 3 && unit.line_start != 6),
      "no window may end on the opener line or start on the closer line",
    )
    .map(drop)?;
    ensure(
      units.lines.iter().any(|unit| (unit.line_start, unit.line_end) == (3, 5)),
      "the signature plus its own body is still a valid window",
    )
    .map(drop)
  }

  #[test]
  fn token_windows_are_stable_across_unrelated_line_shifts() -> Result<(), ConditionFailure> {
    let config = Config {
      token_min_tokens: 12,
      token_min_lines: 3,
      ..Config::default()
    };
    let shifted = format!("let unrelated = prefix_offset(1);\n\n{COMPUTATION_BLOCK}");
    let original = extract(Path::new("first.rs"), COMPUTATION_BLOCK, &config);
    let moved = extract(Path::new("second.rs"), &shifted, &config);
    ensure(
      !original.normalized_tokens.is_empty(),
      "the original concept must produce a token window",
    )
    .map(drop)?;
    ensure(
      original.normalized_tokens.iter().all(|first| {
        moved.normalized_tokens.iter().any(|second| {
          first.fingerprint == second.fingerprint
            && first.body == second.body
            && first.node_count == second.node_count
            && second.line_start == first.line_start.saturating_add(2)
            && second.line_end == first.line_end.saturating_add(2)
        })
      }),
      "every moved concept window retains its complete token body and identity while its source span shifts",
    )
    .map(drop)
  }

  #[test]
  fn line_windows_include_shifted_duplicate_candidates() -> WindowTestResult<Vec<(usize, usize)>> {
    let source = format!("{PROSE_BLOCK}foxtrot keeps the warnings near the output\ngolf returns the final status to clients\n");
    check_visible_line_spans("sample.txt", &source, 3, vec![(1, 3), (2, 4), (3, 5), (4, 6), (5, 7)])
  }

  #[test]
  fn token_windows_attribute_import_scaffolding_and_chain_tails() -> WindowTestResult<RuleId> {
    let imports = "\
use crate::alpha::Beta;
use crate::gamma::Delta;
pub mod tests;
use super::*;
";
    let chain = "\
command()
    .arg(\"report\")
    .arg(\"--format\")
    .arg(\"json\")
    .assert()
    .success();
";
    for (source, min_lines, rule) in [(imports, 2, RuleId::TokenImportScaffold), (chain, 3, RuleId::TokenChainTail)] {
      let config = Config {
        token_min_tokens: 12,
        token_min_lines: min_lines,
        ..Config::default()
      };
      check_windows("sample.rs", source, config, rule, |units, &expected| {
        ensure_all_tagged(&units.normalized_tokens, expected)?;
        ensure_all_tagged(&units.raw_tokens, expected)
      })?;
    }
    Ok(())
  }

  #[test]
  fn token_windows_preserve_executable_and_structured_content() -> WindowTestResult<Option<RuleId>> {
    let structured = r#"{
  "service": "api",
  "timeout": 30,
  "endpoint": "/v1/items",
  "team": "platform"
}"#;
    for (path, source) in [("sample.rs", COMPUTATION_BLOCK), ("sample.json", structured)] {
      let config = Config {
        token_min_tokens: 12,
        token_min_lines: 3,
        ..Config::default()
      };
      check_windows(path, source, config, None, |units, &expected| {
        ensure(
          [&units.normalized_tokens, &units.raw_tokens]
            .into_iter()
            .all(|dimension| !dimension.is_empty() && dimension.iter().all(|unit| unit.suppressed == expected)),
          "executable and structured token windows remain visible in both dimensions",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  #[test]
  fn line_windows_attribute_import_scaffolding_and_detached_chains() -> WindowTestResult<RuleId> {
    let imports = "\
use crate::alpha::Beta;
use crate::gamma::Delta;
#[cfg(test)]
mod tests {
}
";
    // No `-` anywhere: a dash counts as line behavior, which routes a
    // window to the low-signal score instead of the chain-tail rule.
    let chain = "\
command()
    .arg(\"report\")
    .arg(\"json\")
    .assert()
    .success();
";
    let callback_tail = "\
    .iter()
    .map(|item| item.name.to_string())
    .filter(|name| !name.is_empty())
    .collect::<Vec<_>>();
";
    for (source, min_lines, rule) in [
      (imports, 5, RuleId::LineImportScaffold),
      (chain, 5, RuleId::LineChainTail),
      (callback_tail, 4, RuleId::LineChainTail),
    ] {
      let config = Config {
        line_min_lines: min_lines,
        ..Config::default()
      };
      check_windows("sample.rs", source, config, rule, |units, &expected| {
        ensure_all_tagged(&units.lines, expected)
      })?;
    }
    Ok(())
  }

  #[test]
  fn line_windows_preserve_executable_structured_and_prose_content() -> WindowTestResult<Vec<(usize, usize)>> {
    let structured = "\
service: api
timeout: 30
endpoint: /v1/items
team: platform
region: us-east
";
    let bullets = "\
* validate incoming records before exporting results
* preserve warning details for later diagnosis
* compare generated reports with expected output
* collect duplicate groups for human review
* document policy decisions after each audit
";
    for (path, source, spans) in [
      ("sample.rs", COMPUTATION_BLOCK, vec![(1, 5), (2, 6), (3, 7)]),
      ("sample.txt", PROSE_BLOCK, vec![(1, 5)]),
      ("sample.yaml", structured, vec![(1, 5)]),
      ("README.md", bullets, vec![(1, 5)]),
    ] {
      check_visible_line_spans(path, source, 5, spans)?;
    }
    Ok(())
  }

  #[test]
  fn line_windows_reject_block_comment_only_prose() -> WindowTestResult<Vec<(usize, usize)>> {
    let source = "\
/*
 * validate incoming records before exporting results
 * preserve warning details for later diagnosis
 * compare generated reports with expected output
 * collect duplicate groups for human review
 */
";
    check_visible_line_spans("sample.rs", source, 5, Vec::new())
  }

  #[test]
  fn comment_marker_lines_do_not_blind_line_windows() -> Result<(), ConditionFailure> {
    let config = Config {
      line_min_lines: 3,
      ..Config::default()
    };
    // A `/*` inside a string literal or after `//` is content, not a
    // block-comment opener: the lines after it must still window.
    let quoted_marker = "\
let marker = rest.find(\"/*\");
let total = alpha + beta;
let scaled = total * gamma;
let bounded = scaled - delta;
";
    let line_comment_marker = "\
// tracks spans like /* these
let sum = one + two + three;
let widened = sum * sum;
let clamped = widened / four;
";
    for source in [quoted_marker, line_comment_marker] {
      let units = extract(Path::new("sample.rs"), source, &config);
      ensure(
        units.lines.iter().any(|unit| unit.line_end == 4),
        "line windows after a quoted or prose comment marker must still exist",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn strip_block_comments_tracks_comment_state_across_lines() -> Result<(), ConditionFailure> {
    let mut in_comment = false;
    let sequence = [
      ("alpha /* gone */ beta", "alpha  beta", false),
      ("open /* spans", "open ", true),
      ("still hidden", "", true),
      ("done */ tail", " tail", false),
    ];
    for (line, expected, state_after) in sequence {
      let output = strip_block_comments(line, &mut in_comment);
      ensure(
        (output.as_str(), in_comment) == (expected, state_after),
        "comment stripping preserves the visible text and tracks its continuation state",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn strip_block_comments_keeps_quoted_and_prose_markers() -> Result<(), ConditionFailure> {
    for (line, expected) in [
      ("rest.find(\"/*\")", "rest.find(\"/*\")"),
      ("let quote = '\"'; /* gone */", "let quote = '\"'; "),
      ("// prose /* stays", "// prose /* stays"),
      ("# python /* stays", "# python /* stays"),
      ("fn f<'a>(s: &'a str) { /* gone */ }", "fn f<'a>(s: &'a str) {  }"),
    ] {
      let mut in_comment = false;
      let output = strip_block_comments(line, &mut in_comment);
      ensure(
        (output.as_str(), in_comment) == (expected, false),
        "quoted and prose markers stay literal while actual block comments close",
      )
      .map(drop)?;
    }
    Ok(())
  }
}
