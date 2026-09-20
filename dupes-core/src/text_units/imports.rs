//! Complete Rust import declarations used only for window classification.

use std::collections::BTreeSet;

use super::Token;
use super::after_attributes;
use super::after_token_group;
use super::after_visibility;
use super::window_code_lines;

/// Find source lines covered entirely by imports and balanced module boundaries.
///
/// Attributes, visibility, grouped paths, aliases, and globs belong to their
/// declaration. A line containing any additional code remains unclassified.
/// The original token stream and window boundaries are never changed.
#[allow(
  clippy::single_call_fn,
  reason = "Complete import spans provide source context independently of candidate window cuts."
)]
pub(super) fn lines(tokens: &[Token]) -> BTreeSet<usize> {
  let code_lines = window_code_lines(tokens, tokens.len());
  let code: Vec<&Token> = code_lines.iter().flatten().copied().collect();
  let mut covered = BTreeSet::new();
  let mut remaining = code.as_slice();
  while let Some((first, next)) = remaining.split_first() {
    if let Some(tail) = after_import(remaining) {
      covered.extend(code.len().saturating_sub(remaining.len())..code.len().saturating_sub(tail.len()));
      remaining = tail;
    } else if let Some((body, tail)) = module_boundaries(remaining) {
      covered.extend(code.len().saturating_sub(remaining.len())..code.len().saturating_sub(body.len()));
      covered.extend([code.len().saturating_sub(tail.len()).saturating_sub(1)]);
      remaining = body;
    } else if first.raw == "#"
      && let Some(tail) = after_attributes(remaining)
    {
      remaining = tail;
    } else if first.raw == "macro_rules"
      && let &[bang, name, ref input @ ..] = next
      && bang.raw == "!"
      && name.normalized == "IDENT"
      && let Some(tail) = after_token_group(input)
    {
      remaining = tail;
    } else if first.raw == "!"
      && let Some(tail) = after_token_group(next)
    {
      // Macro input may describe imports as data; its caller owns that meaning.
      remaining = tail;
    } else {
      remaining = next;
    }
  }
  let mut offset = 0_usize;
  code_lines
    .into_iter()
    .filter_map(|line| {
      let start = offset;
      offset = offset.saturating_add(line.len());
      let first = line.first()?;
      (start..offset).all(|index| covered.contains(&index)).then_some(first.line)
    })
    .collect()
}

/// Source suffixes starting at a module body and immediately after its closing brace.
type ModuleSlices<'a> = (&'a [&'a Token], &'a [&'a Token]);

/// Borrow the body start and suffix of a balanced inline module without classifying its contents.
#[allow(
  clippy::single_call_fn,
  reason = "Module boundaries are declaration scaffolding while every body token retains independent classification."
)]
fn module_boundaries<'a>(tokens: &'a [&'a Token]) -> Option<ModuleSlices<'a>> {
  let declaration = after_attributes(tokens).and_then(after_visibility)?;
  let &[keyword, name, ref group @ ..] = declaration else {
    return None;
  };
  let (open, body) = group.split_first()?;
  if keyword.raw != "mod" || name.normalized != "IDENT" || open.raw != "{" {
    return None;
  }
  let tail = after_token_group(group)?;
  Some((body, tail))
}

/// Borrow the suffix after one complete import, including its attributes and visibility.
#[allow(
  clippy::single_call_fn,
  reason = "Import grammar is distinct from scanning source context around declaration candidates."
)]
fn after_import<'a>(tokens: &'a [&'a Token]) -> Option<&'a [&'a Token]> {
  let declaration = after_attributes(tokens).and_then(after_visibility)?;
  let (keyword, remaining) = declaration.split_first()?;
  match keyword.raw.as_str() {
    "use" => after_use_tree(remaining),
    "extern" => {
      let (kind, rest) = remaining.split_first()?;
      (kind.raw == "crate").then_some(rest).and_then(after_crate_name)
    }
    "mod" => {
      let (name, rest) = remaining.split_first()?;
      if name.normalized != "IDENT" {
        return None;
      }
      match *rest {
        [end, ref tail @ ..] if end.raw == ";" => Some(tail),
        [open, close, ref tail @ ..] if open.raw == "{" && close.raw == "}" => Some(tail),
        _ => None,
      }
    }
    _ => None,
  }
}

/// A crate import ends after its name and optional alias, with no executable tokens.
#[allow(
  clippy::single_call_fn,
  reason = "Crate imports have a distinct name-and-alias grammar from grouped use paths."
)]
fn after_crate_name<'a>(tokens: &'a [&'a Token]) -> Option<&'a [&'a Token]> {
  let (name, remaining) = tokens.split_first()?;
  if name.normalized != "IDENT" {
    return None;
  }
  match *remaining {
    [end, ref tail @ ..] if end.raw == ";" => Some(tail),
    [rename, alias, end, ref tail @ ..] if rename.raw == "as" && alias.normalized == "IDENT" && end.raw == ";" => Some(tail),
    _ => None,
  }
}

/// Consume a complete path tree while rejecting calls, initializers, and mismatched delimiters.
#[allow(
  clippy::single_call_fn,
  reason = "Use-tree traversal owns balanced path groups separately from import dispatch."
)]
fn after_use_tree<'a>(mut tokens: &'a [&'a Token]) -> Option<&'a [&'a Token]> {
  while let Some((token, remaining)) = tokens.split_first() {
    match token.raw.as_str() {
      ";" => return Some(remaining),
      "{" => {
        let after_group = after_token_group(tokens)?;
        let group_length = tokens.len().saturating_sub(after_group.len());
        let interior = tokens.get(1..group_length.checked_sub(1)?)?;
        if !interior
          .iter()
          .all(|component| matches!(component.raw.as_str(), "{" | "}") || use_path_token(component))
        {
          return None;
        }
        tokens = after_group;
      }
      _ if use_path_token(token) => tokens = remaining,
      _ => return None,
    }
  }
  None
}

/// Path components, renaming, and glob punctuation have declaration meaning inside `use`.
fn use_path_token(token: &Token) -> bool {
  token.normalized == "IDENT" || matches!(token.raw.as_str(), "self" | "as" | ":" | "," | "*")
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use strict_test_support::PredicateFailure;
  use strict_test_support::ensure_that;

  use crate::config::Config;
  use crate::suppression::RuleId;
  use crate::suppression::SuppressionPolicy;
  use crate::suppression::SuppressionWarning;
  use crate::text_units::TextUnits;
  use crate::text_units::extract;

  /// Original source, window dimensions, and the complete native candidate population.
  type Observation = (String, Config, TextUnits);
  /// Both policy inputs and populations, warnings, and the untagged view remain available.
  type PolicyObservation = (Observation, Observation, Vec<SuppressionWarning>, TextUnits);
  /// Failed classification checks retain every native observation in the batch.
  type ClassificationFailure<T> = Box<PredicateFailure<Vec<T>>>;

  /// Observe all dimensions over a complete source without altering its declaration grammar.
  fn observe(source: &str, min_lines: usize, suppression: SuppressionPolicy) -> Observation {
    let config = Config {
      token_min_tokens: 1,
      token_min_lines: min_lines,
      line_min_lines: min_lines,
      suppression,
      ..Config::default()
    };
    let units = extract(Path::new("imports.rs"), source, &config);
    (source.to_owned(), config, units)
  }

  /// Public, restricted, attributed, aliased, grouped, and glob imports are declaration
  /// scaffolding.
  #[test]
  fn complete_imports_classify_without_treating_attributes_or_globs_as_computation() -> Result<(), ClassificationFailure<Observation>> {
    let mut observations = Vec::new();
    for visibility in ["", "pub ", "pub(crate) ", "pub(super) ", "pub(in crate::api) "] {
      let source = format!(
        "// Imports for callers; if, return, and fn are prose.\n#[cfg(\n    all(feature = \"std\", not(test))\n)]\n{visibility}use \
         crate::owner::{{\n    self,\n    Item as Alias,\n    nested::{{First, Second}},\n    *,\n}};\n{visibility}mod child;\nextern \
         crate external as dependency;"
      );
      let nested = format!("#[cfg(test)]\n{visibility}mod outer {{\n{visibility}mod imports {{\n{source}\n}}\n}}");
      for program in [&source, &nested] {
        observations.extend([2, 5, program.lines().count()].map(|min_lines| observe(program, min_lines, SuppressionPolicy::default())));
      }
    }
    ensure_that(
      observations,
      "only complete import declarations cover these source windows",
      |cases| {
        cases.iter().all(|case| {
          let units = &case.2;
          !units.normalized_tokens.is_empty()
            && !units.raw_tokens.is_empty()
            && !units.lines.is_empty()
            && units
              .normalized_tokens
              .iter()
              .chain(&units.raw_tokens)
              .all(|unit| unit.suppressed == Some(RuleId::TokenImportScaffold) || unit.suppressed == Some(RuleId::TokenCommentOnly))
            && units
              .lines
              .iter()
              .all(|unit| unit.suppressed == Some(RuleId::LineImportScaffold))
        })
      },
    )
    .map_err(Box::new)
    .map(drop)
  }

  /// A nearby import cannot classify an implementation, computation, or malformed declaration.
  #[test]
  fn imports_do_not_hide_executable_or_incomplete_windows() -> Result<(), ClassificationFailure<Observation>> {
    let sources = [
      "pub use crate::Item;\nfn execute() {\n    consume(Item);\n}",
      "use crate::Item; consume(Item);\nlet output = transform(Item);",
      "pub mod nested {\n    fn execute() {\n        consume(value);\n    }\n}",
      "pub mod nested {\n    use crate::Item;\n    fn execute() {\n        consume(Item);\n    }\n}",
      "#[cfg(test)]\nmod nested {\n    use crate::Item;\n    use crate::Other;",
      "#[cfg(feature = \"std\")]\npub use crate::{\n    Item,\n    transform(value)\n};",
      "pub use crate::{\n    First,\n    Second;",
      "#[cfg(\n    feature = \"std\"\n]\npub use crate::Item;",
      "pub(crate\nuse crate::Item;\nuse crate::Other;",
      "pub const SIZE: usize = evaluate();\nuse crate::Item;\nlet result = SIZE + 1;",
    ];
    let observations = sources
      .into_iter()
      .map(|source| observe(source, source.lines().count(), SuppressionPolicy::default()))
      .collect();
    ensure_that(
      observations,
      "executable and incomplete source cannot inherit an import's classification",
      |cases: &Vec<Observation>| {
        cases.iter().all(|case| {
          let units = &case.2;
          !units.normalized_tokens.is_empty()
            && !units.raw_tokens.is_empty()
            && !units.lines.is_empty()
            && units
              .normalized_tokens
              .iter()
              .chain(&units.raw_tokens)
              .chain(&units.lines)
              .all(|unit| unit.suppressed != Some(RuleId::TokenImportScaffold) && unit.suppressed != Some(RuleId::LineImportScaffold))
        })
      },
    )
    .map_err(Box::new)
    .map(drop)
  }

  /// Import-shaped literal and macro input stays data, including raw literals with interior quotes.
  #[test]
  fn import_classification_preserves_embedded_programs() -> Result<(), ClassificationFailure<Observation>> {
    let body = "pub use crate::First;\npub use crate::Second;\npub use crate::Third;";
    let sources = [
      format!("let source = \"\n{body}\n\";"),
      format!("let source = r##\"an interior quote: \"\n{body}\n\"##;"),
      format!("let source = br#\"\n{body}\n\"#;"),
      format!("quote! {{\n{body}\n}}"),
      format!("macro_rules! imported {{\n    () => {{\n{body}\n    }}\n}}"),
      format!("#[input(\n{body}\n)]\nfn execute() {{ work(); }}"),
    ];
    let observations = sources
      .iter()
      .map(|source| observe(source, 2, SuppressionPolicy::default()))
      .collect();
    ensure_that(
      observations,
      "declarations inside quoted or macro data do not become source-level imports",
      |cases: &Vec<Observation>| {
        cases.iter().all(|case| {
          !case.2.lines.is_empty()
            && case
              .2
              .lines
              .iter()
              .all(|unit| unit.suppressed != Some(RuleId::LineImportScaffold))
            && case
              .2
              .normalized_tokens
              .iter()
              .chain(&case.2.raw_tokens)
              .all(|unit| unit.suppressed != Some(RuleId::TokenImportScaffold))
        })
      },
    )
    .map_err(Box::new)
    .map(drop)
  }

  /// A rule toggle preserves complete candidates and fingerprints, including partial-window cuts.
  #[test]
  fn import_rule_toggles_preserve_all_candidate_fields() -> Result<(), ClassificationFailure<PolicyObservation>> {
    let source = "#[cfg(feature = \"std\")]\npub use crate::{\n    First,\n    Second as Alias,\n};\npub(crate) use super::*;";
    let mut observations = Vec::new();
    for min_lines in [2, 3, 6] {
      let (disabled, warnings) = SuppressionPolicy::resolve(&["token.import-scaffold".to_owned(), "line.import-scaffold".to_owned()], &[]);
      let tagged = observe(source, min_lines, SuppressionPolicy::default());
      let mut without_tags = tagged.2.clone();
      for unit in without_tags
        .normalized_tokens
        .iter_mut()
        .chain(&mut without_tags.raw_tokens)
        .chain(&mut without_tags.lines)
      {
        unit.suppressed = None;
      }
      observations.push((tagged, observe(source, min_lines, disabled), warnings, without_tags));
    }
    ensure_that(
      observations,
      "disabling import classification changes only the suppression tags",
      |cases| {
        cases.iter().all(|case| {
          let tagged = &case.0.2;
          let visible = &case.1.2;
          case.2.is_empty()
            && !tagged.normalized_tokens.is_empty()
            && !tagged.raw_tokens.is_empty()
            && !tagged.lines.is_empty()
            && case.3 == *visible
        })
      },
    )
    .map_err(Box::new)
    .map(drop)
  }
}
