//! Independent parsed-source locations for the self-corpus consolidation gate.

use std::fs;
use std::io;
use std::path::Path;

use proc_macro2::Span;
use syn::Ident;
use syn::spanned::Spanned as _;
use syn::visit;
use syn::visit::Visit;

/// Source read, parsing, or unique-definition selection failure.
#[derive(Debug, thiserror::Error)]
pub(super) enum FunctionFailure {
  /// The source file could not be read.
  #[error(transparent)]
  Read(#[from] io::Error),
  /// The source was not valid Rust.
  #[error("source could not be parsed: {source}")]
  Parse {
    /// Complete source text presented to the parser.
    input:  String,
    /// Native parser diagnostic.
    source: syn::Error,
  },
  /// The requested function was absent or ambiguous.
  #[error("function `{name}` did not identify exactly one definition")]
  Selection {
    /// Requested function identity.
    name:       String,
    /// Complete parsed source containing the candidates.
    syntax:     Box<syn::File>,
    /// All matching definition locations.
    candidates: Vec<Span>,
  },
}

/// Collect function definitions by identifier without interpreting comment or literal text.
#[derive(Debug)]
struct FunctionSpans<'name> {
  /// Identifier selected by the consolidation contract.
  name:       &'name str,
  /// Full item spans of every definition with that identifier.
  candidates: Vec<Span>,
}

impl FunctionSpans<'_> {
  /// Retain the native item span when its identifier matches the requested function.
  fn record(&mut self, name: &Ident, span: Span) {
    if name == self.name {
      self.candidates.push(span);
    }
  }
}

impl<'ast> Visit<'ast> for FunctionSpans<'_> {
  fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
    self.record(&function.sig.ident, function.span());
    visit::visit_item_fn(self, function);
  }

  fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
    self.record(&function.sig.ident, function.span());
    visit::visit_impl_item_fn(self, function);
  }

  fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
    self.record(&function.sig.ident, function.span());
    visit::visit_trait_item_fn(self, function);
  }
}

/// Resolve the only function definition with `name` from a complete Rust syntax tree.
fn parse_span(input: &str, name: &str) -> Result<Span, FunctionFailure> {
  let syntax = syn::parse_file(input).map_err(|source| FunctionFailure::Parse {
    input: input.to_owned(),
    source,
  })?;
  let mut locator = FunctionSpans {
    name,
    candidates: Vec::new(),
  };
  locator.visit_file(&syntax);
  if let [span] = *locator.candidates.as_slice() {
    Ok(span)
  } else {
    Err(FunctionFailure::Selection {
      name:       name.to_owned(),
      syntax:     Box::new(syntax),
      candidates: locator.candidates,
    })
  }
}

/// Read a source file and locate its uniquely named function.
#[allow(
  clippy::single_call_fn,
  reason = "the self-corpus gate needs one named boundary for reading and structurally locating its source oracle"
)]
pub(super) fn function_span(path: &Path, name: &str) -> Result<Span, FunctionFailure> {
  parse_span(&fs::read_to_string(path)?, name)
}

#[cfg(test)]
mod tests {
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;

  use super::FunctionFailure;
  use super::parse_span;

  /// Test outcomes retain both parser failures and expectation failures.
  #[derive(Debug, thiserror::Error)]
  enum SpanTestFailure {
    /// The source locator failed.
    #[error(transparent)]
    Function(#[from] FunctionFailure),
    /// The observed span violated the expected source boundary.
    #[error(transparent)]
    Expectation(#[from] ConditionFailure),
  }

  #[test]
  fn locates_complete_bodies_despite_comment_and_literal_braces() -> Result<(), SpanTestFailure> {
    let source = "// fn selected() {\nmod nested {\n  fn selected<T>() {\n    let text = \"}\";\n    /* } */\n    consume(text);\n  }\n}\n";
    let span = parse_span(source, "selected")?;
    ensure(
      (span.start().line, span.end().line) == (3, 7),
      "comments and literals must not alter the function span",
    )
    .map(drop)?;
    Ok(())
  }

  #[test]
  fn locates_impl_and_trait_functions() -> Result<(), SpanTestFailure> {
    let source = "trait Render { fn render(&self); }\nimpl View { fn draw(&self) {} }\n";
    let declared = parse_span(source, "render")?;
    let implemented = parse_span(source, "draw")?;
    ensure(
      (declared.start().line, implemented.start().line) == (1, 2),
      "trait and impl functions must retain their declaration locations",
    )
    .map(drop)?;
    Ok(())
  }

  #[test]
  fn rejects_absent_and_ambiguous_definitions_with_all_candidates() -> Result<(), ConditionFailure> {
    for (source, expected) in [
      ("fn different() {}", 0),
      ("mod a { fn selected() {} } mod b { fn selected() {} }", 2),
    ] {
      ensure(
        matches!(parse_span(source, "selected"), Err(FunctionFailure::Selection { name, candidates, syntax })
        if name == "selected" && candidates.len() == expected && !syntax.items.is_empty()),
        "selection failure must retain every matching definition and the parsed source",
      )
      .map(drop)?;
    }
    Ok(())
  }

  #[test]
  fn retains_invalid_source_and_native_parse_diagnostic() -> Result<(), ConditionFailure> {
    let source = "fn selected(";
    ensure(
      matches!(parse_span(source, "selected"), Err(FunctionFailure::Parse { input, source: diagnostic })
      if input == source && diagnostic.span().start().line == 1),
      "invalid source must remain available with its parser diagnostic",
    )
    .map(drop)
  }
}
