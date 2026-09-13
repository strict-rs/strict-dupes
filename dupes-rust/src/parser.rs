//! Rust `CodeUnit` extraction through `syn`: top-level and sub-function
//! extractors, impl-aware naming, and test-code tagging.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::from_ref;

pub use dupes_core::code_unit::CodeUnit;
pub use dupes_core::code_unit::CodeUnitKind;
use dupes_core::fingerprint::Fingerprint;
use dupes_core::node::NodeKind;
use dupes_core::node::NormalizationContext;
use dupes_core::node::NormalizedNode;
use dupes_core::node::reindex_placeholders;
use dupes_core::source::SourceFile;
use dupes_core::source::SourceReadError;
use proc_macro2::TokenTree;
use syn::spanned::Spanned as _;
use syn::visit;
use syn::visit::Visit;

use crate::normalizer;

/// A rejected Rust source together with its native parser diagnostic.
#[derive(Debug, thiserror::Error)]
#[error("Failed to parse {}: {source}", input.path.display())]
pub struct RustParseError {
  /// Complete rejected source and its identity, including text outside the diagnostic span.
  pub input:  SourceFile,
  /// Original `syn` diagnostic and its source spans.
  #[source]
  pub source: syn::Error,
}

/// A file-read or parse failure retaining the native cause and available input.
#[derive(Debug, thiserror::Error)]
pub enum RustFileError {
  /// The shared source reader could not produce valid UTF-8 text.
  #[error(transparent)]
  Read(#[from] SourceReadError),
  /// The decoded file was rejected by the Rust parser.
  #[error(transparent)]
  Parse(#[from] RustParseError),
}

/// A successfully read and parsed file with its complete source and extracted units.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedRustFile {
  /// Complete native source read used for extraction.
  pub file:  SourceFile,
  /// Every admitted code unit, including units tagged as tests.
  pub units: Vec<CodeUnit>,
}

/// Check if attributes contain `#[test]`.
#[allow(
  clippy::single_call_fn,
  reason = "Free-function classification shares the exact test attribute predicate with its parser tests"
)]
fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
  attrs.iter().any(|attr| attr.path().is_ident("test"))
}

/// Define `with_test_context` for a unit extractor: run `visit` with the
/// `#[cfg(test)]`-context flag set to `is_test`, restoring the previous
/// value afterwards. Stamped into both extractors so the context juggling
/// is stated once.
macro_rules! with_test_context_method {
  () => {
    /// Visit one scope with its test context, restoring the enclosing context afterward.
    fn with_test_context(&mut self, is_test: bool, visit: impl FnOnce(&mut Self)) {
      let previous_test = self.in_test_context;
      self.in_test_context = is_test;
      visit(self);
      self.in_test_context = previous_test;
    }
  };
}

/// Extracts nested code units with precise spans.
#[derive(Debug)]
struct SubUnitExtractor {
  /// Native source-file identity retained by each extracted unit.
  file:            PathBuf,
  /// Minimum normalized body size admitted as a sub-unit.
  min_node_count:  usize,
  /// Complete admitted sub-units in source visitation order.
  units:           Vec<CodeUnit>,
  /// Function or method enclosing the current sub-unit.
  current_parent:  Option<String>,
  /// Whether the current source scope is test code.
  in_test_context: bool,
  /// `if` statements represented by an if-chain unit, mapped to that chain
  /// unit's content fingerprint; their branch units are emitted linked via
  /// `parent_chain` so the pipeline can treat them as chain-covered.
  chained_ifs:     HashMap<*const syn::ExprIf, Fingerprint>,
}

impl SubUnitExtractor {
  /// Prepare extraction for one source file and normalized body-size floor.
  #[allow(
    clippy::single_call_fn,
    reason = "Sub-unit construction establishes the source identity and empty enclosing-context state"
  )]
  fn new(file: PathBuf, min_node_count: usize) -> Self {
    Self {
      file,
      min_node_count,
      units: Vec::new(),
      current_parent: None,
      in_test_context: false,
      chained_ifs: HashMap::new(),
    }
  }

  with_test_context_method!();

  /// Visit a function body while retaining and restoring its enclosing source identity.
  fn with_parent(&mut self, parent: String, is_test: bool, visit: impl FnOnce(&mut Self)) {
    let previous_parent = self.current_parent.replace(parent);
    self.with_test_context(is_test, visit);
    self.current_parent = previous_parent;
  }

  /// Normalize an expression and append its complete admitted sub-unit.
  fn add_expr_unit(
    &mut self,
    kind: CodeUnitKind,
    description: String,
    expr: &syn::Expr,
    lines: RangeInclusive<usize>,
    parent_chain: Option<Fingerprint>,
  ) {
    let mut ctx = NormalizationContext::new();
    let body = reindex_placeholders(&normalizer::normalize_expr(expr, &mut ctx));
    self
      .units
      .extend(self.normalized_unit(kind, description, body, lines, parent_chain));
  }

  /// Normalize a block and append its complete admitted sub-unit with brace-delimited lines.
  fn add_block_unit(&mut self, kind: CodeUnitKind, description: String, block: &syn::Block, parent_chain: Option<Fingerprint>) {
    let mut ctx = NormalizationContext::new();
    let body = reindex_placeholders(&normalizer::normalize_block(block, &mut ctx));
    let line_start = block.brace_token.span.open().start().line;
    let line_end = block.brace_token.span.close().end().line;
    self
      .units
      .extend(self.normalized_unit(kind, description, body, line_start..=line_end, parent_chain));
  }

  /// Record the body of one supported loop construct.
  fn add_loop_body(&mut self, description: &str, block: &syn::Block) {
    self.add_block_unit(CodeUnitKind::LoopBody, description.to_owned(), block, None);
  }

  /// Construct the complete sub-unit when its normalized body reaches the configured floor.
  fn normalized_unit(
    &self,
    kind: CodeUnitKind,
    description: String,
    body: NormalizedNode,
    lines: RangeInclusive<usize>,
    parent_chain: Option<Fingerprint>,
  ) -> Option<CodeUnit> {
    let node_count = normalizer::count_nodes(&body);
    if node_count < self.min_node_count {
      return None;
    }
    Some(CodeUnit {
      suppressed: None,
      parent_chain,
      kind,
      name: description,
      file: self.file.clone(),
      line_start: *lines.start(),
      line_end: *lines.end(),
      signature: NormalizedNode::leaf(NodeKind::Opaque),
      fingerprint: Fingerprint::from_node(&body),
      node_count,
      body,
      parent_name: self.current_parent.clone(),
      is_test: self.in_test_context,
    })
  }

  /// Extract runs of two or more consecutive `if` statements as one
  /// coherent if-chain unit (for example option-to-field setter clusters),
  /// replacing the per-branch fragments of the chained statements.
  fn collect_if_chains(&mut self, block: &syn::Block) {
    let mut run: Vec<&syn::Expr> = Vec::new();
    for stmt in &block.stmts {
      if let syn::Stmt::Expr(ref expr @ syn::Expr::If(_), _) = *stmt {
        run.push(expr);
      } else {
        self.flush_if_chain(&run);
        run.clear();
      }
    }
    self.flush_if_chain(&run);
  }

  /// Emit one admitted chain and link its constituent `if` nodes by native pointer identity.
  fn flush_if_chain(&mut self, run: &[&syn::Expr]) {
    if run.len() < 2 {
      return;
    }
    let mut ctx = NormalizationContext::new();
    let chain = NormalizedNode::with_children(
      NodeKind::Block,
      run.iter().map(|expr| normalizer::normalize_expr(expr, &mut ctx)).collect(),
    );
    let body = reindex_placeholders(&chain);
    let line_start = run.first().map_or(1, |expr| expr.span().start().line);
    let line_end = run.last().map_or(line_start, |expr| expr.span().end().line);
    // Branches link to the chain only when the chain itself became a
    // unit; a sub-threshold chain leaves its branches unlinked, which
    // matches their pre-chain behavior because they fall under the same
    // node threshold.
    let Some(unit) = self.normalized_unit(
      CodeUnitKind::IfChain,
      format!("if chain ({} branches)", run.len()),
      body,
      line_start..=line_end,
      None,
    ) else {
      return;
    };
    let chain_fp = unit.fingerprint;
    self.units.push(unit);
    self.chained_ifs.extend(run.iter().filter_map(|expr| {
      if let syn::Expr::If(ref expr_if) = **expr {
        Some((from_ref(expr_if), chain_fp))
      } else {
        None
      }
    }));
  }
}

/// Define a loop visitor that extracts the loop body before recursing.
macro_rules! visit_loop_body {
  ($method:ident, $expr_ty:ty, $label:literal, $visitor:path) => {
    fn $method(&mut self, node: &'ast $expr_ty) {
      self.add_loop_body($label, &node.body);
      $visitor(self, node);
    }
  };
}

/// Define the module visitor shared by both extractors: recurse with the
/// `#[cfg(test)]` context propagated to everything inside the module.
macro_rules! visit_item_mod_with_test_context {
  () => {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
      let is_test = self.in_test_context || has_cfg_test_attr(&node.attrs);
      self.with_test_context(is_test, |visitor| {
        visit::visit_item_mod(visitor, node);
      });
    }
  };
}

impl<'ast> Visit<'ast> for SubUnitExtractor {
  fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
    let is_test = item_fn_is_test(self.in_test_context, node);
    self.with_parent(node.sig.ident.to_string(), is_test, |visitor| {
      visitor.visit_block(&node.block);
    });
  }

  fn visit_block(&mut self, node: &'ast syn::Block) {
    self.collect_if_chains(node);
    visit::visit_block(self, node);
  }

  visit_item_mod_with_test_context!();

  fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
    let naming = ImplNaming::of(node);
    let is_test = self.in_test_context || has_cfg_test_attr(&node.attrs);
    self.with_test_context(is_test, |visitor| {
      for method in impl_methods(node) {
        let full_name = naming.method_name(method);
        let in_test_context = visitor.in_test_context;
        visitor.with_parent(full_name, in_test_context, |scope| scope.visit_block(&method.block));
      }
    });
  }

  fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
    let owning_chain = self.chained_ifs.get(&from_ref(node)).copied();
    self.add_block_unit(CodeUnitKind::IfBranch, "if-then branch".to_owned(), &node.then_branch, owning_chain);
    if let Some(branch) = node.else_branch.as_ref() {
      let else_expr = &branch.1;
      let span = else_expr.span();
      self.add_expr_unit(
        CodeUnitKind::IfBranch,
        "if-else branch".to_owned(),
        else_expr,
        span.start().line..=span.end().line,
        owning_chain,
      );
    }
    visit::visit_expr_if(self, node);
  }

  fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
    for (idx, arm) in node.arms.iter().enumerate() {
      let span = arm.body.span();
      self.add_expr_unit(
        CodeUnitKind::MatchArm,
        format!("match arm {}", idx.saturating_add(1)),
        &arm.body,
        span.start().line..=span.end().line,
        None,
      );
    }
    visit::visit_expr_match(self, node);
  }

  visit_loop_body!(visit_expr_loop, syn::ExprLoop, "loop body", visit::visit_expr_loop);
  visit_loop_body!(visit_expr_while, syn::ExprWhile, "while body", visit::visit_expr_while);
  visit_loop_body!(visit_expr_for_loop, syn::ExprForLoop, "for body", visit::visit_expr_for_loop);

  fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
    if let syn::Expr::Block(ref block) = *node.body {
      self.add_block_unit(CodeUnitKind::Block, "closure body".to_owned(), &block.block, None);
    }
    visit::visit_expr_closure(self, node);
  }
}

/// Check if attributes contain `#[cfg(test)]`.
fn has_cfg_test_attr(attrs: &[syn::Attribute]) -> bool {
  attrs.iter().any(|attr| {
    if let syn::Meta::List(ref list) = attr.meta {
      list.path.is_ident("cfg")
        && matches!(*list.tokens.clone().into_iter().collect::<Vec<_>>().as_slice(),
        [TokenTree::Ident(ref ident)] if ident == "test")
    } else {
      false
    }
  })
}

/// True when a free `fn` is test code: marked `#[test]`, gated by
/// `#[cfg(test)]`, or already inside a test context.
fn item_fn_is_test(in_test_context: bool, node: &syn::ItemFn) -> bool {
  in_test_context || has_test_attr(&node.attrs) || has_cfg_test_attr(&node.attrs)
}

/// Extracts code units from a syn file by visiting the AST.
#[derive(Debug)]
struct CodeUnitExtractor {
  /// Native file identity retained by each unit.
  file:            PathBuf,
  /// Minimum combined signature and body size.
  min_node_count:  usize,
  /// Minimum inclusive source-line span.
  min_line_count:  usize,
  /// Complete admitted units in source visitation order.
  units:           Vec<CodeUnit>,
  /// Track if we're inside test code (`#[cfg(test)]` module/impl).
  in_test_context: bool,
}

impl CodeUnitExtractor {
  /// Prepare top-level extraction with source identity and both admission floors.
  #[allow(
    clippy::single_call_fn,
    reason = "Top-level extraction starts with explicit source and admission constraints and no inherited test context"
  )]
  const fn new(file: PathBuf, min_node_count: usize, min_line_count: usize) -> Self {
    Self {
      file,
      min_node_count,
      min_line_count,
      units: Vec::new(),
      in_test_context: false,
    }
  }

  /// Admit a normalized function-like unit while preserving its signature/body pairing.
  fn add_unit(
    &mut self,
    kind: CodeUnitKind,
    name: String,
    lines: RangeInclusive<usize>,
    normalized: (NormalizedNode, NormalizedNode),
    is_test: bool,
  ) {
    let (sig, body) = normalized;
    let node_count = normalizer::count_nodes(&sig).saturating_add(normalizer::count_nodes(&body));
    if node_count < self.min_node_count {
      return;
    }
    let line_start = *lines.start();
    let line_end = *lines.end();
    let line_count = line_end.saturating_sub(line_start).saturating_add(1);
    if self.min_line_count > 0 && line_count < self.min_line_count {
      return;
    }
    let fingerprint = Fingerprint::from_sig_and_body(&sig, &body);
    self.units.push(CodeUnit {
      suppressed: None,
      parent_chain: None,
      kind,
      name,
      file: self.file.clone(),
      line_start,
      line_end,
      signature: sig,
      body,
      fingerprint,
      node_count,
      parent_name: None,
      is_test,
    });
  }

  with_test_context_method!();
}

impl<'ast> Visit<'ast> for CodeUnitExtractor {
  fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
    let is_test = item_fn_is_test(self.in_test_context, node);

    let name = node.sig.ident.to_string();
    let line_start = node.sig.ident.span().start().line;
    let line_end = node.block.brace_token.span.close().end().line;
    let (sig, body) = normalizer::normalize_item_fn(node);
    self.add_unit(CodeUnitKind::Function, name, line_start..=line_end, (sig, body), is_test);

    // Continue visiting nested items (propagate test context)
    self.with_test_context(is_test, |visitor| {
      visit::visit_item_fn(visitor, node);
    });
  }

  visit_item_mod_with_test_context!();

  fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
    let is_test = self.in_test_context || has_cfg_test_attr(&node.attrs);
    let naming = ImplNaming::of(node);
    let kind = if naming.trait_name.is_some() {
      CodeUnitKind::TraitImplBlock
    } else {
      CodeUnitKind::Method
    };

    self.with_test_context(is_test, |visitor| {
      for method in impl_methods(node) {
        let full_name = naming.method_name(method);

        let line_start = method.sig.ident.span().start().line;
        let line_end = method.block.brace_token.span.close().end().line;

        let (sig, body) = normalizer::normalize_fn_like(&method.sig, &method.block);
        let in_test_context = visitor.in_test_context;
        visitor.add_unit(kind, full_name, line_start..=line_end, (sig, body), in_test_context);
      }
    });
  }

  fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
    let line_start = node.inputs_begin.span.start().line;
    let line_end = if let syn::Expr::Block(ref block) = *node.body {
      block.block.brace_token.span.close().end().line
    } else {
      let end = node.body.span().end().line;
      if end > 0 { end } else { line_start }
    };

    let normalized = normalizer::normalize_closure_expr(node);
    let node_count = normalizer::count_nodes(&normalized);
    let line_count = line_end.saturating_sub(line_start).saturating_add(1);
    if node_count >= self.min_node_count && (self.min_line_count == 0 || line_count >= self.min_line_count) {
      let name = format!("closure at {}:{}", self.file.display(), line_start);
      let fingerprint = Fingerprint::from_node(&normalized);
      self.units.push(CodeUnit {
        suppressed: None,
        parent_chain: None,
        kind: CodeUnitKind::Closure,
        name,
        file: self.file.clone(),
        line_start,
        line_end,
        signature: NormalizedNode::leaf(NodeKind::Opaque),
        body: normalized,
        fingerprint,
        node_count,
        parent_name: None,
        is_test: self.in_test_context,
      });
    }

    // Continue visiting nested closures
    visit::visit_expr_closure(self, node);
  }
}

/// Visit only implementation methods, sharing the native variant selection between extractors.
fn impl_methods(implementation: &syn::ItemImpl) -> impl Iterator<Item = &syn::ImplItemFn> {
  implementation.items.iter().filter_map(|member| {
    if let syn::ImplItem::Fn(ref method) = *member {
      Some(method)
    } else {
      None
    }
  })
}

/// Join a path's segment identifiers with `::`.
fn path_name(path: &syn::Path) -> String {
  path
    .segments
    .iter()
    .map(|segment| segment.ident.to_string())
    .collect::<Vec<_>>()
    .join("::")
}

/// Get a simple string representation of a type for naming.
#[allow(
  clippy::single_call_fn,
  reason = "Impl naming preserves native type-path names and the established label for non-path types"
)]
fn quote_type(ty: &syn::Type) -> String {
  if let syn::Type::Path(ref tp) = *ty {
    path_name(&tp.path)
  } else {
    "Unknown".to_owned()
  }
}

/// Method naming for one `impl` block, shared by both extractors.
#[derive(Debug)]
struct ImplNaming {
  /// Normalized display identity of the implementation's self type.
  type_name:  String,
  /// Trait identity for a trait implementation, absent for an inherent implementation.
  trait_name: Option<String>,
}

impl ImplNaming {
  /// Derive naming inputs from the native implementation header.
  fn of(node: &syn::ItemImpl) -> Self {
    Self {
      type_name:  quote_type(&node.self_ty),
      trait_name: node.trait_.as_ref().map(|implementation| path_name(&implementation.0)),
    }
  }

  /// `<Type as Trait>::method` for trait impls, `Type::method` otherwise.
  fn method_name(&self, method: &syn::ImplItemFn) -> String {
    let method_name = method.sig.ident.to_string();
    let type_name = &self.type_name;
    self.trait_name.as_ref().map_or_else(
      || format!("{type_name}::{method_name}"),
      |trait_name| format!("<{type_name} as {trait_name}>::{method_name}"),
    )
  }
}

/// Parse Rust source code and extract code units.
///
/// This is the core parsing entry point used by `RustAnalyzer`.
/// `path` is used for diagnostics and naming only.
/// Test code is always included but tagged with `is_test: true`;
/// filtering is handled by the caller.
///
/// # Errors
///
/// Returns the complete source and native diagnostic when `syn` rejects the input.
pub fn parse_source(path: &Path, source: &str, min_node_count: usize, min_line_count: usize) -> Result<Vec<CodeUnit>, RustParseError> {
  let file = parse_syn_file(path, source)?;

  let mut extractor = CodeUnitExtractor::new(path.to_path_buf(), min_node_count, min_line_count);
  extractor.visit_file(&file);

  Ok(extractor.units)
}

/// Parse Rust source code and extract nested sub-function units.
///
/// # Errors
///
/// Returns the complete source and native diagnostic when `syn` rejects the input.
#[allow(
  clippy::single_call_fn,
  reason = "The source parser owns sub-unit extraction and retains the native diagnostic before analyzer adaptation"
)]
pub fn parse_sub_units(path: &Path, source: &str, min_node_count: usize) -> Result<Vec<CodeUnit>, RustParseError> {
  let file = parse_syn_file(path, source)?;

  let mut extractor = SubUnitExtractor::new(path.to_path_buf(), min_node_count);
  extractor.visit_file(&file);

  Ok(extractor.units)
}

/// Parse Rust source while retaining the source identity, contents, and native diagnostic on
/// failure.
fn parse_syn_file(path: &Path, contents: &str) -> Result<syn::File, RustParseError> {
  syn::parse_file(contents).map_err(|source| RustParseError {
    input: SourceFile {
      path:     path.to_path_buf(),
      contents: contents.to_owned(),
    },
    source,
  })
}

/// Parse a single Rust file and extract code units.
///
/// This is a lower-level convenience function. Prefer using [`crate::RustAnalyzer`]
/// with [`dupes_core::analyze`] for the full pipeline.
///
/// # Errors
///
/// Returns the native read, UTF-8 decoding, or Rust parse failure with its available input.
#[allow(
  clippy::single_call_fn,
  reason = "One-file parsing retains the successful source read alongside extracted units or its native failure"
)]
pub fn parse_file(path: &Path, min_node_count: usize, min_line_count: usize) -> Result<ParsedRustFile, RustFileError> {
  let file = SourceFile::read(path)?;
  let units = parse_source(path, &file.contents, min_node_count, min_line_count)?;
  Ok(ParsedRustFile {
    file,
    units,
  })
}

/// Parse every requested file, retaining each success or failure in request order.
///
/// This is a lower-level convenience function. Prefer using [`crate::RustAnalyzer`]
/// with [`dupes_core::analyze`] for the full pipeline.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "The file-batch API owns ordered collection of every requested file's complete read and parse outcome."
)]
pub fn parse_files(paths: &[PathBuf], min_node_count: usize, min_line_count: usize) -> Vec<Result<ParsedRustFile, RustFileError>> {
  paths
    .iter()
    .map(|path| parse_file(path, min_node_count, min_line_count))
    .collect()
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::io;
  use std::path::Path;

  use dupes_core::code_unit::CodeUnit;
  use dupes_core::code_unit::CodeUnitKind;
  use dupes_core::source::SourceFile;
  use dupes_core::source::SourceReadError;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;

  use super::ParsedRustFile;
  use super::RustFileError;
  use super::RustParseError;
  use super::parse_file;
  use super::parse_files;
  use super::parse_source;
  use super::parse_sub_units;

  /// Native setup failures or a complete parser outcome that failed an expectation.
  #[derive(Debug, thiserror::Error)]
  enum ParserTestFailure {
    /// A fixture could not be created or written.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Source intended to be valid was rejected by the native parser.
    #[error(transparent)]
    Parse(#[from] RustParseError),
    /// An assertion failed with all extracted units retained.
    #[error("parsed units did not satisfy the expected contract: {source}; input: {input:?}; units: {units:?}")]
    Units {
      /// Complete in-memory source supplied under the fixture's parser identity.
      input:  Box<SourceFile>,
      /// Complete units produced by the parser.
      units:  Vec<CodeUnit>,
      /// Failed behavioral expectation.
      source: Box<ConditionFailure>,
    },
    /// Declaration extraction did not preserve its expected identities and test contexts.
    #[error("declaration identity expectation failed: {source}; input: {input:?}; expected: {expected:?}; units: {units:?}")]
    Identities {
      /// Complete original source and parser path.
      input:    Box<SourceFile>,
      /// Independently specified kind, name, and test context for every admitted declaration.
      expected: Vec<(CodeUnitKind, String, bool)>,
      /// Complete units produced by parsing.
      units:    Vec<CodeUnit>,
      /// Native assertion failure.
      source:   Box<ConditionFailure>,
    },
    /// Function fingerprints did not preserve the declared equivalence relationship.
    #[error("function fingerprint expectation failed: {source}; input: {input:?}; expected equal: {equal}; units: {units:?}")]
    Fingerprints {
      /// Complete original source and parser path.
      input:  Box<SourceFile>,
      /// Whether the two function bodies should share a normalized fingerprint.
      equal:  bool,
      /// Complete parser output, including both normalized signatures and bodies.
      units:  Vec<CodeUnit>,
      /// Native assertion failure.
      source: ConditionFailure,
    },
    /// An assertion failed with every attempted file outcome retained.
    #[error("file parsing did not satisfy the expected contract: {source}; outcomes: {outcomes:?}")]
    Files {
      /// Ordered successful and failed file operations.
      outcomes: Vec<Result<ParsedRustFile, RustFileError>>,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
  }

  /// Parse an in-memory fixture with one stable source identity.
  fn parse_test_source(code: &str, min_nodes: usize) -> Result<Vec<CodeUnit>, RustParseError> {
    parse_source(Path::new("test.rs"), code, min_nodes, 0)
  }

  /// Keep the complete in-memory input and all units when a contract assertion fails.
  fn check_units(
    code: &str,
    units: Vec<CodeUnit>,
    check: impl FnOnce(&[CodeUnit]) -> Result<(), ConditionFailure>,
  ) -> Result<(), ParserTestFailure> {
    check(&units).map_err(|source| ParserTestFailure::Units {
      input: Box::new(SourceFile {
        path:     Path::new("test.rs").to_path_buf(),
        contents: code.to_owned(),
      }),
      units,
      source: Box::new(source),
    })
  }

  /// Exercise the nested-source parser with the same retained input as its behavioral assertion.
  fn check_sub_units(code: &str, check: impl FnOnce(&[CodeUnit]) -> Result<(), ConditionFailure>) -> Result<(), ParserTestFailure> {
    check_units(code, parse_sub_units(Path::new("test.rs"), code, 1)?, check)
  }

  /// Require the complete ordered declaration identities while leaving suppression to the pipeline.
  fn check_declarations(code: &str, expected: &[(CodeUnitKind, &str, bool)]) -> Result<(), ParserTestFailure> {
    let input = SourceFile {
      path:     Path::new("test.rs").to_path_buf(),
      contents: code.to_owned(),
    };
    let units = parse_source(&input.path, &input.contents, 1, 0)?;
    ensure(
      units
        .iter()
        .map(|unit| (unit.kind, unit.name.as_str(), unit.is_test))
        .eq(expected.iter().copied())
        && units.iter().all(|unit| unit.suppressed.is_none() && unit.file == input.path),
      "declaration extraction preserves source order, complete names, kinds, test contexts, and file identity before pipeline tagging",
    )
    .map(drop)
    .map_err(|source| ParserTestFailure::Identities {
      input: Box::new(input),
      expected: expected
        .iter()
        .map(|&(kind, name, is_test)| (kind, name.to_owned(), is_test))
        .collect(),
      units,
      source: Box::new(source),
    })
  }

  /// Keep native file successes and failures together when a contract assertion fails.
  fn check_files(
    outcomes: Vec<Result<ParsedRustFile, RustFileError>>,
    check: impl FnOnce(&[Result<ParsedRustFile, RustFileError>]) -> Result<(), ConditionFailure>,
  ) -> Result<(), ParserTestFailure> {
    check(&outcomes).map_err(|source| ParserTestFailure::Files {
      outcomes,
      source,
    })
  }

  #[test]
  fn extracts_free_inherent_and_trait_function_identities() -> Result<(), ParserTestFailure> {
    let functions = r#"
            fn foo(x: i32) -> i32 {
                let y = x + 1;
                y * 2
            }
            fn bar() {
                println!("hello");
            }
            "#;
    let inherent = "
            struct Foo;
            impl Foo {
                fn bar(&self) -> i32 {
                    42
                }
                fn baz(&mut self, val: i32) {
                    let _ = val + 1;
                }
            }
            ";
    let trait_impl = "
            struct Foo;
            trait MyTrait {
                fn do_thing(&self) -> i32;
            }
            impl MyTrait for Foo {
                fn do_thing(&self) -> i32 {
                    let x = 42;
                    x + 1
                }
            }
            ";
    check_declarations(functions, &[
      (CodeUnitKind::Function, "foo", false),
      (CodeUnitKind::Function, "bar", false),
    ])?;
    check_declarations(inherent, &[
      (CodeUnitKind::Method, "Foo::bar", false),
      (CodeUnitKind::Method, "Foo::baz", false),
    ])?;
    check_declarations(trait_impl, &[(CodeUnitKind::TraitImplBlock, "<Foo as MyTrait>::do_thing", false)])
  }

  #[test]
  fn respects_min_node_count() -> Result<(), ParserTestFailure> {
    let source = "
            fn tiny() -> i32 { 1 }
            fn bigger(x: i32) -> i32 {
                let a = x + 1;
                let b = a * 2;
                a + b
            }
            ";
    let units_low = parse_test_source(source, 1)?;
    let expected_high = units_low
      .iter()
      .filter(|unit| unit.node_count >= 20)
      .cloned()
      .collect::<Vec<_>>();
    check_units(source, units_low, |parsed| {
      ensure(parsed.len() == 2, "the lower node floor admits both functions").map(drop)?;
      ensure(
        parsed.iter().any(|unit| unit.node_count < 20),
        "the higher floor excludes an actually smaller function",
      )
      .map(drop)
    })?;
    check_units(source, parse_test_source(source, 20)?, |parsed| {
      ensure(
        parsed == expected_high,
        "the higher node floor retains exactly the eligible complete units",
      )
      .map(drop)
    })
  }

  #[test]
  fn function_fingerprints_ignore_renaming_and_distinguish_behavior() -> Result<(), ParserTestFailure> {
    let renamed = "
            fn foo(x: i32) -> i32 {
                let y = x + 1;
                y * 2
            }
            fn bar(a: i32) -> i32 {
                let b = a + 1;
                b * 2
            }
            ";
    let different = "
            fn add(x: i32) -> i32 {
                x + 1
            }
            fn mul(x: i32) -> i32 {
                x * 2
            }
            ";
    for (code, equal) in [(renamed, true), (different, false)] {
      let input = SourceFile {
        path:     Path::new("test.rs").to_path_buf(),
        contents: code.to_owned(),
      };
      let units = parse_source(&input.path, &input.contents, 1, 0)?;
      ensure(
        matches!(units.as_slice(), [first, second]
          if (first.kind, second.kind) == (CodeUnitKind::Function, CodeUnitKind::Function)
            && (first.fingerprint == second.fingerprint) == equal),
        "renaming bindings preserves function identity while different arithmetic behavior changes it",
      )
      .map(drop)
      .map_err(|source| ParserTestFailure::Fingerprints {
        input: Box::new(input),
        equal,
        units,
        source,
      })?;
    }
    Ok(())
  }

  #[test]
  fn handles_parse_errors_gracefully() -> Result<(), ParserTestFailure> {
    let tmp = TempDir::new()?;
    let file = tmp.path().join("broken.rs");
    let contents = "fn broken( { }";
    fs::write(&file, contents)?;
    check_files(vec![parse_file(&file, 1, 0)], |outcomes| {
      let [Err(RustFileError::Parse(ref failure))] = *outcomes else {
        return ensure(false, "invalid Rust must return its typed parse failure").map(drop);
      };
      ensure(
        failure.input.path == file && failure.input.contents == contents && failure.source.span().start().line == 1,
        "the parse failure retains the source identity, complete contents, and native diagnostic span",
      )
      .map(drop)
    })
  }

  #[test]
  fn parse_files_preserves_successes_and_native_failures_in_order() -> Result<(), ParserTestFailure> {
    let tmp = TempDir::new()?;
    let good = tmp.path().join("good.rs");
    let bad = tmp.path().join("bad.rs");
    let invalid_utf8 = tmp.path().join("bytes.rs");
    let missing = tmp.path().join("missing.rs");
    let last = tmp.path().join("last.rs");
    let good_source = "fn good() { let count = 1; }";
    let bad_source = "fn bad( {";
    let last_source = "fn last() { let total = 2; }";
    for (path, contents) in [(&good, good_source), (&bad, bad_source), (&last, last_source)] {
      fs::write(path, contents)?;
    }
    let invalid_bytes = [b'f', b'n', b' ', 0xff];
    fs::write(&invalid_utf8, invalid_bytes)?;
    check_files(
      parse_files(
        &[good.clone(), bad.clone(), invalid_utf8.clone(), missing.clone(), last.clone()],
        1,
        0,
      ),
      |outcomes| {
        let [
          Ok(ref first),
          Err(RustFileError::Parse(ref syntax)),
          Err(RustFileError::Read(SourceReadError::Utf8 {
            path: ref utf8_path,
            source: ref utf8,
          })),
          Err(RustFileError::Read(SourceReadError::Read {
            path: ref missing_path,
            source: ref read,
          })),
          Ok(ref final_file),
        ] = *outcomes
        else {
          return ensure(false, "retain the five file outcomes in request order and continue after failures").map(drop);
        };
        ensure(
          first.file.path == good
            && first.file.contents == good_source
            && first.units.iter().map(|unit| unit.name.as_str()).collect::<Vec<_>>() == ["good"]
            && final_file.file.path == last
            && final_file.file.contents == last_source
            && final_file.units.iter().map(|unit| unit.name.as_str()).collect::<Vec<_>>() == ["last"],
          "retain complete source reads and extracted units on both sides of the failures",
        )
        .map(drop)?;
        ensure(
          syntax.input.path == bad && syntax.input.contents == bad_source && syntax.source.span().start().line == 1,
          "retain the original parse failure and rejected source",
        )
        .map(drop)?;
        ensure(
          utf8_path == &invalid_utf8 && utf8.as_bytes() == invalid_bytes,
          "retain every byte from the file that is not valid UTF-8",
        )
        .map(drop)?;
        ensure(
          missing_path == &missing && read.kind() == io::ErrorKind::NotFound && read.raw_os_error().is_some(),
          "retain the native missing-file failure with its operating-system error code",
        )
        .map(drop)
      },
    )
  }

  #[test]
  fn code_unit_has_line_numbers() -> Result<(), ParserTestFailure> {
    let code = "
fn first() {
    let x = 1;
}

fn second() {
    let y = 2;
}
            ";
    check_units(code, parse_test_source(code, 1)?, |parsed| {
      ensure(
        parsed
          .iter()
          .map(|unit| (unit.name.as_str(), unit.line_start, unit.line_end))
          .collect::<Vec<_>>()
          == [("first", 2, 4), ("second", 6, 8)],
        "retain precise inclusive function spans",
      )
      .map(drop)
    })
  }

  #[test]
  fn code_unit_kind_display() -> Result<(), ConditionFailure> {
    ensure(
      [CodeUnitKind::Function, CodeUnitKind::Method, CodeUnitKind::Closure].map(|kind| kind.to_string())
        == ["function", "method", "closure"],
      "render the public function, method, and closure labels",
    )
    .map(drop)
  }

  #[test]
  fn closures_remain_units_before_pipeline_classification() -> Result<(), ParserTestFailure> {
    for code in [
      "
            fn foo() {
                let f = |x: i32, y: i32| {
                    let sum = x + y;
                    let product = x * y;
                    sum + product
                };
            }
            ",
      "
            fn sort_groups(groups: &mut Vec<Group>) {
                groups.sort_by(|a, b| start_key(a).cmp(&start_key(b)));
            }
            ",
      r#"
            fn collect_names(paths: &[Item]) -> Vec<String> {
                paths
                    .iter()
                    .map(|item| {
                        let name = item.ident.to_string();
                        format!("{name}::suffix")
                    })
                    .collect()
            }
            "#,
    ] {
      check_units(code, parse_test_source(code, 1)?, |parsed| {
        ensure(
          parsed.iter().map(|unit| (unit.kind, unit.suppressed)).collect::<Vec<_>>()
            == [(CodeUnitKind::Function, None), (CodeUnitKind::Closure, None)],
          "arithmetic, comparator, and structured closures remain separate units with their containing function before pipeline tagging",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  #[test]
  fn parse_sub_units_extracts_if_chain_with_precise_span() -> Result<(), ParserTestFailure> {
    // Consecutive option-to-field setter branches are one coherent
    // chain unit, not many tiny if-branch fragments.
    check_sub_units(
      "
            fn apply(config: &mut Config, overrides: &Overrides) {
                if let Some(width_limit) = overrides.width_limit {
                    config.width_limit = width_limit;
                }
                if let Some(depth_limit) = overrides.depth_limit {
                    config.depth_limit = depth_limit;
                }
                if let Some(score_limit) = overrides.score_limit {
                    config.score_limit = score_limit;
                }
            }
            ",
      |parsed| {
        let [ref chain, ref first, ref second, ref third] = *parsed else {
          return ensure(false, "extract one complete chain and all three constituent branches").map(drop);
        };
        ensure(
          (chain.kind, chain.name.as_str(), chain.line_start, chain.line_end) == (CodeUnitKind::IfChain, "if chain (3 branches)", 3, 11),
          "the chain spans all consecutive branches",
        )
        .map(drop)?;
        ensure(
          [first, second, third].iter().all(|branch| {
            branch.kind == CodeUnitKind::IfBranch
              && branch.parent_chain == Some(chain.fingerprint)
              && branch.parent_name.as_deref() == Some("apply")
          }),
          "retain every branch with the owning chain fingerprint and function identity",
        )
        .map(drop)
      },
    )
  }

  #[test]
  fn parse_sub_units_keeps_single_if_branch_extraction() -> Result<(), ParserTestFailure> {
    check_sub_units(
      "
            fn single(config: &mut Config, value: Option<usize>) {
                if let Some(value) = value {
                    config.min_nodes = value;
                }
                let _ = config;
            }
            ",
      |parsed| {
        ensure(
          parsed.iter().map(|unit| (unit.kind, unit.parent_chain)).collect::<Vec<_>>() == [(CodeUnitKind::IfBranch, None)],
          "a standalone branch remains extracted without an owning chain",
        )
        .map(drop)
      },
    )
  }

  #[test]
  fn identical_if_chains_share_fingerprints_across_functions() -> Result<(), ParserTestFailure> {
    check_sub_units(
      "
            fn apply_first(config: &mut Config, overrides: &Overrides) {
                if let Some(node_quota) = overrides.node_quota {
                    config.node_quota = node_quota;
                }
                if let Some(line_quota) = overrides.line_quota {
                    config.line_quota = line_quota;
                }
            }
            fn apply_second(target: &mut Config, source: &Source) {
                if let Some(node_floor) = source.node_floor {
                    target.node_floor = node_floor;
                }
                if let Some(line_floor) = source.line_floor {
                    target.line_floor = line_floor;
                }
            }
            ",
      |parsed| {
        let chains = parsed
          .iter()
          .filter(|unit| unit.kind == CodeUnitKind::IfChain)
          .collect::<Vec<_>>();
        let [first, second] = *chains.as_slice() else {
          return ensure(false, "extract both renamed chains").map(drop);
        };
        ensure(
          first.fingerprint == second.fingerprint
            && (first.parent_name.as_deref(), second.parent_name.as_deref()) == (Some("apply_first"), Some("apply_second")),
          "chain fingerprints survive renaming while parent identities remain distinct",
        )
        .map(drop)
      },
    )
  }

  #[test]
  fn parse_sub_units_extracts_each_loop_body_kind() -> Result<(), ParserTestFailure> {
    check_sub_units(
      "
            fn loops(xs: Vec<i32>) {
                loop {
                    break;
                }
                while xs.is_empty() {
                    break;
                }
                for x in xs {
                    let _ = x;
                }
            }
            ",
      |parsed| {
        ensure(
          parsed.iter().map(|unit| (unit.kind, unit.name.as_str())).collect::<Vec<_>>()
            == [
              (CodeUnitKind::LoopBody, "loop body"),
              (CodeUnitKind::LoopBody, "while body"),
              (CodeUnitKind::LoopBody, "for body"),
            ],
          "extract loop, while, and for bodies in source order",
        )
        .map(drop)
      },
    )
  }

  #[test]
  fn min_line_count_filters_short_functions() -> Result<(), ParserTestFailure> {
    let code = "
fn short(x: i32) -> i32 {
    x + 1
}

fn longer(x: i32) -> i32 {
    let a = x + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    a + b + c + d
}
        ";
    let tmp = TempDir::new()?;
    let file = tmp.path().join("test.rs");
    fs::write(&file, code)?;
    check_files(vec![parse_file(&file, 1, 0), parse_file(&file, 1, 5)], |outcomes| {
      let [Ok(ref unfiltered), Ok(ref filtered)] = *outcomes else {
        return ensure(false, "both file parses must succeed").map(drop);
      };
      ensure(
        unfiltered.file.path == file && filtered.file.path == file && unfiltered.file.contents == code && filtered.file.contents == code,
        "both runs retain the complete file read",
      )
      .map(drop)?;
      let [ref short, ref longer] = *unfiltered.units.as_slice() else {
        return ensure(false, "the unrestricted run must retain both functions").map(drop);
      };
      ensure(
        (short.name.as_str(), short.line_start, short.line_end) == ("short", 2, 4)
          && (longer.name.as_str(), longer.line_start, longer.line_end) == ("longer", 6, 12)
          && filtered.units.as_slice() == [longer.clone()],
        "the five-line floor removes the short function and preserves the complete longer unit",
      )
      .map(drop)
    })
  }

  #[test]
  fn test_attributes_mark_their_scope_and_restore_sibling_context() -> Result<(), ParserTestFailure> {
    let attributed = "
            #[test]
            fn my_test() {}
            fn normal() {}
            ";
    let configured = "
            #[cfg(test)]
            mod tests { fn helper() {} }
            #[cfg(unix)]
            mod normal { fn production() {} }
            ";
    for (code, tagged, ordinary) in [(attributed, "my_test", "normal"), (configured, "helper", "production")] {
      check_declarations(code, &[
        (CodeUnitKind::Function, tagged, true),
        (CodeUnitKind::Function, ordinary, false),
      ])?;
    }
    Ok(())
  }

  #[test]
  fn executable_functions_inherit_only_their_own_test_context() -> Result<(), ParserTestFailure> {
    let production = "
            fn production(x: i32) -> i32 {
                let y = x + 1;
                y * 2
            }
";
    let attributed = [
      production,
      "
            #[test]
            fn my_test() {
                let x = 1;
                let y = x + 1;
                assert_eq!(y, 2);
            }
        ",
    ]
    .concat();
    let module = [
      production,
      "
            #[cfg(test)]
            mod tests {
                fn helper(x: i32) -> i32 {
                    let y = x + 1;
                    y * 2
                }
            }
        ",
    ]
    .concat();
    let implementation = "
            struct Foo;

            impl Foo {
                fn production(&self) -> i32 {
                    let x = 42;
                    x + 1
                }
            }

            #[cfg(test)]
            impl Foo {
                fn test_helper(&self) -> i32 {
                    let x = 42;
                    x + 1
                }
            }
        ";
    for (code, kind, ordinary, tagged) in [
      (attributed.as_str(), CodeUnitKind::Function, "production", "my_test"),
      (module.as_str(), CodeUnitKind::Function, "production", "helper"),
      (implementation, CodeUnitKind::Method, "Foo::production", "Foo::test_helper"),
    ] {
      check_declarations(code, &[(kind, ordinary, false), (kind, tagged, true)])?;
    }
    Ok(())
  }

  #[test]
  fn parse_source_works() -> Result<(), ParserTestFailure> {
    let path = Path::new("test.rs");
    let source = "fn foo(x: i32) -> i32 { x + 1 }";
    check_units(source, parse_source(path, source, 1, 0)?, |parsed| {
      ensure(
        parsed
          .iter()
          .map(|unit| (unit.name.as_str(), unit.file.as_path()))
          .collect::<Vec<_>>()
          == [("foo", path)],
        "parse in-memory source with its supplied source identity",
      )
      .map(drop)
    })
  }

  #[test]
  fn setters_validators_and_accessors_remain_units_for_pipeline_tagging() -> Result<(), ParserTestFailure> {
    let setters = "
            struct Builder { resolver: Option<u32>, detector: Option<u32> }
            impl Builder {
                pub fn with_resolver(mut self, resolver: u32) -> Self {
                    self.resolver = Some(resolver);
                    self
                }
                pub fn with_detector(mut self, detector: u32) -> Self {
                    self.detector = Some(detector);
                    self
                }
            }
            ";
    let validator = r#"
            struct Builder { port: u16 }
            impl Builder {
                pub fn with_port(mut self, port: u16) -> Result<Self, String> {
                    if port == 0 {
                        return Err("port must be nonzero".to_string());
                    }
                    self.port = port;
                    Ok(self)
                }
            }
            "#;
    let accessors = "
            struct Stats { exact: usize, near: usize }
            impl Stats {
                pub fn exact_percent(&self) -> f64 {
                    self.percent_of(self.exact)
                }
                pub fn near_percent(&self) -> f64 {
                    self.percent_of(self.near)
                }
            }
            ";
    check_declarations(setters, &[
      (CodeUnitKind::Method, "Builder::with_resolver", false),
      (CodeUnitKind::Method, "Builder::with_detector", false),
    ])?;
    check_declarations(validator, &[(CodeUnitKind::Method, "Builder::with_port", false)])?;
    check_declarations(accessors, &[
      (CodeUnitKind::Method, "Stats::exact_percent", false),
      (CodeUnitKind::Method, "Stats::near_percent", false),
    ])
  }

  #[test]
  fn constant_binding_wrappers_remain_units() -> Result<(), ParserTestFailure> {
    // `fixture_path("cargo-dupes", name)`-style named specializations
    // stay reportable: the wrapper binds a constant.
    let code = r#"
            fn rust_fixture_path(name: &str) -> PathBuf {
                fixture_path("cargo-dupes", name)
            }
            "#;
    check_declarations(code, &[(CodeUnitKind::Function, "rust_fixture_path", false)])
  }

  #[test]
  fn behavior_bearing_small_functions_remain_units() -> Result<(), ParserTestFailure> {
    let code = "
            fn clamp_total(total: i32) -> i32 {
                if total > 100 { 100 } else { total }
            }
            ";
    check_declarations(code, &[(CodeUnitKind::Function, "clamp_total", false)])
  }
}
