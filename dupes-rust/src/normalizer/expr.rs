//! Expression and statement normalization with stable child ordering.

use dupes_core::node::NodeKind;
use dupes_core::node::NormalizationContext;
use dupes_core::node::NormalizedNode;
use dupes_core::node::PlaceholderKind;

use super::helpers::PlaceholderNodeRole;
use super::helpers::member_to_string;
use super::helpers::normalize_bin_op;
use super::helpers::normalize_list;
use super::helpers::normalize_lit;
use super::helpers::normalize_macro;
use super::helpers::normalize_un_op;
use super::helpers::one_child_node;
use super::helpers::path_node_from_segments;
use super::helpers::path_segment_nodes;
use super::helpers::placeholder_node;
use super::helpers::reference_node;
use super::pat::normalize_pat;
use super::pat::normalize_type;

/// Normalize an expression, erasing identifiers and literal values.
pub fn normalize_expr(expr: &syn::Expr, ctx: &mut NormalizationContext) -> NormalizedNode {
  match *expr {
    // BinaryOp -> [left, right]
    syn::Expr::Binary(ref eb) => NormalizedNode::with_children(NodeKind::BinaryOp(normalize_bin_op(&eb.op)), vec![
      normalize_expr(&eb.left, ctx),
      normalize_expr(&eb.right, ctx),
    ]),
    // UnaryOp -> [operand]
    syn::Expr::Unary(ref eu) => {
      NormalizedNode::with_children(NodeKind::UnaryOp(normalize_un_op(eu.op)), vec![normalize_expr(&eu.expr, ctx)])
    }
    // Call -> [func, arg0, arg1, ...]
    syn::Expr::Call(ref ec) => {
      let mut children = vec![normalize_expr(&ec.func, ctx)];
      children.extend(ec.args.iter().map(|argument| normalize_expr(argument, ctx)));
      NormalizedNode::with_children(NodeKind::Call, children)
    }
    // MethodCall -> [receiver, method, arg0, ...]
    // The method name is preserved as a Token leaf: which method runs is
    // behavior, not naming, so `x.is_ascii_alphabetic()` must never
    // fingerprint equal to `x.is_ascii_alphanumeric()`.
    syn::Expr::MethodCall(ref emc) => normalize_method_call(emc, ctx),
    // Closure -> [body, param0, param1, ...]
    syn::Expr::Closure(ref ec) => {
      let mut children = vec![normalize_expr(&ec.body, ctx)];
      children.extend(ec.inputs.iter().map(|pattern| normalize_pat(pattern, ctx)));
      NormalizedNode::with_children(NodeKind::Closure, children)
    }
    // Return -> [] or [value]
    syn::Expr::Return(ref er) => node_with_optional_expr(NodeKind::Return, er.expr.as_deref(), ctx),
    // Break -> [] or [value]
    syn::Expr::Break(ref eb) => node_with_optional_expr(NodeKind::Break, eb.expr.as_deref(), ctx),
    syn::Expr::Continue(_) => NormalizedNode::leaf(NodeKind::Continue),
    // Assign -> [left, right]
    syn::Expr::Assign(ref ea) => normalize_expr_pair(NodeKind::Assign, &ea.left, &ea.right, ctx),
    // Reference -> [expr]
    syn::Expr::Reference(ref er) => reference_node(er.mutability.as_ref(), PlaceholderNodeRole::Expr, &*er.expr, ctx, normalize_expr),
    // Cast -> [expr, ty]
    syn::Expr::Cast(ref ec) => {
      NormalizedNode::with_children(NodeKind::Cast, vec![normalize_expr(&ec.expr, ctx), normalize_type(&ec.ty, ctx)])
    }
    // Await -> [expr]
    syn::Expr::Await(ref ea) => one_child_node(NodeKind::Await, &*ea.base, ctx, normalize_expr),
    // Try -> [expr]
    syn::Expr::Try(ref et) => one_child_node(NodeKind::Try, &*et.expr, ctx, normalize_expr),
    // If -> [condition, then_branch, else_or_None]
    syn::Expr::If(ref ei) => NormalizedNode::with_children(NodeKind::If, vec![
      normalize_expr(&ei.cond, ctx),
      normalize_block(&ei.then_branch, ctx),
      NormalizedNode::opt(ei.else_branch.as_ref().map(|branch| normalize_expr(&branch.1, ctx))),
    ]),
    // Match -> [expr, arm0, arm1, ...]
    // Each arm is MatchArm -> [pattern, guard_or_None, body]
    syn::Expr::Match(ref em) => normalize_match(em, ctx),
    // Loop -> [body]
    syn::Expr::Loop(ref el) => one_child_node(NodeKind::Loop, &el.body, ctx, normalize_block),
    // While -> [condition, body]
    syn::Expr::While(ref ew) => {
      NormalizedNode::with_children(NodeKind::While, vec![normalize_expr(&ew.cond, ctx), normalize_block(&ew.body, ctx)])
    }
    // ForLoop -> [pat, iter, body]
    syn::Expr::ForLoop(ref ef) => NormalizedNode::with_children(NodeKind::ForLoop, vec![
      normalize_pat(&ef.pat, ctx),
      normalize_expr(&ef.expr, ctx),
      normalize_block(&ef.body, ctx),
    ]),
    syn::Expr::Block(ref eb) => normalize_block(&eb.block, ctx),
    // Paren -> [expr]
    syn::Expr::Paren(ref ep) => one_child_node(NodeKind::Paren, &*ep.expr, ctx, normalize_expr),
    // LetExpr -> [pat, expr]
    syn::Expr::Let(ref el) => {
      NormalizedNode::with_children(NodeKind::LetExpr, vec![normalize_pat(&el.pat, ctx), normalize_expr(&el.expr, ctx)])
    }
    syn::Expr::Macro(ref em) => normalize_macro(&em.mac, ctx),
    syn::Expr::Group(ref eg) => normalize_expr(&eg.expr, ctx),
    syn::Expr::Unsafe(ref eu) => normalize_block(&eu.block, ctx),
    syn::Expr::Const(ref ec) => normalize_block(&ec.block, ctx),
    syn::Expr::Array(_)
    | syn::Expr::Async(_)
    | syn::Expr::Field(_)
    | syn::Expr::Index(_)
    | syn::Expr::Infer(_)
    | syn::Expr::Lit(_)
    | syn::Expr::Path(_)
    | syn::Expr::Range(_)
    | syn::Expr::RawAddr(_)
    | syn::Expr::Repeat(_)
    | syn::Expr::Struct(_)
    | syn::Expr::TryBlock(_)
    | syn::Expr::Tuple(_)
    | syn::Expr::Verbatim(_)
    | syn::Expr::Yield(_)
    | _ => normalize_data_expr(expr, ctx),
  }
}

/// Normalize data construction and access after operator, call, and control-flow expressions.
#[allow(
  clippy::single_call_fn,
  reason = "data construction and access own their content layouts separately from expression execution and control flow"
)]
fn normalize_data_expr(expr: &syn::Expr, ctx: &mut NormalizationContext) -> NormalizedNode {
  match *expr {
    syn::Expr::Lit(ref literal) => normalize_lit(&literal.lit),
    syn::Expr::Path(ref path) => normalize_expr_path(&path.path, ctx),
    // FieldAccess -> [base, field]
    syn::Expr::Field(ref field) => NormalizedNode::with_children(NodeKind::FieldAccess, vec![
      normalize_expr(&field.base, ctx),
      placeholder_node(
        ctx,
        &member_to_string(&field.member),
        PlaceholderKind::Variable,
        PlaceholderNodeRole::Expr,
      ),
    ]),
    // Index -> [base, index]
    syn::Expr::Index(ref index) => normalize_expr_pair(NodeKind::Index, &index.expr, &index.index, ctx),
    syn::Expr::Tuple(ref tuple) => normalize_list(NodeKind::Tuple, &tuple.elems, ctx, normalize_expr),
    syn::Expr::Array(ref array) => normalize_list(NodeKind::Array, &array.elems, ctx, normalize_expr),
    // Repeat -> [elem, len]
    syn::Expr::Repeat(ref repeat) => normalize_expr_pair(NodeKind::Repeat, &repeat.expr, &repeat.len, ctx),
    // StructInit -> [rest_or_None, field0, field1, ...]
    syn::Expr::Struct(ref structure) => normalize_struct(structure, ctx),
    // Range -> [from_or_None, to_or_None]
    syn::Expr::Range(ref range) => node_with_optional_expr_pair(NodeKind::Range, range.start.as_deref(), range.end.as_deref(), ctx),
    syn::Expr::Assign(_)
    | syn::Expr::Async(_)
    | syn::Expr::Await(_)
    | syn::Expr::Binary(_)
    | syn::Expr::Block(_)
    | syn::Expr::Break(_)
    | syn::Expr::Call(_)
    | syn::Expr::Cast(_)
    | syn::Expr::Closure(_)
    | syn::Expr::Const(_)
    | syn::Expr::Continue(_)
    | syn::Expr::ForLoop(_)
    | syn::Expr::Group(_)
    | syn::Expr::If(_)
    | syn::Expr::Infer(_)
    | syn::Expr::Let(_)
    | syn::Expr::Loop(_)
    | syn::Expr::Macro(_)
    | syn::Expr::Match(_)
    | syn::Expr::MethodCall(_)
    | syn::Expr::Paren(_)
    | syn::Expr::RawAddr(_)
    | syn::Expr::Reference(_)
    | syn::Expr::Return(_)
    | syn::Expr::Try(_)
    | syn::Expr::TryBlock(_)
    | syn::Expr::Unary(_)
    | syn::Expr::Unsafe(_)
    | syn::Expr::Verbatim(_)
    | syn::Expr::While(_)
    | syn::Expr::Yield(_)
    | _ => NormalizedNode::leaf(NodeKind::Opaque),
  }
}

/// Keep the method token between receiver and arguments because method identity is behavior.
#[allow(
  clippy::single_call_fn,
  reason = "method calls have a fingerprint-sensitive layout that preserves the called method separately from argument placeholders"
)]
fn normalize_method_call(method: &syn::ExprMethodCall, ctx: &mut NormalizationContext) -> NormalizedNode {
  let mut children = vec![
    normalize_expr(&method.receiver, ctx),
    NormalizedNode::leaf(NodeKind::Token(method.method.to_string())),
  ];
  children.extend(method.args.iter().map(|argument| normalize_expr(argument, ctx)));
  NormalizedNode::with_children(NodeKind::MethodCall, children)
}

/// Normalize struct fields after the optional update-base sentinel.
#[allow(
  clippy::single_call_fn,
  reason = "struct construction owns the ordering of its update base, field placeholders, and field expressions"
)]
fn normalize_struct(structure: &syn::ExprStruct, ctx: &mut NormalizationContext) -> NormalizedNode {
  let mut children = vec![NormalizedNode::opt(
    structure.rest.as_ref().map(|expression| normalize_expr(expression, ctx)),
  )];
  children.extend(structure.fields.iter().map(|field| {
    let field_idx = ctx.placeholder(&member_to_string(&field.member), PlaceholderKind::Variable);
    NormalizedNode::with_children(NodeKind::FieldValue, vec![
      NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, field_idx)),
      normalize_expr(&field.expr, ctx),
    ])
  }));
  NormalizedNode::with_children(NodeKind::StructInit, children)
}

/// Project `syn` guard patterns into the established pattern/guard/body match-arm layout.
#[allow(
  clippy::single_call_fn,
  reason = "the match adapter preserves existing guard slots and placeholder ordering across the syn AST version change"
)]
fn normalize_match(expression: &syn::ExprMatch, ctx: &mut NormalizationContext) -> NormalizedNode {
  let mut children = vec![normalize_expr(&expression.expr, ctx)];
  children.extend(expression.arms.iter().map(|arm| {
    let (pattern, guard) = if let syn::Pat::Guard(ref guarded) = arm.pat {
      (guarded.pat.as_ref(), Some(guarded.guard.as_ref()))
    } else {
      (&arm.pat, None)
    };
    NormalizedNode::with_children(NodeKind::MatchArm, vec![
      normalize_pat(pattern, ctx),
      NormalizedNode::opt(guard.map(|condition| normalize_expr(condition, ctx))),
      normalize_expr(&arm.body, ctx),
    ])
  }));
  NormalizedNode::with_children(NodeKind::Match, children)
}

/// Normalize a statement, preserving trailing-semicolon significance.
#[allow(
  clippy::single_call_fn,
  reason = "Statement normalization owns binding slots and semicolon significance within blocks"
)]
pub fn normalize_stmt(stmt: &syn::Stmt, ctx: &mut NormalizationContext) -> NormalizedNode {
  match *stmt {
    // LetBinding -> [pattern, type_or_None, init_or_None, diverge_or_None]
    syn::Stmt::Local(ref local) => NormalizedNode::with_children(NodeKind::LetBinding, vec![
      normalize_pat(&local.pat, ctx),
      NormalizedNode::none(), // type annotations on let bindings are part of the pattern in syn
      NormalizedNode::opt(local.init.as_ref().map(|init| normalize_expr(&init.expr, ctx))),
      NormalizedNode::opt(
        local
          .init
          .as_ref()
          .and_then(|init| init.diverge.as_ref())
          .map(|divergence| normalize_expr(&divergence.1, ctx)),
      ),
    ]),
    syn::Stmt::Expr(ref expr, ref semi) => {
      let normalized = normalize_expr(expr, ctx);
      with_optional_semi(normalized, semi.is_some())
    }
    syn::Stmt::Item(_) => NormalizedNode::leaf(NodeKind::Opaque),
    syn::Stmt::Macro(ref sm) => {
      let normalized = normalize_macro(&sm.mac, ctx);
      with_optional_semi(normalized, sm.semi_token.is_some())
    }
  }
}

/// Normalize a block into a `Block` node over its statements.
pub fn normalize_block(block: &syn::Block, ctx: &mut NormalizationContext) -> NormalizedNode {
  NormalizedNode::with_children(
    NodeKind::Block,
    block.stmts.iter().map(|statement| normalize_stmt(statement, ctx)).collect(),
  )
}

/// Build a node from a fixed pair of child expressions.
fn normalize_expr_pair(kind: NodeKind, left: &syn::Expr, right: &syn::Expr, ctx: &mut NormalizationContext) -> NormalizedNode {
  NormalizedNode::with_children(kind, vec![normalize_expr(left, ctx), normalize_expr(right, ctx)])
}

/// Build a node whose children are an optional expression payload.
fn node_with_optional_expr(kind: NodeKind, expr: Option<&syn::Expr>, ctx: &mut NormalizationContext) -> NormalizedNode {
  let children = expr.map(|expression| vec![normalize_expr(expression, ctx)]).unwrap_or_default();
  NormalizedNode::with_children(kind, children)
}

/// Build a range-like node from optional start/end payloads, keeping the
/// `None` sentinel positions.
pub(super) fn node_with_optional_expr_pair(
  kind: NodeKind,
  start: Option<&syn::Expr>,
  end: Option<&syn::Expr>,
  ctx: &mut NormalizationContext,
) -> NormalizedNode {
  NormalizedNode::with_children(kind, vec![
    NormalizedNode::opt(start.map(|expression| normalize_expr(expression, ctx))),
    NormalizedNode::opt(end.map(|expression| normalize_expr(expression, ctx))),
  ])
}

/// Normalize expression-path segments using type or value placeholders.
#[allow(
  clippy::single_call_fn,
  reason = "Expression paths distinguish type-looking segments before building the stable path layout"
)]
fn normalize_expr_path(path: &syn::Path, ctx: &mut NormalizationContext) -> NormalizedNode {
  let segments = path_segment_nodes(ctx, path, |context, ident| {
    let kind = if ident.chars().next().is_some_and(char::is_uppercase) {
      PlaceholderKind::Type
    } else {
      PlaceholderKind::Variable
    };
    placeholder_node(context, ident, kind, PlaceholderNodeRole::Expr)
  });

  path_node_from_segments(segments, true, NodeKind::Path)
}

/// Retain the distinction between a statement and a value expression.
fn with_optional_semi(normalized: NormalizedNode, has_semi: bool) -> NormalizedNode {
  if has_semi {
    NormalizedNode::with_children(NodeKind::Semi, vec![normalized])
  } else {
    normalized
  }
}
