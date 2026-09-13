//! Pattern and type normalization with distinct placeholder roles.

use dupes_core::node::NodeKind;
use dupes_core::node::NormalizationContext;
use dupes_core::node::NormalizedNode;
use dupes_core::node::PlaceholderKind;

use super::expr::node_with_optional_expr_pair;
use super::expr::normalize_expr;
use super::helpers::PlaceholderNodeRole;
use super::helpers::member_to_string;
use super::helpers::normalize_list;
use super::helpers::normalize_lit;
use super::helpers::normalize_macro;
use super::helpers::one_child_node;
use super::helpers::path_node_from_segments;
use super::helpers::placeholder_node;
use super::helpers::reference_node;
use super::helpers::uniform_path_segment_nodes;

/// Normalize a type, erasing type names to placeholders.
pub fn normalize_type(ty: &syn::Type, ctx: &mut NormalizationContext) -> NormalizedNode {
  match *ty {
    syn::Type::Path(ref tp) => normalize_type_path(&tp.path, tp.qself.is_none(), ctx),
    syn::Type::Reference(ref reference) => reference_node(
      reference.mutability.as_ref(),
      PlaceholderNodeRole::Type,
      &*reference.elem,
      ctx,
      normalize_type,
    ),
    syn::Type::Tuple(ref tuple) => {
      if tuple.elems.is_empty() {
        NormalizedNode::leaf(NodeKind::TypeUnit)
      } else {
        normalize_list(NodeKind::TypeTuple, &tuple.elems, ctx, normalize_type)
      }
    }
    syn::Type::Slice(ref slice) => one_child_node(NodeKind::TypeSlice, &*slice.elem, ctx, normalize_type),
    syn::Type::Array(ref array) => NormalizedNode::with_children(NodeKind::TypeArray, vec![
      normalize_type(&array.elem, ctx),
      normalize_expr(&array.len, ctx),
    ]),
    syn::Type::ImplTrait(ref implementation) => NormalizedNode::with_children(
      NodeKind::TypeImplTrait,
      implementation
        .bounds
        .iter()
        .filter_map(|bound| {
          if let syn::TypeParamBound::Trait(ref constraint) = *bound {
            Some(normalize_type_path(&constraint.path, true, ctx))
          } else {
            None
          }
        })
        .collect(),
    ),
    syn::Type::Infer(_) => NormalizedNode::leaf(NodeKind::TypeInfer),
    syn::Type::Never(_) => NormalizedNode::leaf(NodeKind::TypeNever),
    syn::Type::Paren(ref parenthesized) => normalize_type(&parenthesized.elem, ctx),
    syn::Type::Macro(ref tm) => normalize_macro(&tm.mac, ctx),
    syn::Type::FnPtr(_) | syn::Type::Group(_) | syn::Type::Ptr(_) | syn::Type::TraitObject(_) | syn::Type::Verbatim(_) | _ => {
      NormalizedNode::leaf(NodeKind::Opaque)
    }
  }
}

/// Normalize a pattern, erasing bindings to placeholders.
pub fn normalize_pat(pat: &syn::Pat, ctx: &mut NormalizationContext) -> NormalizedNode {
  match *pat {
    syn::Pat::Ident(ref pi) => placeholder_node(ctx, &pi.ident.to_string(), PlaceholderKind::Variable, PlaceholderNodeRole::Pat),
    syn::Pat::Wild(_) => NormalizedNode::leaf(NodeKind::PatWild),
    syn::Pat::Tuple(ref pt) => normalize_list(NodeKind::PatTuple, &pt.elems, ctx, normalize_pat),
    syn::Pat::TupleStruct(ref pts) => normalize_list(NodeKind::PatStruct, &pts.elems, ctx, normalize_pat),
    syn::Pat::Struct(ref ps) => NormalizedNode::with_children(
      NodeKind::PatStruct,
      ps.fields
        .iter()
        .map(|f| {
          let field_pattern = normalize_pat(&f.pat, ctx);
          NormalizedNode::with_children(NodeKind::FieldValue, vec![
            placeholder_node(
              ctx,
              &member_to_string(&f.member),
              PlaceholderKind::Variable,
              PlaceholderNodeRole::Pat,
            ),
            field_pattern,
          ])
        })
        .collect(),
    ),
    syn::Pat::Or(ref po) => normalize_list(NodeKind::PatOr, &po.cases, ctx, normalize_pat),
    syn::Pat::Lit(ref pl) => NormalizedNode::with_children(NodeKind::PatLiteral, vec![normalize_lit(&pl.lit)]),
    syn::Pat::Reference(ref pr) => reference_node(pr.mutability.as_ref(), PlaceholderNodeRole::Pat, &*pr.pat, ctx, normalize_pat),
    syn::Pat::Slice(ref ps) => normalize_list(NodeKind::PatSlice, &ps.elems, ctx, normalize_pat),
    syn::Pat::Rest(_) => NormalizedNode::leaf(NodeKind::PatRest),
    // PatRange -> [from_or_None, to_or_None]
    syn::Pat::Range(ref pr) => node_with_optional_expr_pair(NodeKind::PatRange, pr.start.as_deref(), pr.end.as_deref(), ctx),
    syn::Pat::Path(ref pp) => normalize_pat_path(&pp.path, ctx),
    syn::Pat::Type(ref pt) => normalize_pat(&pt.pat, ctx),
    syn::Pat::Macro(ref pm) => normalize_macro(&pm.mac, ctx),
    syn::Pat::Const(_) | syn::Pat::Guard(_) | syn::Pat::Paren(_) | syn::Pat::Verbatim(_) | _ => NormalizedNode::leaf(NodeKind::Opaque),
  }
}

/// Normalize type path segments while retaining the qualified-path boundary.
fn normalize_type_path(path: &syn::Path, single_segment_as_placeholder: bool, ctx: &mut NormalizationContext) -> NormalizedNode {
  let segments = uniform_path_segment_nodes(ctx, path, PlaceholderKind::Type, PlaceholderNodeRole::Type);
  path_node_from_segments(segments, single_segment_as_placeholder, NodeKind::TypePath)
}

/// Normalize a pattern path using pattern-role placeholders.
#[allow(
  clippy::single_call_fn,
  reason = "Pattern paths own their placeholder role and multi-segment node kind"
)]
fn normalize_pat_path(path: &syn::Path, ctx: &mut NormalizationContext) -> NormalizedNode {
  let segments = uniform_path_segment_nodes(ctx, path, PlaceholderKind::Variable, PlaceholderNodeRole::Pat);
  path_node_from_segments(segments, true, NodeKind::PatStruct)
}
