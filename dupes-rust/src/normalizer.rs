//! `syn` AST to `NormalizedNode` conversion: signature/body normalization
//! entry points plus the expression, pattern/type, and operator/literal
//! submodules they compose.

// Re-export core node types used by the normalizer's public API and tests.
pub use dupes_core::node::BinOpKind;
pub use dupes_core::node::LiteralKind;
pub use dupes_core::node::NodeKind;
pub use dupes_core::node::NormalizationContext;
pub use dupes_core::node::NormalizedNode;
pub use dupes_core::node::PlaceholderKind;
pub use dupes_core::node::UnOpKind;
pub use dupes_core::node::count_nodes;
pub use dupes_core::node::reindex_placeholders;

mod expr;
mod helpers;
/// Pattern and type normalization preserves each grammar role.
mod pat;

pub use expr::normalize_block;
pub use expr::normalize_expr;
pub use expr::normalize_stmt;
pub use helpers::normalize_bin_op;
pub use helpers::normalize_lit;
pub use helpers::normalize_un_op;
pub use pat::normalize_pat;
pub use pat::normalize_type;

/// Normalize a function signature into its return type and parameters.
#[allow(
  clippy::single_call_fn,
  reason = "Signature normalization owns return and parameter ordering independently of the function body"
)]
pub fn normalize_signature(sig: &syn::Signature, ctx: &mut NormalizationContext) -> NormalizedNode {
  // FnSignature -> [return_type_or_None, param0, param1, ...]
  let return_type = match sig.output {
    syn::ReturnType::Default => NormalizedNode::none(),
    syn::ReturnType::Type(_, ref ty) => normalize_type(ty, ctx),
  };
  let mut children = vec![return_type];
  children.extend(sig.inputs.iter().map(|arg| match *arg {
    syn::FnArg::Receiver(ref receiver) => {
      let idx = ctx.placeholder("self", PlaceholderKind::Variable);
      let self_node = NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, idx));
      if let syn::ReceiverKind::Reference(_, _, ref mutability) = receiver.kind {
        NormalizedNode::with_children(
          NodeKind::Reference {
            mutable: mutability.is_some(),
          },
          vec![self_node],
        )
      } else {
        self_node
      }
    }
    syn::FnArg::Typed(ref pt) => {
      let pat = normalize_pat(&pt.pat, ctx);
      let ty = normalize_type(&pt.ty, ctx);
      NormalizedNode::with_children(NodeKind::FieldValue, vec![pat, ty])
    }
  }));
  NormalizedNode::with_children(NodeKind::FnSignature, children)
}

// -- Public entry points ------------------------------------------------------

/// Normalize any function-like item from its signature and body block.
#[must_use]
pub fn normalize_fn_like(sig: &syn::Signature, block: &syn::Block) -> (NormalizedNode, NormalizedNode) {
  let mut ctx = NormalizationContext::new();
  let signature = normalize_signature(sig, &mut ctx);
  let body = normalize_block(block, &mut ctx);
  (signature, body)
}

/// Normalize a top-level function.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "Adapt a complete top-level function to the shared signature and body normalizer"
)]
pub fn normalize_item_fn(func: &syn::ItemFn) -> (NormalizedNode, NormalizedNode) {
  normalize_fn_like(&func.sig, &func.block)
}

/// Normalize a closure expression.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "An extracted closure owns a fresh placeholder context for its body and input patterns"
)]
pub fn normalize_closure_expr(closure: &syn::ExprClosure) -> NormalizedNode {
  let mut ctx = NormalizationContext::new();
  let mut children = vec![normalize_expr(&closure.body, &mut ctx)];
  children.extend(closure.inputs.iter().map(|pattern| normalize_pat(pattern, &mut ctx)));
  NormalizedNode::with_children(NodeKind::Closure, children)
}

/// Normalize an impl block -- normalizes each method body.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "The public impl-block boundary preserves each method name together with its normalized signature and body."
)]
pub fn normalize_impl_block(imp: &syn::ItemImpl) -> Vec<(String, NormalizedNode, NormalizedNode)> {
  imp
    .items
    .iter()
    .filter_map(|member| {
      if let syn::ImplItem::Fn(ref method) = *member {
        let name = method.sig.ident.to_string();
        let (sig, body) = normalize_fn_like(&method.sig, &method.block);
        Some((name, sig, body))
      } else {
        None
      }
    })
    .collect()
}

#[cfg(test)]
mod tests;
