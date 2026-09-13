//! Native Rust normalization contracts, with complete values retained on assertion failure.

use dupes_core::fingerprint::Fingerprint;
use strict_test_support::ConditionFailure;
use strict_test_support::ensure;
use syn::parse::Parse;

use super::LiteralKind;
use super::NodeKind;
use super::NormalizationContext;
use super::NormalizedNode;
use super::count_nodes;
use super::normalize_expr;
use super::normalize_impl_block;
use super::normalize_item_fn;
use super::normalize_type;
use super::reindex_placeholders;

/// One method's complete name, normalized signature, and body.
type NormalizedMethod = (String, NormalizedNode, NormalizedNode);

/// Native fixture failures and complete observations that violated a behavior contract.
#[derive(Debug, thiserror::Error)]
enum NormalizerTestFailure {
  /// Rust parsing rejected the exact supplied fixture.
  #[error("fixture {input:?} was rejected: {source}")]
  Parse {
    /// Complete input supplied to syn.
    input:  String,
    /// Native parser diagnostic.
    source: syn::Error,
  },
  /// Normalized values failed the requested semantic comparison.
  #[error("normalization expectation failed: {source}; nodes: {nodes:?}")]
  Nodes {
    /// Complete observed nodes in comparison order.
    nodes:  Vec<NormalizedNode>,
    /// Failed behavioral assertion.
    source: ConditionFailure,
  },
  /// Implementation methods differed from their expected names and order.
  #[error("method expectation failed: {source}; methods: {methods:?}")]
  Methods {
    /// Complete normalized methods, including signatures and bodies.
    methods: Vec<NormalizedMethod>,
    /// Failed behavioral assertion.
    source:  ConditionFailure,
  },
  /// The fixture's normalized body lacked the required conditional branch.
  #[error("the normalized function lacks its conditional branch: {body:?}")]
  MissingBranch {
    /// Complete normalized body returned by the real function normalizer.
    body: Box<NormalizedNode>,
  },
}

/// Parse a fixture while retaining its exact input and native diagnostic.
fn parse_fixture<T: Parse>(input: &str) -> Result<T, NormalizerTestFailure> {
  syn::parse_str(input).map_err(|source| NormalizerTestFailure::Parse {
    input: input.to_owned(),
    source,
  })
}

/// Normalize an expression using a fresh context at the public Rust boundary.
fn normalize_code_expr(input: &str) -> Result<NormalizedNode, NormalizerTestFailure> {
  let expression: syn::Expr = parse_fixture(input)?;
  Ok(normalize_expr(&expression, &mut NormalizationContext::new()))
}

/// Preserve the signature and body produced by one parsed function.
fn normalize_function(input: &str) -> Result<(NormalizedNode, NormalizedNode), NormalizerTestFailure> {
  let function: syn::ItemFn = parse_fixture(input)?;
  Ok(normalize_item_fn(&function))
}

/// Assert a semantic contract without losing any observed normalized values.
fn check_nodes<const COUNT: usize>(
  nodes: [NormalizedNode; COUNT],
  check: impl FnOnce([&NormalizedNode; COUNT]) -> Result<(), ConditionFailure>,
) -> Result<(), NormalizerTestFailure> {
  check(nodes.each_ref()).map_err(|source| NormalizerTestFailure::Nodes {
    nodes: Vec::from(nodes),
    source,
  })
}

/// Compare complete normalized nodes against an independently supplied equality expectation.
fn check_relation(original: NormalizedNode, compared: NormalizedNode, equal: bool) -> Result<(), NormalizerTestFailure> {
  check_nodes([original, compared], |[first, second]| {
    ensure(
      (first == second) == equal,
      "normalized values preserve the expected semantic relation",
    )
    .map(drop)
  })
}

/// Compare the semantic kind and child count of a real expression fixture.
fn check_shape(input: &str, kind: &NodeKind, children: usize) -> Result<(), NormalizerTestFailure> {
  check_nodes([normalize_code_expr(input)?], |[node]| {
    ensure(
      (&node.kind, node.children.len()) == (kind, children),
      "the expression retains its semantic kind and ordered child slots",
    )
    .map(drop)
  })
}

/// Compare both normalized parts across a complete function-renaming fixture pair.
fn check_function_renaming(first: &str, second: &str) -> Result<(), NormalizerTestFailure> {
  let (first_signature, first_body) = normalize_function(first)?;
  let (second_signature, second_body) = normalize_function(second)?;
  check_nodes(
    [first_signature, first_body, second_signature, second_body],
    |[original_signature, original_body, renamed_signature, renamed_body]| {
      ensure(
        (original_signature, original_body) == (renamed_signature, renamed_body),
        "renaming preserves the complete signature and body",
      )
      .map(drop)
    },
  )
}

/// Describe a complete expected macro node independently of parsing its arguments.
fn macro_node(name: &str, children: Vec<NormalizedNode>) -> NormalizedNode {
  NormalizedNode::with_children(
    NodeKind::MacroCall {
      name: name.to_owned()
    },
    children,
  )
}

/// Renaming function names and bindings preserves both signature and body.
#[test]
fn renamed_variables_produce_identical_trees() -> Result<(), NormalizerTestFailure> {
  check_function_renaming(
    "fn foo(x: i32) -> i32 { let y = x + 1; y }",
    "fn bar(a: i32) -> i32 { let b = a + 1; b }",
  )
}

/// Changing a function's arithmetic changes its body.
#[test]
fn structural_changes_produce_different_trees() -> Result<(), NormalizerTestFailure> {
  let (_, first) = normalize_function("fn foo(x: i32) -> i32 { x + 1 }")?;
  let (_, second) = normalize_function("fn foo(x: i32) -> i32 { x * 1 }")?;
  check_relation(first, second, false)
}

/// Integer values normalize together while floating literals remain distinct.
#[test]
fn literal_kind_preserved_but_value_erased() -> Result<(), NormalizerTestFailure> {
  check_nodes(
    [
      normalize_code_expr("42")?,
      normalize_code_expr("99")?,
      normalize_code_expr("3.14")?,
    ],
    |[first, second, floating]| {
      ensure(
        first == second && first != floating,
        "literal normalization erases values while preserving their kinds",
      )
      .map(drop)
    },
  )
}

/// Distinct string values have the same literal representation.
#[test]
fn string_literals_are_equal() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("\"hello\"")?, normalize_code_expr("\"world\"")?, true)
}

/// Boolean values share their normalized literal representation.
#[test]
fn bool_literals_normalize_as_placeholders() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("true")?, normalize_code_expr("false")?, true)
}

/// Expression paths retain each segment beneath a path node.
#[test]
fn multi_segment_expression_paths_are_path_nodes() -> Result<(), NormalizerTestFailure> {
  check_shape("foo::bar", &NodeKind::Path, 2)
}

/// Type paths retain their three source segments.
#[test]
fn multi_segment_type_paths_are_type_path_nodes() -> Result<(), NormalizerTestFailure> {
  let ty: syn::Type = parse_fixture("std::vec::Vec<i32>")?;
  check_nodes([normalize_type(&ty, &mut NormalizationContext::new())], |[node]| {
    ensure(
      node.kind == NodeKind::TypePath && node.children.len() == 3,
      "type paths preserve their segment structure",
    )
    .map(drop)
  })
}

/// Addition and subtraction retain distinct operators.
#[test]
fn binary_ops_preserved() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("a + b")?, normalize_code_expr("a - b")?, false)
}

/// Renamed receivers and arguments preserve an otherwise identical method call.
#[test]
fn method_calls_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("x.foo(y)")?, normalize_code_expr("a.foo(b)")?, true)
}

/// The method token occupies the slot between receiver and arguments.
#[test]
fn method_name_preserved_as_token() -> Result<(), NormalizerTestFailure> {
  check_nodes([normalize_code_expr("x.foo(y)")?], |[node]| {
    ensure(
      node.kind == NodeKind::MethodCall
        && node
          .children
          .get(1)
          .is_some_and(|method| method.kind == NodeKind::Token("foo".to_owned())),
      "the method name remains a semantic token in its established slot",
    )
    .map(drop)
  })
}

/// Distinct method names change both normalized trees and content identities.
#[test]
fn different_method_names_get_different_fingerprints() -> Result<(), NormalizerTestFailure> {
  check_nodes(
    [
      normalize_code_expr("ch.is_ascii_alphabetic()")?,
      normalize_code_expr("ch.is_ascii_alphanumeric()")?,
    ],
    |[first, second]| {
      ensure(
        first != second && Fingerprint::from_node(first) != Fingerprint::from_node(second),
        "method identity remains part of the fingerprint",
      )
      .map(drop)
    },
  )
}

/// Existing ignore registries depend on this method-name-preserving identity.
#[test]
fn method_call_fingerprint_pin() -> Result<(), NormalizerTestFailure> {
  let (_, body) = normalize_function("fn probe(x: &str) -> usize { x.trim().len() + 1 }")?;
  check_nodes([body], |[observed]| {
    ensure(
      Fingerprint::from_node(observed).to_hex() == "80a3bfe1fbf90075",
      "preserve the recorded method-call fingerprint",
    )
    .map(drop)
  })
}

/// Renaming a conditional's bindings preserves both branch structures.
#[test]
fn if_else_structure_preserved() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("if x > 0 { x } else { -x }")?,
    normalize_code_expr("if a > 0 { a } else { -a }")?,
    true,
  )
}

/// A missing alternative differs from an explicit else branch.
#[test]
fn if_vs_if_else_different() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("if x > 0 { x }")?,
    normalize_code_expr("if x > 0 { x } else { 0 }")?,
    false,
  )
}

/// A match contains its subject followed by both arms.
#[test]
fn match_arms_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape(r#"match x { 0 => "zero", _ => "other" }"#, &NodeKind::Match, 3)
}

/// Closure parameter renaming preserves its body relationship.
#[test]
fn closures_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("|x| x + 1")?, normalize_code_expr("|y| y + 1")?, true)
}

/// Loop binding names and string values normalize consistently.
#[test]
fn for_loops_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("for i in 0..10 { println!(\"hello\") }")?,
    normalize_code_expr("for j in 0..10 { println!(\"world\") }")?,
    true,
  )
}

/// Function signatures and bodies both contribute countable normalized nodes.
#[test]
fn node_counting_works() -> Result<(), NormalizerTestFailure> {
  let parts = normalize_function("fn foo(x: i32) -> i32 { x + 1 }")?;
  check_nodes(parts.into(), |[signature, body]| {
    ensure(
      count_nodes(signature) > 0 && count_nodes(body) > 0,
      "both function parts contain normalized syntax",
    )
    .map(drop)
  })
}

/// Tuple binding renaming preserves the complete function body.
#[test]
fn tuple_pattern_normalized() -> Result<(), NormalizerTestFailure> {
  let (_, first) = normalize_function("fn foo() { let (a, b) = (1, 2); }")?;
  let (_, second) = normalize_function("fn bar() { let (x, y) = (1, 2); }")?;
  check_relation(first, second, true)
}

/// Shared and mutable reference expressions remain distinct.
#[test]
fn reference_expressions_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("&x")?, normalize_code_expr("&mut x")?, false)
}

/// Impl normalization retains method names and their declaration order.
#[test]
fn impl_block_methods_normalized() -> Result<(), NormalizerTestFailure> {
  let implementation: syn::ItemImpl =
    parse_fixture("impl Foo { fn bar(&self) -> i32 { self.x + 1 } fn baz(&mut self, val: i32) { self.x = val; } }")?;
  let methods = normalize_impl_block(&implementation);
  ensure(
    methods.iter().map(|method| method.0.as_str()).eq(["bar", "baz"]),
    "both methods retain their names and source order",
  )
  .map(drop)
  .map_err(|source| NormalizerTestFailure::Methods {
    methods,
    source,
  })
}

/// Casts retain their expression and target type.
#[test]
fn cast_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("x as f64", &NodeKind::Cast, 2)
}

/// Indexing retains the indexed expression and index.
#[test]
fn index_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("arr[0]", &NodeKind::Index, 2)
}

/// Await retains its future expression.
#[test]
fn await_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("fut.await", &NodeKind::Await, 1)
}

/// Try retains its fallible operand.
#[test]
fn try_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("result?", &NodeKind::Try, 1)
}

/// A bounded range retains both populated endpoint slots.
#[test]
fn range_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_nodes([normalize_code_expr("0..10")?], |[node]| {
    ensure(
      node.kind == NodeKind::Range && node.children.len() == 2 && node.children.iter().all(|child| !child.is_none()),
      "bounded ranges preserve both endpoints",
    )
    .map(drop)
  })
}

/// Renaming a nested loop, conditional, and accumulation preserves complete function structure.
#[test]
fn complex_function_normalization() -> Result<(), NormalizerTestFailure> {
  check_function_renaming(
    "fn process(data: Vec<i32>) -> Result<i32, String> { let mut sum = 0; for item in data.iter() { if *item > 0 { sum += *item; } } \
     Ok(sum) }",
    "fn compute(values: Vec<i32>) -> Result<i32, String> { let mut total = 0; for val in values.iter() { if *val > 0 { total += *val; } } \
     Ok(total) }",
  )
}

/// An expression-list macro retains its name and normalized string argument.
#[test]
fn macro_invocations_produce_macro_call() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("println!(\"hello\")")?,
    macro_node("println", vec![NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Str))]),
    true,
  )
}

/// Changing a macro name changes its normalized node.
#[test]
fn different_macro_names_produce_different_nodes() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("println!(\"hello\")")?,
    normalize_code_expr("eprintln!(\"hello\")")?,
    false,
  )
}

/// Macro string values erase while their name and argument count remain equal.
#[test]
fn same_macro_different_literal_values_are_equal() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("println!(\"hello\")")?,
    normalize_code_expr("println!(\"world\")")?,
    true,
  )
}

/// Changing a macro's argument count changes its normalized node.
#[test]
fn same_macro_different_arg_count_are_different() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("println!(\"a\")")?,
    normalize_code_expr("println!(\"a\", \"b\")")?,
    false,
  )
}

/// A vector expression-list macro retains all three integer arguments.
#[test]
fn vec_macro_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("vec![1, 2, 3]")?,
    macro_node("vec", vec![NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)); 3]),
    true,
  )
}

/// A qualified macro path uses its final segment as its semantic name.
#[test]
fn multi_segment_macro_path_uses_last_segment() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("std::println!(\"hello\")")?,
    macro_node("println", vec![NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Str))]),
    true,
  )
}

/// Macro node counts include the macro node and both arguments.
#[test]
fn macro_call_node_count() -> Result<(), NormalizerTestFailure> {
  check_nodes([normalize_code_expr("println!(\"a\", \"b\")")?], |[node]| {
    ensure(count_nodes(node) == 3, "count the macro and both argument nodes").map(drop)
  })
}

/// Unsupported macro argument grammar remains an explicit opaque child.
#[test]
fn unparseable_macro_args_produce_opaque() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("vec![x; 10]")?,
    macro_node("vec", vec![NormalizedNode::leaf(NodeKind::Opaque)]),
    true,
  )
}

/// An empty macro and an unsupported macro body retain different complete shapes.
#[test]
fn unparseable_macro_differs_from_no_args() -> Result<(), NormalizerTestFailure> {
  check_nodes(
    [normalize_code_expr("my_macro!()")?, normalize_code_expr("vec![x; 10]")?],
    |[empty, opaque]| {
      ensure(
        empty == &macro_node("my_macro", vec![]) && opaque == &macro_node("vec", vec![NormalizedNode::leaf(NodeKind::Opaque)]),
        "empty arguments stay empty while unsupported arguments retain an opaque child",
      )
      .map(drop)
    },
  )
}

/// A type-position macro parses and contributes to the signature.
#[test]
fn type_position_macro_normalized() -> Result<(), NormalizerTestFailure> {
  let (signature, _) = normalize_function("fn foo() -> my_type!(i32) {}")?;
  check_nodes([signature], |[observed]| {
    ensure(count_nodes(observed) > 0, "a parsed type macro contributes signature syntax").map(drop)
  })
}

/// A pattern macro parses and contributes to the function body.
#[test]
fn pat_macro_normalized() -> Result<(), NormalizerTestFailure> {
  let (_, body) = normalize_function("fn foo(x: i32) { match x { my_pat!(x) => {} _ => {} } }")?;
  check_nodes([body], |[observed]| {
    ensure(count_nodes(observed) > 0, "a parsed pattern macro contributes body syntax").map(drop)
  })
}

/// Renamed while-loop bindings preserve the condition and update body.
#[test]
fn while_loop_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(
    normalize_code_expr("while x > 0 { x = x - 1; }")?,
    normalize_code_expr("while a > 0 { a = a - 1; }")?,
    true,
  )
}

/// Returned integer literal values erase consistently.
#[test]
fn return_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("return 42")?, normalize_code_expr("return 99")?, true)
}

/// Assignment retains its target and value.
#[test]
fn assign_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("x = 5", &NodeKind::Assign, 2)
}

/// Renamed struct fields preserve the initializer kind and field population.
#[test]
fn struct_init_normalized() -> Result<(), NormalizerTestFailure> {
  check_nodes(
    [
      normalize_code_expr("Foo { x: 1, y: 2 }")?,
      normalize_code_expr("Bar { a: 1, b: 2 }")?,
    ],
    |[first, second]| {
      ensure(
        first.kind == NodeKind::StructInit && second.kind == NodeKind::StructInit && first.children.len() == second.children.len(),
        "both struct initializers retain their field population",
      )
      .map(drop)
    },
  )
}

/// Arrays retain each element.
#[test]
fn array_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("[1, 2, 3]", &NodeKind::Array, 3)
}

/// Tuples retain each element.
#[test]
fn tuple_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("(1, 2, 3)", &NodeKind::Tuple, 3)
}

/// Field access retains its base and field placeholder.
#[test]
fn field_access_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("foo.bar", &NodeKind::FieldAccess, 2)
}

/// Logical negation and arithmetic negation remain distinct.
#[test]
fn unary_ops_preserved() -> Result<(), NormalizerTestFailure> {
  check_relation(normalize_code_expr("!x")?, normalize_code_expr("-x")?, false)
}

/// Infinite loops retain their body.
#[test]
fn loop_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("loop { break; }", &NodeKind::Loop, 1)
}

/// An empty function body remains an empty block.
#[test]
fn empty_block_normalized() -> Result<(), NormalizerTestFailure> {
  let (_, body) = normalize_function("fn foo() {}")?;
  check_nodes([body], |[observed]| {
    ensure(
      observed.kind == NodeKind::Block && observed.children.is_empty(),
      "empty bodies remain empty blocks",
    )
    .map(drop)
  })
}

/// Break payload absence matters while integer payload values erase.
#[test]
fn break_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_nodes(
    [
      normalize_code_expr("loop { break 42; }")?,
      normalize_code_expr("loop { break; }")?,
      normalize_code_expr("loop { break 99; }")?,
    ],
    |[first, empty, second]| {
      ensure(
        first != empty && first == second,
        "break retains payload presence and erases integer values",
      )
      .map(drop)
    },
  )
}

/// Parenthesized expressions retain their wrapper and operand.
#[test]
fn paren_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("(x + 1)", &NodeKind::Paren, 1)
}

/// Array repetition retains the element and repeat count expressions.
#[test]
fn repeat_expression_normalized() -> Result<(), NormalizerTestFailure> {
  check_shape("[0; 16]", &NodeKind::Repeat, 2)
}

/// Or-patterns differ from slice patterns, while slice binding renaming preserves structure.
#[test]
fn or_and_slice_patterns_normalized() -> Result<(), NormalizerTestFailure> {
  check_nodes(
    [
      normalize_code_expr("match x { 1 | 2 => 0, _ => 1 }")?,
      normalize_code_expr("match x { [first, rest @ ..] => 0, _ => 1 }")?,
      normalize_code_expr("match x { [a, b] => 0, _ => 1 }")?,
      normalize_code_expr("match y { [c, d] => 0, _ => 1 }")?,
    ],
    |[alternatives, rest, first_slice, second_slice]| {
      ensure(
        alternatives != rest && first_slice == second_slice,
        "pattern kinds remain distinct while binding names erase",
      )
      .map(drop)
    },
  )
}

/// Reference type mutability remains significant when type and argument names erase.
#[test]
fn type_reference_and_slice_normalized() -> Result<(), NormalizerTestFailure> {
  let (first, _) = normalize_function("fn foo(values: &[i32]) -> &mut i32 { unimplemented!() }")?;
  let (second, _) = normalize_function("fn bar(items: &[u64]) -> &mut u64 { unimplemented!() }")?;
  let (different, _) = normalize_function("fn baz(values: &mut [i32]) -> &i32 { unimplemented!() }")?;
  check_nodes([first, second, different], |[original, renamed, changed]| {
    ensure(
      original == renamed && original != changed,
      "type erasure preserves the direction of reference mutability",
    )
    .map(drop)
  })
}

/// Select the real then-branch only from the expected block and conditional structure.
fn then_branch(body: NormalizedNode) -> Result<NormalizedNode, NormalizerTestFailure> {
  let branch = body
    .children
    .first()
    .filter(|conditional| body.kind == NodeKind::Block && conditional.kind == NodeKind::If)
    .and_then(|conditional| conditional.children.get(1))
    .cloned();
  branch.ok_or_else(|| NormalizerTestFailure::MissingBranch {
    body: Box::new(body)
  })
}

/// Reindexing real function subtrees removes enclosing placeholder offsets.
#[test]
fn reindex_from_real_function_subtrees() -> Result<(), NormalizerTestFailure> {
  let (_, first) = normalize_function("fn foo(x: i32, y: i32) -> i32 { if x > 0 { let z = y + 1; z } else { x } }")?;
  let (_, second) = normalize_function("fn bar(unused: i32, a: i32, b: i32) -> i32 { if a > 0 { let c = b + 1; c } else { a } }")?;
  check_nodes([then_branch(first)?, then_branch(second)?], |[original, renamed]| {
    ensure(
      original != renamed && reindex_placeholders(original) == reindex_placeholders(renamed),
      "reindexing preserves subtree structure while removing enclosing index offsets",
    )
    .map(drop)
  })
}
