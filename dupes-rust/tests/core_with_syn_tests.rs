//! Tests for dupes-core modules that require syn for test data construction.
//! These tests exercise fingerprint, similarity, grouper, and extractor functionality
//! using syn-parsed Rust code, so they live in dupes-rust (which depends on syn).

#[cfg(test)]
mod tests {
  use std::cmp::Ordering;
  use std::path::Path;

  use dupes_core::code_unit::DetectionDimension;
  use dupes_core::extractor;
  use dupes_core::extractor::SubUnit;
  use dupes_core::fingerprint::Fingerprint;
  use dupes_core::grouper;
  use dupes_core::grouper::DuplicateGroup;
  use dupes_core::grouper::NearGroupingFailure;
  use dupes_core::grouper::StatisticsFailure;
  use dupes_core::node::NodeKind;
  use dupes_core::node::NormalizedNode;
  use dupes_core::similarity::SimilarityFailure;
  use dupes_core::similarity::SimilarityScore;
  use dupes_core::similarity::similarity_score;
  use dupes_rust::normalizer::NormalizationContext;
  use dupes_rust::normalizer::normalize_expr;
  use dupes_rust::normalizer::normalize_item_fn;
  use dupes_rust::normalizer::reindex_placeholders;
  use dupes_rust::parser;
  use dupes_rust::parser::CodeUnit;
  use dupes_rust::parser::CodeUnitKind;
  use dupes_rust::parser::RustParseError;
  use strict_test_support::ComparisonFailure;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  /// Native fixture and calculation failures, including complete scored outcomes.
  #[derive(Debug, thiserror::Error)]
  enum FixtureFailure {
    /// A Rust fixture could not be parsed.
    #[error("Rust fixture parse failed: {source}; input: {input}")]
    Syntax {
      /// Original parser input.
      input:  String,
      /// Native syntax failure.
      source: syn::Error,
    },
    /// Source-unit extraction failed.
    #[error(transparent)]
    Parse(#[from] RustParseError),
    /// Similarity could not be calculated from the original node counts.
    #[error(transparent)]
    Similarity(#[from] SimilarityFailure),
    /// Near grouping failed after any completed pair comparisons.
    #[error(transparent)]
    Grouping(#[from] Box<NearGroupingFailure>),
    /// Line statistics failed with original source-unit evidence.
    #[error(transparent)]
    Statistics(#[from] StatisticsFailure),
    /// A scored result did not satisfy the fixture's similarity contract.
    #[error("similarity expectation failed: {source}; score: {score:?}")]
    Score {
      /// Original integer populations and rounded score.
      score:  SimilarityScore,
      /// Failed behavioral expectation.
      source: ConditionFailure,
    },
    /// Grouping returned an unexpected population.
    #[error("group expectation failed: {source}; groups: {groups:?}")]
    Groups {
      /// Complete grouped result.
      groups: Vec<DuplicateGroup>,
      /// Failed behavioral expectation.
      source: ConditionFailure,
    },
    /// Exact grouping returned a different number of independent families.
    #[error("exact-group count expectation failed: {source}; groups: {groups:?}")]
    GroupCount {
      /// Complete source-unit population passed to grouping.
      units:  Vec<CodeUnit>,
      /// Complete groups returned by the operation.
      groups: Vec<DuplicateGroup>,
      /// Native observed and expected cardinalities.
      source: ComparisonFailure<usize, usize>,
    },
    /// Function identity differed from the required relation.
    #[error("{source}; inputs: {inputs:?}; parsed: {parsed:?}; normalized: {normalized:?}; expected equality: {expected_equal}")]
    Identity {
      /// Complete source of both functions.
      inputs:         Box<[String; 2]>,
      /// Both native parse outcomes, including an earlier success if its peer fails.
      parsed:         Box<[Result<syn::ItemFn, syn::Error>; 2]>,
      /// Complete normalized signature, body, and content identity for each parsed function.
      normalized:     Box<[Option<FunctionIdentity>; 2]>,
      /// Whether both complete identities must match.
      expected_equal: bool,
      /// Failed behavioral expectation.
      source:         Box<ConditionFailure>,
    },
    /// Nested extraction did not retain the requested syntax kinds or descriptions.
    #[error("{source}; input: {input}; body: {body:?}; sub-units: {sub_units:?}; expected: {expected:?}")]
    Extraction {
      /// Complete function supplied to normalization.
      input:     String,
      /// Complete normalized function body.
      body:      Box<NormalizedNode>,
      /// Every extracted sub-unit, including tags and owner links.
      sub_units: Vec<SubUnit>,
      /// Expected counts and optional descriptions by syntax kind.
      expected:  Vec<(CodeUnitKind, usize, Option<String>)>,
      /// Failed behavioral expectation.
      source:    Box<ConditionFailure>,
    },
    /// Another fixture contract was violated.
    #[error(transparent)]
    Assertion(#[from] ConditionFailure),
  }

  /// Fallible result of a Rust-backed core fixture.
  type FixtureResult<T = ()> = Result<T, FixtureFailure>;

  /// A function's normalized signature, normalized body, and derived fingerprint.
  type FunctionIdentity = (NormalizedNode, NormalizedNode, Fingerprint);

  /// Expected population and optional description for one nested syntax kind.
  type NestedUnitExpectation<'a> = (CodeUnitKind, usize, Option<&'a str>);

  /// Renamed multiline functions used for grouping and line-accounting scenarios.
  const MULTILINE_PAIR: &str = "
        fn foo(x: i32) -> i32 {
            let y = x + 1;
            y * 2
        }
        fn bar(a: i32) -> i32 {
            let b = a + 1;
            b * 2
        }
        ";

  /// The smallest ordinary exact family used to check grouping and near exclusion.
  const EXACT_PAIR: &str = "
        fn a(x: i32) -> i32 { x + 1 }
        fn b(y: i32) -> i32 { y + 1 }
        ";

  // ── Helpers ───────────────────────────────────────────────────────────────

  /// Parse a complete function, retaining the original input on syntax failure.
  fn parse_fn(code: &str) -> FixtureResult<syn::ItemFn> {
    syn::parse_str(code).map_err(|source| FixtureFailure::Syntax {
      input: code.to_owned(),
      source,
    })
  }

  /// Parse a complete expression, retaining the original input on syntax failure.
  fn parse_expr(code: &str) -> FixtureResult<syn::Expr> {
    syn::parse_str(code).map_err(|source| FixtureFailure::Syntax {
      input: code.to_owned(),
      source,
    })
  }

  /// Compare function bodies through the public numeric outcome.
  fn fn_body_similarity(code1: &str, code2: &str) -> FixtureResult<SimilarityScore> {
    let f1 = parse_fn(code1)?;
    let f2 = parse_fn(code2)?;
    let (_, b1) = normalize_item_fn(&f1);
    let (_, b2) = normalize_item_fn(&f2);
    Ok(similarity_score(&b1, &b2)?)
  }

  /// Compare expressions with separate placeholder contexts.
  fn expr_similarity(code1: &str, code2: &str) -> FixtureResult<SimilarityScore> {
    let e1 = parse_expr(code1)?;
    let e2 = parse_expr(code2)?;
    let mut ctx1 = NormalizationContext::new();
    let mut ctx2 = NormalizationContext::new();
    let n1 = normalize_expr(&e1, &mut ctx1);
    let n2 = normalize_expr(&e2, &mut ctx2);
    Ok(similarity_score(&n1, &n2)?)
  }

  /// Extract a realistic function population without size filtering.
  fn make_units(code: &str) -> FixtureResult<Vec<CodeUnit>> {
    Ok(parser::parse_source(Path::new("test.rs"), code, 1, 0)?)
  }

  /// Normalize one function body for sub-unit extraction.
  fn parse_and_extract_body(code: &str) -> FixtureResult<NormalizedNode> {
    let function = parse_fn(code)?;
    let (_, body) = normalize_item_fn(&function);
    Ok(body)
  }

  /// Preserve original counts when a rounded similarity violates a fixture expectation.
  fn check_score(score: &SimilarityScore, accepts: impl FnOnce(f64) -> bool, context: &'static str) -> FixtureResult {
    ensure(accepts(score.value), context)
      .map(drop)
      .map_err(|source| FixtureFailure::Score {
        score: *score,
        source,
      })
  }

  /// Retain complete groups when a public grouping contract is violated.
  fn check_groups(groups: Vec<DuplicateGroup>, check: impl FnOnce(&[DuplicateGroup]) -> Result<(), ConditionFailure>) -> FixtureResult {
    check(&groups).map_err(|source| FixtureFailure::Groups {
      groups,
      source,
    })
  }

  /// Compare complete function identities while retaining both parsing and normalization outcomes.
  fn check_function_identity(inputs: &[&str; 2], expected_equal: bool) -> FixtureResult {
    let parsed = inputs.map(syn::parse_str::<syn::ItemFn>);
    let normalized = parsed.each_ref().map(|outcome| {
      outcome.as_ref().ok().map(|function| {
        let (signature, body) = normalize_item_fn(function);
        let fingerprint = Fingerprint::from_sig_and_body(&signature, &body);
        (signature, body, fingerprint)
      })
    });
    ensure(
      matches!(&normalized, [Some((_, _, left)), Some((_, _, right))] if (left == right) == expected_equal),
      "both functions parse and retain the required fingerprint relation",
    )
    .map(drop)
    .map_err(|source| FixtureFailure::Identity {
      inputs: Box::new(inputs.map(str::to_owned)),
      parsed: Box::new(parsed),
      normalized: Box::new(normalized),
      expected_equal,
      source: Box::new(source),
    })
  }

  /// Check syntax-specific nested populations without discarding the other extracted candidates.
  fn check_nested_units(input: &str, expected: &[NestedUnitExpectation<'_>]) -> FixtureResult {
    let body = parse_and_extract_body(input)?;
    let sub_units = extractor::extract_sub_units(&body, 1);
    ensure(
      expected.iter().all(|&(kind, count, description)| {
        let matching: Vec<_> = sub_units.iter().filter(|unit| unit.kind == kind).collect();
        matching.len() == count && description.is_none_or(|name| matching.iter().all(|unit| unit.description == name))
      }),
      "nested extraction preserves the expected kinds, populations, and descriptions",
    )
    .map(drop)
    .map_err(|source| FixtureFailure::Extraction {
      input: input.to_owned(),
      body: Box::new(body),
      sub_units,
      expected: expected
        .iter()
        .map(|&(kind, count, description)| (kind, count, description.map(str::to_owned)))
        .collect(),
      source: Box::new(source),
    })
  }

  // ── Fingerprint tests (syn-dependent) ─────────────────────────────────────

  /// Function identity preserves renaming and distinguishes arithmetic behavior.
  #[test]
  fn function_fingerprints_preserve_renaming_and_discriminate_operators() -> FixtureResult {
    for (inputs, expected_equal) in [
      (["fn foo(x: i32) -> i32 { x + 1 }", "fn bar(a: i32) -> i32 { a + 1 }"], true),
      (["fn foo(x: i32) -> i32 { x + 1 }", "fn foo(x: i32) -> i32 { x * 2 }"], false),
      (["fn f(x: i32) -> i32 { x + 1 }", "fn f(x: i32) -> i32 { x - 1 }"], false),
      (
        [
          "fn compute(value: i32) -> i32 { value * value + value }",
          "fn calculate(num: i32) -> i32 { num * num + num }",
        ],
        true,
      ),
    ] {
      check_function_identity(&inputs, expected_equal)?;
    }
    Ok(())
  }

  /// A normalized expression produces a nonzero content fingerprint.
  #[test]
  fn fingerprint_from_node() -> FixtureResult {
    let expr = parse_expr("x + 1")?;
    let mut ctx = NormalizationContext::new();
    let node = normalize_expr(&expr, &mut ctx);
    let fp = Fingerprint::from_node(&node);
    Ok(ensure(fp.value() != 0, "normalized expression has a content identity").map(drop)?)
  }

  /// Repeated normalization retains the same content fingerprint.
  #[test]
  fn fingerprint_stability() -> FixtureResult {
    let code = "fn foo(x: i32) -> i32 { x + 1 }";
    check_function_identity(&[code, code], true)
  }

  // ── Similarity tests ──────────────────────────────────────────────────────

  /// Equivalent normalized bodies have the maximum score.
  #[test]
  fn identical_trees_score_one() -> FixtureResult {
    let score = fn_body_similarity("fn foo(x: i32) -> i32 { x + 1 }", "fn bar(a: i32) -> i32 { a + 1 }")?;
    check_score(&score, |value| value.to_bits() == 1.0_f64.to_bits(), "identical bodies score one")
  }

  /// Incompatible arithmetic and control-flow trees have low similarity.
  #[test]
  fn completely_different_trees_score_low() -> FixtureResult {
    let score = fn_body_similarity("fn foo(x: i32) -> i32 { x + 1 }", "fn bar(x: bool) { if x { loop { break; } } }")?;
    check_score(&score, |value| value < 0.3, "incompatible structures score below 0.3")
  }

  /// Similarity retains a local expression change while distinguishing added branching.
  #[test]
  fn function_similarity_distinguishes_local_and_structural_changes() -> FixtureResult {
    for ([left, right], threshold, expected) in [
      (
        [
          "fn foo(x: i32) -> i32 { let a = x + 1; let b = a * 2; a + b }",
          "fn bar(x: i32) -> i32 { let a = x + 1; let b = a * 3; a + b }",
        ],
        0.8,
        Ordering::Greater,
      ),
      (
        [
          "fn foo(x: i32) -> i32 { x + 1 }",
          "fn bar(x: i32) -> i32 { if x > 0 { x + 1 } else { x - 1 } }",
        ],
        0.7,
        Ordering::Less,
      ),
    ] {
      let score = fn_body_similarity(left, right)?;
      check_score(
        &score,
        |value| value.total_cmp(&threshold) == expected,
        "the body change retains its required threshold relation",
      )?;
    }
    Ok(())
  }

  /// Two empty function bodies retain the successful maximum score.
  #[test]
  fn empty_trees_score_one() -> FixtureResult {
    let score = fn_body_similarity("fn foo() {}", "fn bar() {}")?;
    check_score(&score, |value| value.to_bits() == 1.0_f64.to_bits(), "empty bodies score one")
  }

  /// Equivalent operand, closure, and macro argument shapes retain the maximum score.
  #[test]
  fn equivalent_expression_shapes_score_one() -> FixtureResult {
    for (left, right) in [
      ("x + 1", "y + 1"),
      ("x.foo(y, z)", "a.foo(b, c)"),
      ("|x| x + 1", "|y| y + 1"),
      ("println!(\"hello\")", "println!(\"world\")"),
    ] {
      let score = expr_similarity(left, right)?;
      check_score(
        &score,
        |value| value.to_bits() == 1.0_f64.to_bits(),
        "equivalent normalized expressions score one",
      )?;
    }
    Ok(())
  }

  /// An operator change preserves operand similarity without exact equality.
  #[test]
  fn simple_expr_different_op() -> FixtureResult {
    let score = expr_similarity("x + 1", "x - 1")?;
    check_score(
      &score,
      |value| value > 0.5 && value < 1.0,
      "changed operators retain partial operand similarity",
    )
  }

  /// A realistic loop and conditional body normalizes independently of local names.
  #[test]
  fn near_duplicate_complex_fn() -> FixtureResult {
    let score = fn_body_similarity(
      "
        fn process(data: Vec<i32>) -> i32 {
            let mut sum = 0;
            for item in data.iter() {
                if *item > 0 {
                    sum += *item;
                }
            }
            sum
        }
        ",
      "
        fn compute(values: Vec<i32>) -> i32 {
            let mut total = 0;
            for val in values.iter() {
                if *val > 0 {
                    total += *val;
                }
            }
            total
        }
        ",
    )?;
    check_score(
      &score,
      |value| value.to_bits() == 1.0_f64.to_bits(),
      "renamed complex bodies score one",
    )
  }

  /// Reversing operands retains the score and reverses the original populations.
  #[test]
  fn similarity_is_symmetric() -> FixtureResult {
    let score1 = fn_body_similarity("fn foo(x: i32) -> i32 { x + 1 }", "fn bar(x: i32) -> i32 { x * 2 + 1 }")?;
    let score2 = fn_body_similarity("fn bar(x: i32) -> i32 { x * 2 + 1 }", "fn foo(x: i32) -> i32 { x + 1 }")?;
    Ok(
      ensure(
        (
          score1.value.to_bits(),
          score1.counts.first,
          score1.counts.second,
          score1.counts.matching,
        ) == (
          score2.value.to_bits(),
          score2.counts.second,
          score2.counts.first,
          score2.counts.matching,
        ),
        "similarity is symmetric while preserving the operand population order",
      )
      .map(drop)?,
    )
  }

  /// Distinct branching constructs do not normalize into a high-similarity pair.
  #[test]
  fn if_vs_match_low_similarity() -> FixtureResult {
    let score = expr_similarity("if x > 0 { x } else { -x }", "match x > 0 { true => x, false => -x }")?;
    check_score(&score, |value| value < 0.5, "if and match retain distinct structure")
  }

  /// Macro identity differences reject the whole invocation match.
  #[test]
  fn different_macro_names_score_zero() -> FixtureResult {
    let score = expr_similarity("println!(\"hello\")", "eprintln!(\"hello\")")?;
    check_score(
      &score,
      |value| value.to_bits() == 0.0_f64.to_bits(),
      "distinct macro names score zero",
    )
  }

  /// Additional macro arguments preserve a proper partial score.
  #[test]
  fn same_macro_different_arg_count_partial_similarity() -> FixtureResult {
    let score = expr_similarity("println!(\"a\")", "println!(\"a\", \"b\")")?;
    check_score(
      &score,
      |value| value > 0.0 && value < 1.0,
      "different macro arities score strictly between zero and one",
    )
  }

  // ── Grouper tests (syn-dependent) ─────────────────────────────────────────

  /// Equivalent functions group together while unrelated content stays outside.
  #[test]
  fn exact_duplicates_grouped() -> FixtureResult {
    let units = make_units(
      &[
        MULTILINE_PAIR,
        "
        fn unique(x: i32) -> i32 {
            x * x * x
        }
        ",
      ]
      .concat(),
    )?;
    let groups = grouper::group_exact_duplicates(&units);
    check_groups(groups, |observed| {
      ensure(
        matches!(observed, [group] if group.members.len() == 2 && group.similarity.to_bits() == 1.0_f64.to_bits()),
        "the duplicate pair forms one exact group with score one",
      )
      .map(drop)
    })
  }

  /// Distinct arithmetic functions do not produce exact groups.
  #[test]
  fn no_duplicates_no_groups() -> FixtureResult {
    let units = make_units(
      "
        fn add(x: i32) -> i32 { x + 1 }
        fn mul(x: i32) -> i32 { x * 2 }
        fn sub(x: i32) -> i32 { x - 3 }
        ",
    )?;
    let groups = grouper::group_exact_duplicates(&units);
    check_groups(groups, |observed| {
      ensure(observed.is_empty(), "unique functions form no exact groups").map(drop)
    })
  }

  /// Two independent duplicate families remain separate groups.
  #[test]
  fn multiple_exact_groups() -> FixtureResult {
    let units = make_units(
      "
        fn a1(x: i32) -> i32 { x + 1 }
        fn a2(y: i32) -> i32 { y + 1 }
        fn b1(x: i32) -> i32 { x * 2 }
        fn b2(y: i32) -> i32 { y * 2 }
        ",
    )?;
    let groups = grouper::group_exact_duplicates(&units);
    ensure_eq(groups.len(), 2, "independent duplicate families form two groups")
      .map(drop)
      .map_err(|source| FixtureFailure::GroupCount {
        units,
        groups,
        source,
      })
  }

  /// Realistic bodies differing locally remain detectable.
  #[test]
  fn near_duplicates_found() -> FixtureResult {
    let units = make_units(
      "
        fn process(data: i32) -> i32 {
            let a = data + 1;
            let b = a * 2;
            let c = b - 3;
            a + b + c
        }
        fn compute(value: i32) -> i32 {
            let a = value + 1;
            let b = a * 2;
            let c = b - 4;
            a + b + c
        }
        ",
    )?;
    let exact = grouper::group_exact_duplicates(&units);
    let exact_fps = grouper::member_fingerprints(&exact);
    let near = grouper::find_near_duplicates(&units, 0.7, &exact_fps).map_err(Box::new)?;
    Ok(ensure(!exact.is_empty() || !near.is_empty(), "locally changed bodies remain detectable").map(drop)?)
  }

  /// Statistics count the parsed corpus, grouped units, and source lines.
  #[test]
  fn stats_computation() -> FixtureResult {
    let units = make_units(
      "
        fn a(x: i32) -> i32 { x + 1 }
        fn b(y: i32) -> i32 { y + 1 }
        fn c(x: i32) -> i32 { x * 2 }
        ",
    )?;
    let exact = grouper::group_exact_duplicates(&units);
    let stats = grouper::compute_stats(&units, &exact, &[])?;
    ensure(
      (stats.total_code_units, stats.exact_duplicate_groups, stats.exact_duplicate_units) == (3, 1, 2),
      "statistics count the corpus and duplicate pair",
    )
    .map(drop)?;
    Ok(ensure(stats.total_lines > 0, "parsed source contributes lines").map(drop)?)
  }

  /// A function without a duplicate partner forms no group.
  #[test]
  fn single_unit_no_groups() -> FixtureResult {
    let units = make_units("fn solo(x: i32) -> i32 { x + 1 }")?;
    let groups = grouper::group_exact_duplicates(&units);
    check_groups(groups, |observed| {
      ensure(observed.is_empty(), "a single function has no duplicate partner").map(drop)
    })
  }

  /// Larger exact families precede smaller families.
  #[test]
  fn exact_groups_sorted_by_size() -> FixtureResult {
    let units = make_units(
      "
        fn a1(x: i32) -> i32 { x + 1 }
        fn a2(y: i32) -> i32 { y + 1 }
        fn a3(z: i32) -> i32 { z + 1 }
        fn b1(x: i32) -> i32 { x * 2 }
        fn b2(y: i32) -> i32 { y * 2 }
        ",
    )?;
    let groups = grouper::group_exact_duplicates(&units);
    check_groups(groups, |observed| {
      ensure(
        matches!(observed, [first, second] if (first.members.len(), second.members.len()) == (3, 2)),
        "exact families appear in descending membership order",
      )
      .map(drop)
    })
  }

  /// Exact-group members cannot appear again as a near group.
  #[test]
  fn near_duplicates_exclude_exact() -> FixtureResult {
    let units = make_units(EXACT_PAIR)?;
    let exact = grouper::group_exact_duplicates(&units);
    let exact_fps = grouper::member_fingerprints(&exact);
    let near = grouper::find_near_duplicates(&units, 0.7, &exact_fps).map_err(Box::new)?;
    check_groups(near, |observed| {
      ensure(observed.is_empty(), "exact members are excluded from near grouping").map(drop)
    })
  }

  /// A grouped duplicate family has a nonzero content identity.
  #[test]
  fn duplicate_group_has_fingerprint() -> FixtureResult {
    let units = make_units(EXACT_PAIR)?;
    let groups = grouper::group_exact_duplicates(&units);
    check_groups(groups, |observed| {
      ensure(
        matches!(observed, [group] if group.fingerprint.value() != 0),
        "the exact family carries a nonzero fingerprint",
      )
      .map(drop)
    })
  }

  /// Independently supplied near groups contribute to their own statistics.
  #[test]
  fn stats_with_near_duplicates() -> FixtureResult {
    let units = make_units(
      "
        fn a(x: i32) -> i32 { x + 1 }
        fn b(y: i32) -> i32 { y * 2 }
        ",
    )?;
    let composite_fp = Fingerprint::from_fingerprints(&[Fingerprint::from_node(&NormalizedNode::leaf(NodeKind::Opaque))]);
    let near_group = DuplicateGroup {
      suppressed:  None,
      also_seen:   Vec::new(),
      dimension:   DetectionDimension::Ast,
      match_kind:  grouper::MatchKind::Near,
      fingerprint: composite_fp,
      members:     vec![],
      similarity:  0.85,
    };
    let stats = grouper::compute_stats(&units, &[], &[near_group])?;
    Ok(
      ensure(
        (stats.total_code_units, stats.near_duplicate_groups) == (units.len(), 1),
        "near groups contribute without altering the corpus size",
      )
      .map(drop)?,
    )
  }

  /// Exact and near line counts remain distinct.
  #[test]
  fn stats_includes_line_counts() -> FixtureResult {
    let units = make_units(MULTILINE_PAIR)?;
    let exact = grouper::group_exact_duplicates(&units);
    let stats = grouper::compute_stats(&units, &exact, &[])?;
    Ok(
      ensure(
        stats.exact_duplicate_lines > 0 && stats.near_duplicate_lines == 0,
        "exact source lines do not contribute to near totals",
      )
      .map(drop)?,
    )
  }

  /// The corpus denominator includes lines even when no groups are supplied.
  #[test]
  fn stats_total_lines_computed() -> FixtureResult {
    let units = make_units(MULTILINE_PAIR)?;
    let stats = grouper::compute_stats(&units, &[], &[])?;
    Ok(ensure(stats.total_lines > 0, "ungrouped source contributes to the corpus denominator").map(drop)?)
  }

  // ── Extractor tests ───────────────────────────────────────────────────────

  /// Both arms of an if expression become nested candidates.
  #[test]
  fn extracts_if_branches() -> FixtureResult {
    check_nested_units(
      "fn foo(x: i32) -> i32 { if x > 0 { let y = x + 1; y * 2 } else { let z = x - 1; z * 3 } }",
      &[(CodeUnitKind::IfBranch, 2, None)],
    )
  }

  /// Every match arm becomes a nested candidate.
  #[test]
  fn extracts_match_arms() -> FixtureResult {
    check_nested_units(
      "fn foo(x: i32) -> i32 {
            match x {
                0 => { let a = 1; a + 1 },
                1 => { let b = 2; b + 2 },
                _ => { let c = 3; c + 3 },
            }
        }",
      &[(CodeUnitKind::MatchArm, 3, None)],
    )
  }

  /// The minimum size admits small candidates only at a suitable threshold.
  #[test]
  fn respects_min_node_count() -> FixtureResult {
    let body = parse_and_extract_body("fn foo(x: i32) -> i32 { if x > 0 { x + 1 } else { x - 1 } }")?;
    let subs_low = extractor::extract_sub_units(&body, 1);
    let subs_high = extractor::extract_sub_units(&body, 100);
    Ok(
      ensure(
        !subs_low.is_empty() && subs_high.is_empty(),
        "minimum size admits and rejects the same candidate population at the requested thresholds",
      )
      .map(drop)?,
    )
  }

  /// Equivalent branch content normalizes independently of parent parameters.
  #[test]
  fn identical_branches_from_different_functions_match() -> FixtureResult {
    let body1 = parse_and_extract_body("fn foo(unused: i32, x: i32) -> i32 { if x > 0 { let y = x + 1; y * 2 } else { x } }")?;
    let body2 = parse_and_extract_body("fn bar(a: i32) -> i32 { if a > 0 { let b = a + 1; b * 2 } else { a } }")?;

    let subs1 = extractor::extract_sub_units(&body1, 1);
    let subs2 = extractor::extract_sub_units(&body2, 1);

    let then1 = subs1.iter().find(|sub| sub.description == "if-then branch");
    let then2 = subs2.iter().find(|sub| sub.description == "if-then branch");
    Ok(
      ensure(
        matches!((then1, then2), (Some(first), Some(second)) if first.node == second.node),
        "both extracted then branches exist and normalize identically",
      )
      .map(drop)?,
    )
  }

  /// An extracted branch matches a freshly indexed equivalent expression.
  #[test]
  fn sub_units_are_reindexed() -> FixtureResult {
    let body = parse_and_extract_body("fn foo(a: i32, b: i32, c: i32) -> i32 { if c > 0 { let d = c + 1; d } else { c } }")?;
    let subs = extractor::extract_sub_units(&body, 1);
    let then_branch = subs.iter().find(|sub| sub.description == "if-then branch");

    let mut ctx = NormalizationContext::new();
    let fresh_expr = normalize_expr(&parse_expr("{ let d = c + 1; d }")?, &mut ctx);
    let reindexed_fresh = reindex_placeholders(&fresh_expr);
    Ok(
      ensure(
        then_branch.is_some_and(|branch| branch.node == reindexed_fresh),
        "the extracted branch uses fresh placeholder indices",
      )
      .map(drop)?,
    )
  }

  /// Nested loops and surrounding branches both remain discoverable.
  #[test]
  fn nested_structures_extracted_recursively() -> FixtureResult {
    check_nested_units(
      "fn foo(x: i32) -> i32 {
            if x > 0 {
                for i in 0..x {
                    let y = i + 1;
                    let _ = y;
                }
                x
            } else {
                x
            }
        }",
      &[(CodeUnitKind::IfBranch, 2, None), (CodeUnitKind::LoopBody, 1, None)],
    )
  }

  /// Each loop syntax yields one body, retaining its syntax-specific description.
  #[test]
  fn extracts_loop_bodies_with_syntax_descriptions() -> FixtureResult {
    for (input, description) in [
      ("fn foo(x: i32) { for i in 0..10 { let y = i + x; let _ = y; } }", None),
      (
        "fn foo(x: i32) { let mut i = 0; while i < x { let y = i + 1; i = y; } }",
        Some("while body"),
      ),
      (
        "fn foo(x: i32) -> i32 { let mut i = 0; loop { i += 1; if i > x { break i; } } }",
        Some("loop body"),
      ),
    ] {
      check_nested_units(input, &[(CodeUnitKind::LoopBody, 1, description)])?;
    }
    Ok(())
  }

  /// A block closure remains a discoverable nested unit.
  #[test]
  fn extracts_closure_bodies() -> FixtureResult {
    check_nested_units(
      "fn foo(data: Vec<i32>) -> Vec<i32> {
            data.iter().map(|x| {
                let y = x + 1;
                let z = y * 2;
                z
            }).collect()
        }",
      &[(CodeUnitKind::Block, 1, Some("closure body"))],
    )
  }

  /// Let-else identity preserves renaming while distinguishing the diverging behavior.
  #[test]
  fn let_else_fingerprints_track_diverging_behavior() -> FixtureResult {
    for (other, expected_equal) in [
      ("fn bar(x: Option<i32>) -> i32 { let Some(v) = x else { panic!(); }; v }", false),
      ("fn bar(y: Option<i32>) -> i32 { let Some(w) = y else { return 0; }; w }", true),
    ] {
      check_function_identity(
        &["fn foo(x: Option<i32>) -> i32 { let Some(v) = x else { return 0; }; v }", other],
        expected_equal,
      )?;
    }
    Ok(())
  }
}
