//! Detection-coverage regression harness over the frozen `detector_coverage`
//! fixture.
//!
//! Every pin asserts the CURRENT detector behavior and is updated together
//! with the change that flips it. All numeric values are measured actuals;
//! the qualitative expectations around them restate the contract in
//! `DETECTOR_REPORTABILITY.md`, so a pin that can only be satisfied by
//! contradicting that contract is a detector regression to investigate, not
//! a number to adjust.

use dupes_cli_test_support::CliTestFailure;
use dupes_cli_test_support::assert_member_needles_absent;
use dupes_cli_test_support::assert_stdout_contains;
use dupes_cli_test_support::cargo_dupes;
use dupes_cli_test_support::check_json;
use dupes_cli_test_support::fixture_json;
use dupes_cli_test_support::group_containing_member;
use dupes_cli_test_support::groups_of_dimension;
use dupes_cli_test_support::json_array;
use dupes_cli_test_support::json_count;
use dupes_cli_test_support::json_field;
use dupes_cli_test_support::json_text;
use dupes_cli_test_support::run_for_fixture;
use dupes_cli_test_support::suppressed_count_for_rule;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use serde_json::Value;
use strict_test_support::ensure;
use strict_test_support::ensure_eq;
use strict_test_support::ensure_some;

/// Frozen multi-rule detector input.
const FIXTURE: &str = "detector_coverage";
/// Default report with sub-function detection enabled.
const REPORT_ARGS: &[&str] = &["--sub-function", "--format", "json", "report"];
/// Stats over the same extracted population as the report.
const STATS_ARGS: &[&str] = &["--sub-function", "--format", "json", "stats"];
/// Report exposing suppressed groups and their attribution.
const SHOW_SUPPRESSED_REPORT_ARGS: &[&str] = &["--sub-function", "--show-suppressed", "--format", "json", "report"];

/// Line spans of every line-dimension member in files ending with `suffix`.
fn line_member_spans(report: &Value, suffix: &str) -> Result<Vec<(u64, u64)>, CliTestFailure> {
  let mut spans = Vec::new();
  for group in groups_of_dimension(report, "line")? {
    for member in json_array(json_field(group, "members")?)? {
      if json_text(json_field(member, "file")?)?.ends_with(suffix) {
        spans.push((json_count(member, "line_start")?, json_count(member, "line_end")?));
      }
    }
  }
  Ok(spans)
}

#[test]
fn stats_pins() -> Result<(), CliTestFailure> {
  check_json(fixture_json(cargo_dupes, FIXTURE, STATS_ARGS)?, |stats| {
    // The total covers the full extracted population, suppressed included.
    ensure_eq(json_count(stats, "total_code_units")?, 42, "total_code_units").map(drop)?;
    // ranges_overlap/spans_collide (size-cap release) and chain_x/chain_y.
    ensure_eq(json_count(stats, "exact_duplicate_groups")?, 2, "exact_duplicate_groups").map(drop)?;
    ensure_eq(json_count(stats, "exact_duplicate_units")?, 4, "exact_duplicate_units").map(drop)?;
    // collect/rank pairs at >= 0.9 plus the 0.8-threshold captures: the
    // *_total quartet, both touch/order pairs, the dispatch pair, and the
    // build_one/build_two runs (method-name preservation keeps them near).
    ensure_eq(json_count(stats, "near_duplicate_groups")?, 7, "near_duplicate_groups").map(drop)?;
    ensure_eq(json_count(stats, "near_duplicate_units")?, 16, "near_duplicate_units").map(drop)?;
    // The released 14-member apply branch group and the chain_x/chain_y
    // IfChain pair; the 6-member chain branch group is covered and hidden.
    ensure_eq(json_count(stats, "sub_exact_groups")?, 2, "sub_exact_groups").map(drop)?;
    ensure_eq(
      json_count(stats, "token_normalized_exact_groups")?,
      2,
      "token_normalized_exact_groups",
    )
    .map(drop)?;
    ensure_eq(
      json_count(stats, "token_normalized_near_groups")?,
      1,
      "token_normalized_near_groups",
    )
    .map(drop)?;
    ensure_eq(json_count(stats, "token_raw_exact_groups")?, 1, "token_raw_exact_groups").map(drop)?;
    // The Dense pair, the Renderer trio, the CliA/CliB stanza windows, and
    // at least one SpreadA/SpreadB table group admitted by the structural
    // stanza coalescer; the builder-run pair sits under group.covered-by-ast
    // because build_one/build_two form an ast near pair at the 0.8 threshold.
    // Closing the Cli declarations before the Spread blocks also retains the
    // Cli pair's own final window over its epsilon/zeta stanzas.
    ensure_eq(json_count(stats, "line_exact_groups")?, 9, "line_exact_groups").map(drop)?;
    // The Rust quote profile lexes the doc-comment apostrophes ("chain's")
    // as punctuation, so the overrides spans yield four signature-prefix
    // token windows over chain_x/chain_y and one suppressed group (the
    // identical normalized pair). Visibility-qualified field windows add
    // eight declaration-scaffold tags without changing visible groups.
    // Six low-signal windows that crossed completed declaration boundaries
    // are no longer extracted.
    ensure_eq(json_count(stats, "suppressed_unit_count")?, 102, "suppressed_unit_count").map(drop)?;
    ensure_eq(json_count(stats, "suppressed_group_count")?, 27, "suppressed_group_count").map(drop)?;
    Ok(())
  })
}

#[test]
fn suppressed_rule_attribution_pins() -> Result<(), CliTestFailure> {
  check_json(fixture_json(cargo_dupes, FIXTURE, STATS_ARGS)?, |stats| {
    // Every (rule, count) pair the fixture produces; the pins flip together
    // with any rule change. Note that simple field comparator closures
    // attribute to ast.forwarding-accessor (its check precedes the
    // comparator-adapter shape); call-based adapters reach the comparator
    // rule.
    let expected = [
      // Size-cap release: ranges_overlap/spans_collide (>= 24-node bodies)
      // are visible; only is_word_start/is_word_part stay suppressed.
      ("ast.boolean-projection", 2),
      ("ast.forwarding-accessor", 6),
      // Assignment setters and method-mutation setters both tag here.
      ("ast.setter-returning-self", 4),
      // Two covered groups: the chain_x/chain_y body windows shadowed by
      // the AST chain pair, and the admitted builder-run windows shadowed
      // by the build_one/build_two ast near pair at the 0.8 threshold.
      ("group.covered-by-ast", 2),
      // Six narrower stanza-window groups contained (>= 0.8) within wider
      // admitted groups over the same coalesced declaration blocks.
      ("group.overlap-contained", 6),
      ("line.chain-tail", 8),
      ("line.declaration-signature-prefix", 1),
      ("line.import-scaffold", 7),
      // Punctuation/header windows inside each coalesced declaration still
      // fall through to low-signal; windows never cross a completed type.
      ("line.low-signal", 30),
      // The six chain_x/chain_y branches, fully covered by the duplicated
      // IfChain pair; the 14 apply branches stay released and visible.
      ("sub.covered-by-chain", 6),
      ("sub.empty-default-return", 2),
      ("sub.message-only-macro", 2),
      ("sub.value-plumbing", 10),
      ("token.declaration-scaffold", 8),
      ("token.match-table-prefix", 2),
      // Includes the four chain_x/chain_y fn-head windows that the Rust
      // quote profile keeps segmented (both token modes, both files).
      ("token.signature-prefix", 14),
    ];
    let rules = json_field(stats, "suppressed_by_rule")?;
    let map = rules.as_object().ok_or_else(|| CliTestFailure::JsonShape {
      document: rules.clone(),
      context:  "suppression attribution must be an object",
    })?;
    for (rule, count) in expected {
      ensure_eq(suppressed_count_for_rule(stats, rule)?, count, rule).map(drop)?;
    }
    // The comparator rule must NOT fire here: the fixture's field-projection
    // comparators attribute to ast.forwarding-accessor (shadowing note above).
    ensure(
      !map.contains_key("ast.comparator-adapter"),
      "field comparators attribute to forwarding-accessor",
    )
    .map(drop)?;
    ensure_eq(map.len(), expected.len(), "no unexpected suppression rules fire").map(drop)?;
    Ok(())
  })
}

#[test]
fn show_suppressed_exposes_tagged_groups() -> Result<(), CliTestFailure> {
  check_json(fixture_json(cargo_dupes, FIXTURE, SHOW_SUPPRESSED_REPORT_ARGS)?, |report| {
    let suppressed = json_array(json_field(report, "suppressed_groups")?)?;
    ensure(!suppressed.is_empty(), "suppressed groups must be exposed").map(drop)?;
    let mut chain_covered = false;
    // The chain-covered chain_x branch members surface here with their rule.
    for group in suppressed {
      let rule = json_text(json_field(group, "suppressed")?)?;
      for member in json_array(json_field(group, "members")?)? {
        chain_covered |= rule == "sub.covered-by-chain" && json_text(json_field(member, "file")?)?.ends_with("overrides_a.rs");
      }
    }
    ensure(chain_covered, "chain-covered branch members must retain their suppression rule").map(drop)?;
    Ok(())
  })?;
  // Without the flag the array is absent from the document.
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    ensure(
      report.get("suppressed_groups").is_none(),
      "suppressed groups are omitted without the flag",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn text_report_renders_suppression_surface() -> Result<(), CliTestFailure> {
  assert_stdout_contains(
    run_for_fixture(cargo_dupes, FIXTURE, &["--sub-function", "stats"])?.try_success()?,
    &["Suppressed: 102 units, 27 groups (--show-suppressed to list)"],
  )?
  .try_stdout(contains("Suppressed by rule:").not())
  .map(drop)?;

  assert_stdout_contains(
    run_for_fixture(cargo_dupes, FIXTURE, &["--sub-function", "-v", "stats"])?.try_success()?,
    &[
      "Suppressed by rule:",
      "  sub.covered-by-chain: 6 units",
      "  group.covered-by-ast: 2 groups",
    ],
  )
  .map(drop)?;

  run_for_fixture(cargo_dupes, FIXTURE, &["--sub-function", "report"])?
    .try_success()?
    .try_stdout(contains("Suppressed Sub-function Exact Duplicates").not())
    .map(drop)?;

  assert_stdout_contains(
    run_for_fixture(cargo_dupes, FIXTURE, &["--sub-function", "--show-suppressed", "report"])?.try_success()?,
    &["Suppressed Sub-function Exact Duplicates", "[rule: sub.covered-by-chain]"],
  )
  .map(drop)
}

#[test]
fn disabling_a_rule_unhides_its_findings() -> Result<(), CliTestFailure> {
  // sub.value-plumbing hides the dispatch-arm group; disabling the rule
  // makes the arms a visible sub_ast group and removes the attribution.
  let run = |command| {
    let args = [
      "--sub-function", "--disable-rule", "sub.value-plumbing", "--format", "json", command,
    ];
    fixture_json(cargo_dupes, FIXTURE, &args)
  };
  check_json(run("report")?, |report| {
    let arms = ensure_some(
      group_containing_member(report, "match arm", "shapes.rs")?.cloned(),
      "dispatch arms become visible",
    )?;
    ensure_eq(
      (json_text(json_field(&arms, "dimension")?)?).to_owned(),
      "sub_ast".to_owned(),
      "released dispatch-arm dimension",
    )
    .map(drop)?;
    Ok(())
  })?;
  check_json(run("stats")?, |stats| {
    ensure_eq(
      suppressed_count_for_rule(stats, "sub.value-plumbing")?,
      0,
      "disabled rules have no attributed suppression",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn identical_if_chains_group_as_whole_chains() -> Result<(), CliTestFailure> {
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    let chain_fns = ensure_some(
      group_containing_member(report, "chain_x", "overrides_a.rs")?.cloned(),
      "chain function pair",
    )?;
    ensure_eq(
      (json_text(json_field(&chain_fns, "dimension")?)?).to_owned(),
      "ast".to_owned(),
      "chain function dimension",
    )
    .map(drop)?;
    ensure(
      group_containing_member(report, "chain_y", "overrides_b.rs")?.is_some(),
      "the chain pair spans both files",
    )
    .map(drop)?;
    let chain_subs = ensure_some(
      group_containing_member(report, "if chain (3 branches)", "overrides_a.rs")?.cloned(),
      "chain sub-unit pair",
    )?;
    ensure_eq(
      (json_text(json_field(&chain_subs, "dimension")?)?).to_owned(),
      "sub_ast".to_owned(),
      "chain sub-unit dimension",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn override_branch_duplication_is_released() -> Result<(), CliTestFailure> {
  // The apply_a/apply_b rows share one branch shape across 14 regions and
  // their chains never group, so release-on-no-match keeps the cross-file
  // IfBranch group visible; the chain_x/chain_y branches stay hidden under
  // sub.covered-by-chain.
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    ensure_eq(groups_of_dimension(report, "sub_ast")?.len(), 2, "released branch and chain groups").map(drop)?;
    let released = ensure_some(
      group_containing_member(report, "if-then branch", "overrides_a.rs")?.cloned(),
      "released apply-branch group",
    )?;
    ensure_eq(
      (json_text(json_field(&released, "dimension")?)?).to_owned(),
      "sub_ast".to_owned(),
      "released branch dimension",
    )
    .map(drop)?;
    let members = json_array(json_field(&released, "members")?)?;
    ensure_eq(members.len(), 14, "all apply branches remain visible").map(drop)?;
    let mut in_second_file = false;
    // Only apply rows may appear: apply_a spans lines 6-34 of overrides_a.rs
    // and apply_b spans lines 6-22 of overrides_b.rs; the chain branches
    // (lines 39+ / 27+) belong to the covered group.
    for member in members {
      let file = json_text(json_field(member, "file")?)?;
      let start = json_count(member, "line_start")?;
      in_second_file |= file.ends_with("overrides_b.rs");
      if file.ends_with("overrides_a.rs") {
        ensure(start <= 34, "chain branch leaked into the released group").map(drop)?;
      } else {
        ensure(start <= 22, "chain branch leaked into the released group").map(drop)?;
      }
    }
    ensure(in_second_file, "the released group spans both files").map(drop)?;
    Ok(())
  })
}

#[test]
fn declaration_stanzas_are_admitted() -> Result<(), CliTestFailure> {
  // The structural stanza coalescer joins blank-separated doc/attr/field
  // stanzas (including the derive-headed table and the final stanza that
  // carries the closing brace), and line.declaration-stanza admits their
  // windows.
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    let decl_members = line_member_spans(report, "decl_a.rs")?;
    // CliA stanza rows span lines 12-34: admitted windows must reach both the
    // first stanza (start <= 14) and the final stanza (end >= 32).
    ensure(
      decl_members.iter().any(|&(start, _)| start <= 14),
      "no admitted window reaches the first CliA stanza",
    )
    .map(drop)?;
    ensure(
      decl_members.iter().any(|&(_, end)| end >= 32),
      "no admitted window reaches the final CliA stanza",
    )
    .map(drop)?;
    ensure(
      decl_members.contains(&(29, 34)),
      "the final CliA window stays anchored inside its own declaration",
    )
    .map(drop)?;
    // At least one admitted window lies inside the SpreadA row span (40-50).
    ensure(
      decl_members.iter().any(|&(start, end)| start >= 40 && end <= 50),
      "no admitted window covers the SpreadA/SpreadB table",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn contiguous_derive_table_is_visible() -> Result<(), CliTestFailure> {
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    // DenseA's rows live at decl_a.rs lines 57-62; the pair with DenseB is
    // visible without any admission carve-out.
    let mut dense_pair = false;
    for group in groups_of_dimension(report, "line")? {
      let mut first = false;
      let mut second = false;
      for member in json_array(json_field(group, "members")?)? {
        let file = json_text(json_field(member, "file")?)?;
        first |= file.ends_with("decl_a.rs") && json_count(member, "line_start")? >= 57;
        second |= file.ends_with("decl_b.rs");
      }
      dense_pair |= first && second;
    }
    ensure(dense_pair, "DenseA and DenseB must share a visible line group").map(drop)?;
    Ok(())
  })
}

#[test]
fn builder_runs_are_admitted() -> Result<(), CliTestFailure> {
  // The identical six-step runs in build_one (lines 18-23) and build_two
  // (lines 29-34) are admitted via line.builder-chain-run. At the 0.8 near
  // threshold the whole fns also pair in the ast dimension, so the admitted
  // line shadow carries group.covered-by-ast instead of rendering twice;
  // the tail_one/tail_two fragments (lines 39+) stay chain-tail suppressed.
  check_json(fixture_json(cargo_dupes, FIXTURE, SHOW_SUPPRESSED_REPORT_ARGS)?, |report| {
    let builders = ensure_some(
      group_containing_member(report, "build_one", "builders.rs")?.cloned(),
      "builder function pair",
    )?;
    ensure_eq(
      (json_text(json_field(&builders, "dimension")?)?).to_owned(),
      "ast".to_owned(),
      "builder pair dimension",
    )
    .map(drop)?;
    ensure_eq(
      (json_text(json_field(&builders, "match_kind")?)?).to_owned(),
      "near".to_owned(),
      "builder pair match kind",
    )
    .map(drop)?;
    let mut covered = false;
    for group in json_array(json_field(report, "suppressed_groups")?)? {
      if json_text(json_field(group, "suppressed")?)? != "group.covered-by-ast" {
        continue;
      }
      for member in json_array(json_field(group, "members")?)? {
        covered |= json_text(json_field(member, "file")?)?.ends_with("builders.rs")
          && json_count(member, "line_start")? >= 18
          && json_count(member, "line_end")? <= 23;
      }
    }
    ensure(covered, "the admitted builder run retains AST coverage attribution").map(drop)?;
    Ok(())
  })?;
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    ensure(
      line_member_spans(report, "builders.rs")?.is_empty(),
      "AST coverage removes the builder line shadow",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn capped_boolean_projections_surface_while_trivial_shapes_stay_suppressed() -> Result<(), CliTestFailure> {
  // TRIVIAL_BODY_MAX_NODES releases the >= 24-node ranges_overlap and
  // spans_collide pair into a visible ast group; genuinely trivial shapes
  // (setters, accessors, small projections, comparator closures) stay
  // rule-suppressed.
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    let released = ensure_some(
      group_containing_member(report, "ranges_overlap", "shapes.rs")?.cloned(),
      "size-cap released function pair",
    )?;
    ensure_eq(
      (json_text(json_field(&released, "dimension")?)?).to_owned(),
      "ast".to_owned(),
      "released function dimension",
    )
    .map(drop)?;
    ensure_eq(
      (json_text(json_field(&released, "match_kind")?)?).to_owned(),
      "exact".to_owned(),
      "released function match kind",
    )
    .map(drop)?;
    ensure(
      group_containing_member(report, "spans_collide", "shapes.rs")?.is_some(),
      "the size-cap release includes both functions",
    )
    .map(drop)?;
    assert_member_needles_absent(
      report,
      &[
        "with_level", "with_scale", "push_item", "push_mark", "level_for", "mark_for", "is_word_start", "is_word_part", "closure at",
      ],
      "shapes.rs",
      "must stay suppressed",
    )
  })
}

#[test]
fn mutation_setters_are_suppressed_with_attribution() -> Result<(), CliTestFailure> {
  // Method-mutation setters join ast.setter-returning-self; the pair
  // stays detected and recoverable via --show-suppressed.
  check_json(fixture_json(cargo_dupes, FIXTURE, SHOW_SUPPRESSED_REPORT_ARGS)?, |report| {
    let mut setters = None;
    for group in json_array(json_field(report, "suppressed_groups")?)? {
      if json_text(json_field(group, "suppressed")?)? != "ast.setter-returning-self" {
        continue;
      }
      let names = json_array(json_field(group, "members")?)?
        .iter()
        .map(|member| json_text(json_field(member, "name")?).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
      if names.iter().any(|name| name == "Gauge::push_item") {
        setters = Some(names);
        break;
      }
    }
    ensure(
      ensure_some(setters, "mutation-setter pair")? == ["Gauge::push_item", "Gauge::push_mark"],
      "the mutation-setter pair groups alone",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn sub_unit_noise_shapes_stay_suppressed() -> Result<(), CliTestFailure> {
  // Message-only writeln branches, empty-default guards, and dispatch arms
  // are tagged sub units (sub.message-only-macro, sub.empty-default-return,
  // sub.value-plumbing) and never surface in the default report.
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    ensure(
      group_containing_member(report, "if-then branch", "shapes.rs")?.is_none(),
      "guard branches stay suppressed",
    )
    .map(drop)?;
    ensure(
      group_containing_member(report, "match arm", "shapes.rs")?.is_none(),
      "dispatch arms stay suppressed",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn impl_signature_parity_stays_visible() -> Result<(), CliTestFailure> {
  // The Renderer parameter rows pair across the trait and both impls; the
  // fn-led declaration-side window is rejected, the parameter-row windows
  // survive.
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    let mut parity = None;
    for group in groups_of_dimension(report, "line")? {
      let members = json_array(json_field(group, "members")?)?;
      let files = members
        .iter()
        .map(|member| json_text(json_field(member, "file")?))
        .collect::<Result<Vec<_>, _>>()?;
      if files.len() == 3 && files.iter().all(|file| file.ends_with("shapes.rs")) {
        parity = Some(group);
        break;
      }
    }
    ensure_eq(
      (json_text(json_field(
        &ensure_some(parity.cloned(), "Renderer signature parity group")?,
        "match_kind",
      )?)?)
      .to_owned(),
      "exact".to_owned(),
      "signature parity match kind",
    )
    .map(drop)?;
    Ok(())
  })
}

#[test]
fn import_scaffolding_line_windows_stay_invisible() -> Result<(), CliTestFailure> {
  // The shared decl_a/decl_b header + import block surfaces as token
  // windows today (pinned via stats), but the line dimension keeps
  // rejecting import scaffolds: no line window may start in the import
  // block region (lines 1-7).
  check_json(fixture_json(cargo_dupes, FIXTURE, REPORT_ARGS)?, |report| {
    for suffix in ["decl_a.rs", "decl_b.rs"] {
      for (start, _) in line_member_spans(report, suffix)? {
        ensure(start > 7, "line windows must start after the import block").map(drop)?;
      }
    }
    Ok(())
  })
}
