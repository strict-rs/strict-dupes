//! Suppression-rule registry.
//!
//! Every noise judgment the detector makes is a named rule. `Suppress` rules
//! tag candidate units/groups that stay out of the default report; `Admit`
//! rules are named carve-outs that turn otherwise-rejected window shapes into
//! visible candidates. Rules are toggled via `[suppress]` config and the
//! `--disable-rule`/`--enable-rule` CLI flags; disabling a `Suppress` rule
//! makes its candidates fully visible, disabling an `Admit` rule reverts its
//! windows to their base suppression.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::code_unit::DetectionDimension;

/// Stable identity of a suppression or admission rule.
///
/// The string form is `"<scope>.<shape>"` via [`RuleId::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleId {
  /// `ast.setter-returning-self`: builder setter ending in `self`.
  AstSetterReturningSelf,
  /// `ast.forwarding-accessor`: single forwarding method call.
  AstForwardingAccessor,
  /// `ast.boolean-projection`: bare boolean combination of projections.
  AstBooleanProjection,
  /// `ast.comparator-adapter`: `key(a).cmp(&key(b))`-shaped closure.
  AstComparatorAdapter,
  /// `sub.no-structure`: sub-unit without meaningful structure.
  SubNoStructure,
  /// `sub.trivial-predicate`: comparison or boolean of simple values.
  SubTrivialPredicate,
  /// `sub.empty-default-return`: guard returning an empty/default value.
  SubEmptyDefaultReturn,
  /// `sub.message-only-macro`: branch that only writes a message.
  SubMessageOnlyMacro,
  /// `sub.value-plumbing`: call chain that only shuttles simple values.
  SubValuePlumbing,
  /// `sub.covered-by-chain`: if-branch whose whole chain grouped.
  SubCoveredByChain,
  /// `token.import-scaffold`: window over import/module scaffolding.
  TokenImportScaffold,
  /// `token.chain-tail`: window dominated by detached chain tails.
  TokenChainTail,
  /// `token.signature-prefix`: window cut from a doc-led signature prefix.
  TokenSignaturePrefix,
  /// `token.declaration-scaffold`: window over type-declaration scaffolding.
  TokenDeclarationScaffold,
  /// `token.match-table-prefix`: window stopping mid match-arm table.
  TokenMatchTablePrefix,
  /// `token.low-signal`: window without enough meaningful content.
  TokenLowSignal,
  /// `line.import-scaffold`: window over import/module scaffolding.
  LineImportScaffold,
  /// `line.chain-tail`: window dominated by detached chain tails.
  LineChainTail,
  /// `line.declaration-signature-prefix`: window over fn-declaration rows.
  LineDeclarationSignaturePrefix,
  /// `line.low-signal`: window without enough meaningful content.
  LineLowSignal,
  /// `line.declaration-stanza`: admits uniform declaration-stanza windows.
  LineDeclarationStanza,
  /// `line.builder-chain-run`: admits complete single-line builder runs.
  LineBuilderChainRun,
  /// `group.covered-by-ast`: window group covered by an AST group.
  GroupCoveredByAst,
  /// `group.overlap-contained`: group contained in a wider same-dimension group.
  GroupOverlapContained,
}

/// Whether a rule tags individual units or whole groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLevel {
  /// The rule tags individual candidate units.
  Unit,
  /// The rule tags whole duplicate groups.
  Group,
}

/// Whether a rule suppresses candidates or admits otherwise-rejected ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
  /// Tags candidates so they stay out of the default report.
  Suppress,
  /// Turns otherwise-rejected window shapes into visible candidates.
  Admit,
}

/// One registry row.
#[derive(Debug, Clone, Copy)]
pub struct SuppressionRule {
  /// The rule's stable identity.
  pub id:          RuleId,
  /// Whether the rule tags units or groups.
  pub level:       RuleLevel,
  /// Whether the rule suppresses or admits.
  pub action:      RuleAction,
  /// Detection dimensions the rule applies to.
  pub dimensions:  &'static [DetectionDimension],
  /// Human-readable description rendered in rule listings.
  pub description: &'static str,
}

/// Token windows share suppression rules across raw and normalized modes.
const TOKEN_DIMENSIONS: &[DetectionDimension] = &[DetectionDimension::TokenNormalized, DetectionDimension::TokenRaw];
/// Dimensions whose groups can be covered by AST findings or wider windows.
const GENERIC_DIMENSIONS: &[DetectionDimension] = &[
  DetectionDimension::TokenNormalized,
  DetectionDimension::TokenRaw,
  DetectionDimension::Line,
];

/// The full rule registry. Every rule ships enabled.
pub static RULES: &[SuppressionRule] = &[
  SuppressionRule {
    id:          RuleId::AstSetterReturningSelf,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Ast],
    description: "builder setter: field assignment or simple mutation followed by `self`",
  },
  SuppressionRule {
    id:          RuleId::AstForwardingAccessor,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Ast],
    description: "single method call forwarding simple values",
  },
  SuppressionRule {
    id:          RuleId::AstBooleanProjection,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Ast],
    description: "bare boolean combination of simple projections",
  },
  SuppressionRule {
    id:          RuleId::AstComparatorAdapter,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Ast],
    description: "closure of `key(a).cmp(&key(b))` shape",
  },
  SuppressionRule {
    id:          RuleId::SubNoStructure,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::SubAst],
    description: "sub-unit without bindings, control flow, calls, or arithmetic",
  },
  SuppressionRule {
    id:          RuleId::SubTrivialPredicate,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::SubAst],
    description: "comparison or boolean of simple values",
  },
  SuppressionRule {
    id:          RuleId::SubEmptyDefaultReturn,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::SubAst],
    description: "guard returning an empty or default construction",
  },
  SuppressionRule {
    id:          RuleId::SubMessageOnlyMacro,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::SubAst],
    description: "branch that only writes a message",
  },
  SuppressionRule {
    id:          RuleId::SubValuePlumbing,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::SubAst],
    description: "call or method chain that only shuttles simple values",
  },
  SuppressionRule {
    id:          RuleId::SubCoveredByChain,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::SubAst],
    description: "if-branch whose owning if-chain grouped as a whole",
  },
  SuppressionRule {
    id:          RuleId::TokenImportScaffold,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  TOKEN_DIMENSIONS,
    description: "token window over import or module scaffolding",
  },
  SuppressionRule {
    id:          RuleId::TokenChainTail,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  TOKEN_DIMENSIONS,
    description: "token window dominated by detached method-chain tails",
  },
  SuppressionRule {
    id:          RuleId::TokenSignaturePrefix,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  TOKEN_DIMENSIONS,
    description: "token window cut from a doc-led signature prefix",
  },
  SuppressionRule {
    id:          RuleId::TokenDeclarationScaffold,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  TOKEN_DIMENSIONS,
    description: "token window over type-declaration scaffolding",
  },
  SuppressionRule {
    id:          RuleId::TokenMatchTablePrefix,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  TOKEN_DIMENSIONS,
    description: "token window stopping mid-way through a match-arm table",
  },
  SuppressionRule {
    id:          RuleId::TokenLowSignal,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  TOKEN_DIMENSIONS,
    description: "token window without enough meaningful or unique content",
  },
  SuppressionRule {
    id:          RuleId::LineImportScaffold,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Line],
    description: "line window over import or module scaffolding",
  },
  SuppressionRule {
    id:          RuleId::LineChainTail,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Line],
    description: "line window dominated by detached method-chain tails",
  },
  SuppressionRule {
    id:          RuleId::LineDeclarationSignaturePrefix,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Line],
    description: "line window over the opening rows of a fn declaration",
  },
  SuppressionRule {
    id:          RuleId::LineLowSignal,
    level:       RuleLevel::Unit,
    action:      RuleAction::Suppress,
    dimensions:  &[DetectionDimension::Line],
    description: "line window without enough meaningful or unique content",
  },
  SuppressionRule {
    id:          RuleId::LineDeclarationStanza,
    level:       RuleLevel::Unit,
    action:      RuleAction::Admit,
    dimensions:  &[DetectionDimension::Line],
    description: "uniform doc/attr/field stanza windows admitted across blank-separated declaration blocks",
  },
  SuppressionRule {
    id:          RuleId::LineBuilderChainRun,
    level:       RuleLevel::Unit,
    action:      RuleAction::Admit,
    dimensions:  &[DetectionDimension::Line],
    description: "windows made entirely of complete single-line builder steps",
  },
  SuppressionRule {
    id:          RuleId::GroupCoveredByAst,
    level:       RuleLevel::Group,
    action:      RuleAction::Suppress,
    dimensions:  GENERIC_DIMENSIONS,
    description: "token or line group fully covered by one AST or sub-AST group",
  },
  SuppressionRule {
    id:          RuleId::GroupOverlapContained,
    level:       RuleLevel::Group,
    action:      RuleAction::Suppress,
    dimensions:  GENERIC_DIMENSIONS,
    description: "window group contained within a wider same-dimension group",
  },
];

impl RuleId {
  /// The dotted string id used in config, CLI flags, stats, and reports.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::AstSetterReturningSelf => "ast.setter-returning-self",
      Self::AstForwardingAccessor => "ast.forwarding-accessor",
      Self::AstBooleanProjection => "ast.boolean-projection",
      Self::AstComparatorAdapter => "ast.comparator-adapter",
      Self::SubNoStructure => "sub.no-structure",
      Self::SubTrivialPredicate => "sub.trivial-predicate",
      Self::SubEmptyDefaultReturn => "sub.empty-default-return",
      Self::SubMessageOnlyMacro => "sub.message-only-macro",
      Self::SubValuePlumbing => "sub.value-plumbing",
      Self::SubCoveredByChain => "sub.covered-by-chain",
      Self::TokenImportScaffold => "token.import-scaffold",
      Self::TokenChainTail => "token.chain-tail",
      Self::TokenSignaturePrefix => "token.signature-prefix",
      Self::TokenDeclarationScaffold => "token.declaration-scaffold",
      Self::TokenMatchTablePrefix => "token.match-table-prefix",
      Self::TokenLowSignal => "token.low-signal",
      Self::LineImportScaffold => "line.import-scaffold",
      Self::LineChainTail => "line.chain-tail",
      Self::LineDeclarationSignaturePrefix => "line.declaration-signature-prefix",
      Self::LineLowSignal => "line.low-signal",
      Self::LineDeclarationStanza => "line.declaration-stanza",
      Self::LineBuilderChainRun => "line.builder-chain-run",
      Self::GroupCoveredByAst => "group.covered-by-ast",
      Self::GroupOverlapContained => "group.overlap-contained",
    }
  }

  /// Parse a dotted rule id back to its identity.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Rule lookup owns the public mapping from configured identifiers to canonical registry identities."
  )]
  pub fn parse(id_text: &str) -> Option<Self> {
    Self::all().iter().copied().find(|id| id.as_str() == id_text)
  }

  /// Every rule id, in registry order.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "The public registry enumeration keeps rule parsing and consumer listings tied to the same ordered identities"
  )]
  pub fn all() -> &'static [Self] {
    /// Rule identities materialized once from the canonical registry rows.
    static ALL: OnceLock<Vec<RuleId>> = OnceLock::new();
    ALL.get_or_init(|| RULES.iter().map(|rule| rule.id).collect())
  }
}

/// The resolved active rule set: registry defaults plus config/CLI toggles.
#[derive(Debug, Clone, Default)]
pub struct SuppressionPolicy {
  /// Rules disabled after applying registry defaults and ordered overrides.
  disabled: BTreeSet<RuleId>,
}

/// A nonfatal rule-selection failure with the complete requested identifier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuppressionWarning {
  /// A disable request did not name a registered rule.
  #[error("unknown suppression rule id: {id}")]
  UnknownDisabledRule {
    /// Exact identifier supplied in the disable list.
    id: String,
  },
  /// An enable request did not name a registered rule.
  #[error("unknown suppression rule id: {id}")]
  UnknownEnabledRule {
    /// Exact identifier supplied in the enable list.
    id: String,
  },
}

impl SuppressionPolicy {
  /// Resolve a policy from disable/enable id lists.
  ///
  /// Enable wins over disable so CLI `--enable-rule` can override a config
  /// `[suppress] disable` entry. Unknown ids produce warnings, never errors.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Resolving a complete rule policy is a public configuration operation distinct from applying incremental toggles"
  )]
  pub fn resolve(disable: &[String], enable: &[String]) -> (Self, Vec<SuppressionWarning>) {
    let mut policy = Self::default();
    let warnings = policy.apply_toggles(disable, enable);
    (policy, warnings)
  }

  /// Apply ordered disable/enable requests and retain every unknown identifier.
  ///
  /// Unknown identifiers leave the active policy unchanged and report which
  /// requested operation could not be applied. Enable requests run last.
  #[must_use]
  pub fn apply_toggles(&mut self, disable: &[String], enable: &[String]) -> Vec<SuppressionWarning> {
    let mut warnings = Vec::new();
    let toggles = disable
      .iter()
      .map(|id_text| (id_text, true))
      .chain(enable.iter().map(|id_text| (id_text, false)));
    for (id_text, disabling) in toggles {
      match (RuleId::parse(id_text), disabling) {
        (Some(id), true) => self.disabled.extend([id]),
        (Some(id), false) => self.disabled.retain(|candidate| *candidate != id),
        (None, true) => warnings.push(SuppressionWarning::UnknownDisabledRule {
          id: id_text.clone()
        }),
        (None, false) => warnings.push(SuppressionWarning::UnknownEnabledRule {
          id: id_text.clone()
        }),
      }
    }
    warnings
  }

  /// Whether a rule is active.
  #[must_use]
  pub fn is_enabled(&self, id: RuleId) -> bool {
    !self.disabled.contains(&id)
  }

  /// `Some(id)` iff the rule is active; classifiers compose with this.
  #[must_use]
  pub fn allow(&self, id: RuleId) -> Option<RuleId> {
    self.is_enabled(id).then_some(id)
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;

  use strict_test_support::ComparisonFailure;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::RULES;
  use super::RuleAction;
  use super::RuleId;
  use super::SuppressionPolicy;
  use super::SuppressionWarning;

  /// Every identity is represented once in the canonical registry.
  #[test]
  fn every_rule_id_has_exactly_one_registry_row() -> Result<(), ComparisonFailure<usize, usize>> {
    for id in RuleId::all() {
      ensure_eq(RULES.iter().filter(|rule| rule.id == *id).count(), 1, id.as_str()).map(drop)?;
    }
    ensure_eq(
      RULES.len(),
      RuleId::all().len(),
      "registry rows and identities have the same cardinality",
    )
    .map(drop)
  }

  /// Stable rule strings are unique and parse back to their complete identities.
  #[test]
  fn rule_id_strings_are_unique_and_round_trip() -> Result<(), ConditionFailure> {
    let mut seen = BTreeSet::new();
    for id in RuleId::all() {
      ensure(seen.insert(id.as_str()), id.as_str()).map(drop)?;
      ensure(
        RuleId::parse(id.as_str()) == Some(*id),
        "rule text round-trips to its complete identity",
      )
      .map(drop)?;
    }
    ensure(RuleId::parse("ast.unknown-rule").is_none(), "unknown rule identifiers are rejected").map(drop)
  }

  /// Admission remains restricted to the declared line-shape rules.
  #[test]
  fn admit_rules_are_exactly_the_line_carve_outs() -> Result<(), ConditionFailure> {
    let admits: Vec<RuleId> = RULES
      .iter()
      .filter(|rule| rule.action == RuleAction::Admit)
      .map(|rule| rule.id)
      .collect();
    ensure(
      admits == [RuleId::LineDeclarationStanza, RuleId::LineBuilderChainRun],
      "only the declared line rules admit candidates",
    )
    .map(drop)
  }

  /// Enable wins after disable, while unknown requests retain their direction and text.
  #[test]
  fn policy_resolution_applies_disable_then_enable_with_warnings() -> Result<(), ConditionFailure> {
    let (enabled_policy, unknown_warnings) = SuppressionPolicy::resolve(&["line.chain-tail".to_owned(), "no.such-rule".to_owned()], &[
      "line.chain-tail".to_owned(),
      "no.such-rule".to_owned(),
    ]);
    ensure(enabled_policy.is_enabled(RuleId::LineChainTail), "enable overrides disable").map(drop)?;
    ensure(
      unknown_warnings
        == [
          SuppressionWarning::UnknownDisabledRule {
            id: "no.such-rule".to_owned(),
          },
          SuppressionWarning::UnknownEnabledRule {
            id: "no.such-rule".to_owned(),
          },
        ],
      "unknown identifiers retain each requested action in application order",
    )
    .map(drop)?;

    let (disabled_policy, known_warnings) = SuppressionPolicy::resolve(&["sub.value-plumbing".to_owned()], &[]);
    ensure(known_warnings.is_empty(), "known identifiers do not warn").map(drop)?;
    ensure(
      !disabled_policy.is_enabled(RuleId::SubValuePlumbing),
      "disabled rules stay inactive",
    )
    .map(drop)?;
    ensure(
      disabled_policy.allow(RuleId::SubValuePlumbing).is_none(),
      "disabled classifiers cannot tag candidates",
    )
    .map(drop)?;
    ensure(
      disabled_policy.allow(RuleId::SubNoStructure) == Some(RuleId::SubNoStructure),
      "other active rules retain their identity",
    )
    .map(drop)
  }

  /// Incremental requests preserve unrelated policy and override earlier layers.
  #[test]
  fn toggles_layer_on_top_of_an_existing_policy() -> Result<(), ConditionFailure> {
    let (mut policy, initial_warnings) = SuppressionPolicy::resolve(&["line.chain-tail".to_owned()], &[]);
    ensure(initial_warnings.is_empty(), "the initial policy uses known rules").map(drop)?;
    let overlay_warnings = policy.apply_toggles(&["token.low-signal".to_owned()], &["line.chain-tail".to_owned()]);
    ensure(overlay_warnings.is_empty(), "the overlay uses known rules").map(drop)?;
    ensure(
      policy.is_enabled(RuleId::LineChainTail),
      "the overlay re-enables the existing disabled rule",
    )
    .map(drop)?;
    ensure(!policy.is_enabled(RuleId::TokenLowSignal), "the overlay disables its selected rule").map(drop)
  }
}
