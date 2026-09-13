# Future enhancements

## Checked numeric capabilities and exact-ratio evaluation

Status: recorded for future consideration. The numeric contract below is selected for the current repair; the dependency candidates and an exact-ratio redesign are deferred choices, not implementation authorization.

### Selected contract for the current repair

- Preserve the current rounded `f64` threshold semantics and operation ordering. Do not silently replace threshold comparisons with exact rational or decimal comparisons.
- Retain the original integer evidence alongside derived numeric outcomes. A converted count or rendered percentage does not replace its source observations.
- Return complete, subject-specific typed calculation failures, including the original inputs, the failed calculation, completed results, and the native cause or rejected result where applicable.
- Keep calculation, validation, and any handling promised by the operation inside the library. The caller chooses its subsequent application workflow after receiving the complete outcome.
- Do not introduce automatic clamping, threshold adjustment, alternative detection workflows, or new recovery mechanics merely because a calculation can fail.

These requirements remain current repair obligations. Recording the broader proposal here does not defer them or select a dependency implementation.

### Capability and ownership

`dupes-core` owns language-independent similarity scoring, duplicate grouping, and duplication statistics. Strengthen those existing owners instead of creating parallel numeric representations in reporters or consuming projects.

The reviewed formulas and boundary behavior are:

- `dupes-core/src/similarity.rs` calculates the Dice score as `2 × matching_nodes / (first_nodes + second_nodes)`, with an `f64` result and a defined score of `1.0` for two empty trees.
- `dupes-core/src/grouper.rs` calculates duplication percentages as `duplicate_lines / total_lines × 100`, with a defined result of `0.0` for an empty corpus.
- Integer counting and accumulation precede floating-point arithmetic. Checked floating-point operations do not repair an overflowing integer total upstream.

Keep three decisions separate: the numerical behavior promised by the library, the dependency supplying primitive arithmetic mechanics, and the domain outcomes propagated through analysis and reporting. A dependency can supply mechanics without owning the full domain contract.

### Candidate: `checked-float 0.1.5`

`checked-float` provides a wrapper whose floating-point operations validate their results with a caller-supplied `FloatChecker`. The checker defines the invariant and associated error type. Rejected `NaN`, infinity, or out-of-range results can become typed failures. The checker receives the resulting value, so the domain owner must separately preserve the operands, operation, subject identities, and completed work. [Implementation source](https://raw.githubusercontent.com/dragazo/checked-float/c205ac3b22a6b7b90482a02cb32802960925eb29/src/lib.rs).

Required distinctions when evaluating this candidate:

- Intermediate operands need their own valid range. Node counts can exceed `1`; the completed similarity score's `0.0..=1.0` invariant cannot be imposed on every intermediate value.
- Preserve the defined empty-input results. Generic division checks must not silently replace those domain rules.
- Establish the counting invariant before enforcing a percentage ceiling of `100`. The name alone does not decide how independently supplied or overlapping counts are valid.
- Ordinary rounding remains possible. Finite-value checks accept rounded finite results, including underflow to zero; they do not establish exactness.
- The source forbids `unsafe`, but its generic ordering implementation contains an `unwrap()` after excluding `NaN`. The native `f64` branch has a meaningful justification; this does not establish an unconditional panic-free guarantee for every generic implementation or the full dependency graph.

The benefit is reusable invariant enforcement. The costs include another dependency and correct maintenance of its checker contract. The reviewed release is `0.1.5`, published on November 23, 2023, with edition `2021`, an `MIT OR Apache-2.0` license, and no declared minimum Rust version in its manifest. Release age is maintenance evidence, not proof of unsuitability. [Release history](https://docs.rs/crate/checked-float/latest), [versioned manifest](https://raw.githubusercontent.com/dragazo/checked-float/c205ac3b22a6b7b90482a02cb32802960925eb29/Cargo.toml).

### Candidate: direct `num-traits 0.2.19`

The proposed direct use is an explicit conversion API such as `ToPrimitive::to_f64()`. Its contract permits precision loss: integer `9_007_199_254_740_993` rounds to `9_007_199_254_740_992.0` in `f64`. A successful `Some(value)` therefore does not prove exact representation of the source integer. Any future exactness guarantee requires its own declared contract and enforcement. [Official conversion documentation](https://docs.rs/num-traits/latest/num_traits/cast/trait.ToPrimitive.html).

At the September 13, 2026 review, the fork's lockfile already contained `num-traits 0.2.19` and its `autocfg` dependency; `dupes-core` did not declare it directly. A compatible direct declaration would ordinarily reuse that package, but would establish direct coupling and could affect selected features. Recheck the actual lockfile and manifests when considering adoption.

Conversions alone do not require `num-traits`' optional `libm` feature. The reviewed manifest declares edition `2021`, Rust `1.60`, and `MIT OR Apache-2.0`; its default feature is `std`. [Package manifest](https://docs.rs/crate/num-traits/latest/source/Cargo.toml.orig).

### Transitive consequence: `libm`

The proposed dependency chain is:

```text
`dupes-core`
  → `checked-float`
    → `num-traits`, with its `libm` feature enabled
      → `libm`
```

`checked-float 0.1.5` explicitly enables `num-traits/libm`. Setting `default-features = false` on `checked-float` does not remove that request, and another `num-traits` declaration cannot cancel it through feature selection. Cargo combines applicable dependency feature requests. [Versioned dependency declaration](https://raw.githubusercontent.com/dragazo/checked-float/c205ac3b22a6b7b90482a02cb32802960925eb29/Cargo.toml), [Cargo feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification).

`libm` supplies Rust implementations of broader mathematical operations used by the floating-point trait ecosystem. Its inclusion adds a package even though these score formulas use elementary arithmetic. It does not imply that the application calls every supplied operation or that users must install a separate C math library.

The reviewed published version, `libm 0.2.16`, declares edition `2021`, Rust `1.63`, and an MIT license. Its default `arch` feature permits architecture-specific implementations such as SIMD or assembly. A wrapper's `forbid(unsafe_code)` does not establish the implementation properties of this transitive dependency. This is a candidate version, not a resolved lockfile result. [Package manifest](https://docs.rs/crate/libm/latest/source/Cargo.toml.orig).

### Alternatives and compatibility consequences

| Approach | Capability | Consequence |
|---|---|---|
| Preserve rounded `f64` calculations with the proposed dependencies | Reusable checked float operations and explicit conversions | Retains the selected numerical model; still requires checked integer accumulation and complete domain outcomes. Adds `checked-float` and `libm`. |
| Use `num-traits` conversions with another implementation of the checks | Separates conversion mechanics from the float wrapper | Avoids that wrapper's mandatory `libm` feature, but still requires a sound implementation satisfying strict policy. Conversion alone is insufficient. |
| Make ratios and threshold comparisons exact | Decides matches without first rounding the computed ratio | Changes the numerical contract; requires explicit threshold interpretation, overflow handling, and output conversion. |

An exact-ratio redesign can change findings even for small counts. Exact `4/5` rounds to the same `f64` as configured `0.8`, so the current comparison passes. The stored binary `f64` threshold is slightly above exact `4/5`; comparing the exact ratio against that binary threshold fails. Interpreting the configuration text as an exact decimal is a separate possible contract.

Threshold decisions determine group membership. Near-group fingerprints are composites of member fingerprints, so changing those decisions can change group identities and ignore-entry matching. Treat such a redesign as a product behavior change with explicit compatibility adjudication, not an incidental lint fix. Follow the registry migration requirements in `dupes-core/AGENTS.md` when applicable.

### Evidence required before future adoption

The September 13, 2026 assessment examined source and manifests. The proposed graph has not been resolved or integration-tested, and its performance, binary-size impact, target matrix, and advisory status have not been established.

- Revisit release and maintenance status, source provenance, licensing, declared Rust requirements, features, and the actual resolved dependency graph.
- Establish the needed native-operation safety and panic properties for the selected types and targets rather than inferring them from a wrapper's attributes.
- Test complete successful and failed domain outcomes, integer accumulation boundaries, rounded conversions, invalid numeric states, and the defined empty-input behavior.
- If proposing exact comparisons, specify both calculated-ratio and configured-threshold semantics, and demonstrate effects on grouping, composite identities, and retained ignore entries.
- Preserve original typed evidence through analysis, persistence, and public results. Keep the caller's subsequent workflow decisions outside the calculation's promised handling.

Dependency adoption and an exact-ratio redesign remain distinct future decisions. The current repair's rounded `f64` semantics and complete typed outcome requirements are already selected.
