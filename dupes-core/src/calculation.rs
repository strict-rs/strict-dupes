//! Checked binary64 calculations over the detector's original integer counts.
//!
//! Count conversion and division each round to nearest with ties to even. Keeping
//! these rounding steps separate preserves the existing `f64` ratio contract.

use std::num::NonZero;
use std::num::TryFromIntError;

/// An unsigned intermediate operation whose native checked result was absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsignedOperation {
  /// Add two intermediate values.
  Add {
    /// Completed value before addition.
    left:  u128,
    /// Value being added.
    right: u128,
  },
  /// Subtract an intermediate value.
  Subtract {
    /// Value being reduced.
    left:  u128,
    /// Value being subtracted.
    right: u128,
  },
  /// Divide two intermediate values.
  Divide {
    /// Dividend.
    left:  u128,
    /// Divisor.
    right: u128,
  },
  /// Obtain the remainder of an intermediate division.
  Remainder {
    /// Dividend.
    left:  u128,
    /// Divisor.
    right: u128,
  },
}

impl UnsignedOperation {
  /// Preserve both operands when an intermediate cannot be represented.
  fn evaluate(self) -> Result<u128, RatioFailureCause> {
    let result = match self {
      Self::Add {
        left,
        right,
      } => left.checked_add(right),
      Self::Subtract {
        left,
        right,
      } => left.checked_sub(right),
      Self::Divide {
        left,
        right,
      } => left.checked_div(right),
      Self::Remainder {
        left,
        right,
      } => left.checked_rem(right),
    };
    result.ok_or(RatioFailureCause::Arithmetic {
      operation: self
    })
  }
}

/// The exact native operation that prevented a rounded count ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RatioFailureCause {
  /// A ratio has no value when its denominator is zero.
  #[error("the denominator is zero")]
  ZeroDenominator,
  /// The original count did not fit the intermediate integer representation.
  #[error("cannot represent original count {count}: {source}")]
  CountConversion {
    /// Original count being converted.
    count:  usize,
    /// Native conversion failure.
    source: TryFromIntError,
  },
  /// A rounded significand or encoded representation did not fit binary64 storage.
  #[error("cannot encode intermediate integer {integer}: {source}")]
  Encoding {
    /// Complete rejected intermediate value.
    integer: u128,
    /// Native integer conversion failure.
    source:  TryFromIntError,
  },
  /// A checked intermediate arithmetic operation failed.
  #[error("checked unsigned calculation failed: {operation:?}")]
  Arithmetic {
    /// Operation and both original intermediate operands.
    operation: UnsignedOperation,
  },
  /// The requested binary shift exceeded the intermediate representation.
  #[error("cannot shift {significand} left by {shift} bits")]
  Shift {
    /// Complete value before the rejected shift.
    significand: u128,
    /// Requested number of binary places.
    shift:       u32,
  },
  /// A rounded count's exponent could not be incremented.
  #[error("cannot increment binary exponent {exponent}")]
  Exponent {
    /// Exponent before carrying a rounded significand.
    exponent: u32,
  },
}

/// A failed ratio with both original integer counts and its complete cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cannot calculate rounded ratio {numerator}/{denominator}: {source}")]
pub struct RatioFailure {
  /// Original numerator, before any binary64 rounding.
  pub numerator:   usize,
  /// Original denominator, before any binary64 rounding.
  pub denominator: usize,
  /// Failed conversion, validation, or checked intermediate operation.
  pub source:      RatioFailureCause,
}

/// A failed multiplication with the native input, multiplier, and resulting value.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("non-finite scaling calculation: {operand} times {multiplier} produced {result}")]
pub struct ScalingFailure {
  /// Original floating-point input, including any non-finite value.
  pub operand:    f64,
  /// Requested multiplier.
  pub multiplier: f64,
  /// Native rounded result, including any rejected non-finite value.
  pub result:     f64,
}

/// The failed step of an inclusive source-line measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LineRangeFailureCause {
  /// The final line preceded the first line.
  #[error("the final line precedes the first line")]
  Reversed,
  /// Adding the inclusive final line exceeded the counting representation.
  #[error("inclusive line count exceeds usize capacity after width {width}")]
  InclusiveOverflow {
    /// Completed end-minus-start measurement before adding the final line.
    width: usize,
  },
}

/// A failed line measurement retaining both original source coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cannot measure source lines {start} through {end}: {source}")]
pub struct LineRangeFailure {
  /// Original first source line.
  pub start:  usize,
  /// Original inclusive final source line.
  pub end:    usize,
  /// Exact failed subtraction or inclusive addition.
  pub source: LineRangeFailureCause,
}

/// Measure an inclusive source-line interval without saturating or wrapping.
///
/// # Errors
///
/// Returns the original coordinates and failed operation for reversed or
/// unrepresentable intervals.
pub fn inclusive_line_count(start: usize, end: usize) -> Result<usize, LineRangeFailure> {
  let width = end.checked_sub(start).ok_or(LineRangeFailure {
    start,
    end,
    source: LineRangeFailureCause::Reversed,
  })?;
  width.checked_add(1).ok_or(LineRangeFailure {
    start,
    end,
    source: LineRangeFailureCause::InclusiveOverflow {
      width,
    },
  })
}

/// A positive integer rounded to a normalized binary64 significand and exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoundedCount {
  /// The implicit leading bit and 52 fraction bits.
  significand: u128,
  /// Unbiased exponent of the leading bit.
  exponent:    u32,
}

/// The implicit leading bit of a normalized binary64 value.
const LEADING_BIT: u128 = 1 << 52;
/// The first bit beyond binary64's 53-bit significand.
const CARRY_BIT: u128 = 1 << 53;

impl RoundedCount {
  /// Round the original integer once, as conversion to `f64` does.
  fn from_count(count: NonZero<usize>) -> Result<Self, RatioFailureCause> {
    let integer = u128::try_from(count.get()).map_err(|source| RatioFailureCause::CountConversion {
      count: count.get(),
      source,
    })?;
    let exponent = count.ilog2();
    let divisor = shift_left(1, exponent.saturating_sub(52))?;
    let rounded = rounded_quotient(integer, divisor)?;
    let significand = shift_left(rounded, 52_u32.saturating_sub(exponent))?;
    if significand == CARRY_BIT {
      Ok(Self {
        significand: LEADING_BIT,
        exponent:    exponent.checked_add(1).ok_or(RatioFailureCause::Exponent {
          exponent,
        })?,
      })
    } else {
      Ok(Self {
        significand,
        exponent,
      })
    }
  }
}

/// Shift an already bounded significand while retaining a rejected shift's operands.
fn shift_left(significand: u128, shift: u32) -> Result<u128, RatioFailureCause> {
  significand.checked_shl(shift).ok_or(RatioFailureCause::Shift {
    significand,
    shift,
  })
}

/// Round a nonnegative quotient to the nearest integer, choosing the even integer at a tie.
fn rounded_quotient(numerator: u128, denominator: u128) -> Result<u128, RatioFailureCause> {
  let quotient = UnsignedOperation::Divide {
    left:  numerator,
    right: denominator,
  }
  .evaluate()?;
  let remainder = UnsignedOperation::Remainder {
    left:  numerator,
    right: denominator,
  }
  .evaluate()?;
  // Comparing r with d-r avoids overflowing while comparing 2*r with d.
  let complement = UnsignedOperation::Subtract {
    left:  denominator,
    right: remainder,
  }
  .evaluate()?;
  let round_up = remainder > complement || (remainder == complement && !quotient.is_multiple_of(2));
  UnsignedOperation::Add {
    left:  quotient,
    right: u128::from(round_up),
  }
  .evaluate()
}

/// Divide separately rounded integer operands, then encode the rounded binary64 quotient.
#[allow(
  clippy::single_call_fn,
  reason = "Nonzero count division owns significand rounding and binary64 encoding separately from zero-input validation"
)]
fn divide_counts(numerator: NonZero<usize>, denominator: NonZero<usize>) -> Result<f64, RatioFailureCause> {
  let first = RoundedCount::from_count(numerator)?;
  let second = RoundedCount::from_count(denominator)?;
  let below_one = first.significand < second.significand;
  let dividend = shift_left(first.significand, if below_one { 53 } else { 52 })?;
  let significand = rounded_quotient(dividend, second.significand)?;
  let biased = UnsignedOperation::Add {
    left:  1023,
    right: u128::from(first.exponent),
  }
  .evaluate()?;
  let adjusted = UnsignedOperation::Subtract {
    left:  biased,
    right: u128::from(second.exponent),
  }
  .evaluate()?;
  let exponent = UnsignedOperation::Subtract {
    left:  adjusted,
    right: u128::from(below_one),
  }
  .evaluate()?;
  let (fraction, encoded_exponent) = if significand == CARRY_BIT {
    (
      0,
      UnsignedOperation::Add {
        left: exponent, right: 1
      }
      .evaluate()?,
    )
  } else {
    (
      UnsignedOperation::Subtract {
        left:  significand,
        right: LEADING_BIT,
      }
      .evaluate()?,
      exponent,
    )
  };
  let bits = shift_left(encoded_exponent, 52)? | fraction;
  let encoded = u64::try_from(bits).map_err(|source| RatioFailureCause::Encoding {
    integer: bits,
    source,
  })?;
  Ok(f64::from_bits(encoded))
}

/// Calculate the same ratio as separately rounded `f64` counts followed by `f64` division.
///
/// # Errors
///
/// Returns both original counts and the exact failed operation. A zero denominator
/// is rejected; domain-specific empty-input results belong to the calling operation.
pub fn ratio(numerator: usize, denominator: usize) -> Result<f64, RatioFailure> {
  let cause = NonZero::new(denominator).map_or(Err(RatioFailureCause::ZeroDenominator), |divisor| {
    NonZero::new(numerator).map_or(Ok(0.0), |dividend| divide_counts(dividend, divisor))
  });
  cause.map_err(|source| RatioFailure {
    numerator,
    denominator,
    source,
  })
}

/// Multiply a finite value with binary64 rounding and preserve a rejected result.
///
/// # Errors
///
/// Returns both operands and the native result when an operand or result is non-finite.
pub const fn scale(operand: f64, multiplier: f64) -> Result<f64, ScalingFailure> {
  // Adding negative zero preserves multiplication's signed-zero behavior while
  // the native fused operation performs exactly one rounding of the product.
  let result = operand.mul_add(multiplier, -0.0);
  if operand.is_finite() && multiplier.is_finite() && result.is_finite() {
    Ok(result)
  } else {
    Err(ScalingFailure {
      operand,
      multiplier,
      result,
    })
  }
}

#[cfg(test)]
mod tests {
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;

  use super::LineRangeFailure;
  use super::LineRangeFailureCause;
  use super::RatioFailure;
  use super::RatioFailureCause;
  use super::ScalingFailure;
  use super::inclusive_line_count;
  use super::ratio;
  use super::scale;

  /// A calculation expectation retains the complete native outcome and original inputs.
  #[derive(Debug, thiserror::Error)]
  enum CalculationTestFailure {
    /// An inclusive line measurement differed from its complete expected outcome.
    #[error("line range {start} through {end} differed: {observed:?}; expected {expected:?}: {source}")]
    LineRange {
      /// Original first source line.
      start:    usize,
      /// Original final source line.
      end:      usize,
      /// Complete returned length or interval failure.
      observed: Box<Result<usize, LineRangeFailure>>,
      /// Complete expected length or interval failure.
      expected: Box<Result<usize, LineRangeFailure>>,
      /// Failed behavioral expectation.
      source:   TestFailure,
    },
    /// A count ratio differed from its required binary64 outcome.
    #[error("ratio {numerator}/{denominator} differed: {observed:?}; expected {expected:?}: {source}")]
    Ratio {
      /// Original numerator.
      numerator:   usize,
      /// Original denominator.
      denominator: usize,
      /// Complete returned score or calculation failure.
      observed:    Box<Result<f64, RatioFailure>>,
      /// Expected binary64 bits or complete typed failure.
      expected:    Box<Result<u64, RatioFailure>>,
      /// Failed behavioral expectation.
      source:      TestFailure,
    },
    /// Multiplication differed from its required value or typed failure.
    #[error("scaling {operand} by {multiplier} differed: {observed:?}: {source}")]
    Scaling {
      /// Original floating-point input.
      operand:    f64,
      /// Requested multiplier.
      multiplier: f64,
      /// Complete returned value or rejected native calculation.
      observed:   Result<f64, ScalingFailure>,
      /// Failed behavioral expectation.
      source:     TestFailure,
    },
  }

  /// Check the binary64 contract without discarding native failure evidence.
  fn check_ratio(numerator: usize, denominator: usize, expected: &Result<u64, RatioFailure>) -> Result<(), CalculationTestFailure> {
    let observed = ratio(numerator, denominator);
    ensure(
      observed.as_ref().map(|score| score.to_bits()) == expected.as_ref().copied(),
      "count conversion and division preserve the required rounded binary64 result",
    )
    .map_err(|source| CalculationTestFailure::Ratio {
      numerator,
      denominator,
      observed: Box::new(observed),
      expected: Box::new(*expected),
      source,
    })
  }

  /// Count ratios preserve division rounding both below and above one.
  #[test]
  fn ratios_preserve_binary64_results_on_both_sides_of_one() -> Result<(), CalculationTestFailure> {
    for (numerator, denominator, bits) in [
      (0, 1, 0x0000_0000_0000_0000),
      (1, 1, 0x3ff0_0000_0000_0000),
      (4, 5, 0x3fe9_9999_9999_999a),
      (2, 3, 0x3fe5_5555_5555_5555),
      (7, 10, 0x3fe6_6666_6666_6666),
      (1, 3, 0x3fd5_5555_5555_5555),
      (10, 7, 0x3ff6_db6d_b6db_6db7),
    ] {
      check_ratio(numerator, denominator, &Ok(bits))?;
    }
    Ok(())
  }

  /// Integer conversion rounds before division at binary64 precision boundaries.
  #[cfg(target_pointer_width = "64")]
  #[test]
  fn counts_round_before_division_at_precision_and_capacity_boundaries() -> Result<(), CalculationTestFailure> {
    for (numerator, denominator, bits) in [
      (9_007_199_254_740_993, 9_007_199_254_740_994, 0x3fef_ffff_ffff_fffe),
      (9_007_199_254_740_995, 9_007_199_254_740_994, 0x3ff0_0000_0000_0001),
      (usize::MAX, 1, 0x43f0_0000_0000_0000),
      (1, usize::MAX, 0x3bf0_0000_0000_0000),
      (usize::MAX, usize::MAX.saturating_sub(1), 0x3ff0_0000_0000_0000),
      (18_014_398_509_481_986, 18_014_398_509_481_987, 0x3fef_ffff_ffff_fffe),
    ] {
      check_ratio(numerator, denominator, &Ok(bits))?;
    }
    Ok(())
  }

  /// Zero denominators report both original counts, including the zero numerator.
  #[test]
  fn zero_denominators_retain_original_counts() -> Result<(), CalculationTestFailure> {
    for numerator in [0, 9, usize::MAX] {
      check_ratio(
        numerator,
        0,
        &Err(RatioFailure {
          numerator,
          denominator: 0,
          source: RatioFailureCause::ZeroDenominator,
        }),
      )?;
    }
    Ok(())
  }

  /// Inclusive counts preserve valid endpoints and distinguish reversed and overflowing intervals.
  #[test]
  fn inclusive_lines_preserve_boundaries_and_rejected_coordinates() -> Result<(), CalculationTestFailure> {
    for (start, end, expected) in [
      (1, 1, Ok(1)),
      (3, 8, Ok(6)),
      (1, usize::MAX, Ok(usize::MAX)),
      (usize::MAX, usize::MAX, Ok(1)),
      (
        9,
        3,
        Err(LineRangeFailure {
          start:  9,
          end:    3,
          source: LineRangeFailureCause::Reversed,
        }),
      ),
      (
        0,
        usize::MAX,
        Err(LineRangeFailure {
          start:  0,
          end:    usize::MAX,
          source: LineRangeFailureCause::InclusiveOverflow {
            width: usize::MAX
          },
        }),
      ),
    ] {
      let observed = inclusive_line_count(start, end);
      ensure(
        observed == expected,
        "inclusive measurements retain exact counts or the complete failed interval operation",
      )
      .map_err(|source| CalculationTestFailure::LineRange {
        start,
        end,
        observed: Box::new(observed),
        expected: Box::new(expected),
        source,
      })?;
    }
    Ok(())
  }

  /// Finite multiplication preserves ordinary rounding, negative zero, and underflow.
  #[test]
  fn scaling_preserves_finite_rounding_signed_zero_and_underflow() -> Result<(), CalculationTestFailure> {
    for (operand, multiplier, expected) in [
      (3.0_f64, 25.0, 75.0_f64),
      (-0.0, 100.0, -0.0),
      (f64::MIN_POSITIVE, f64::MIN_POSITIVE, 0.0),
    ] {
      let observed = scale(operand, multiplier);
      ensure(
        observed.as_ref().is_ok_and(|result| result.to_bits() == expected.to_bits()),
        "finite scaling keeps its native rounded result, including signed zero and underflow",
      )
      .map_err(|source| CalculationTestFailure::Scaling {
        operand,
        multiplier,
        observed,
        source,
      })?;
    }
    Ok(())
  }

  /// Invalid operands and overflow retain both inputs and the rejected native result.
  #[test]
  fn nonfinite_scaling_retains_operands_and_the_native_result() -> Result<(), CalculationTestFailure> {
    for (operand, multiplier) in [(f64::MAX, 2.0), (f64::INFINITY, 1.0), (1.0, f64::INFINITY), (f64::NAN, 1.0)] {
      let observed = scale(operand, multiplier);
      ensure(
        observed.as_ref().is_err_and(|failure| {
          failure.operand.to_bits() == operand.to_bits()
            && failure.multiplier.to_bits() == multiplier.to_bits()
            && !failure.result.is_finite()
        }),
        "rejected scaling preserves both original operands and its non-finite native result",
      )
      .map_err(|source| CalculationTestFailure::Scaling {
        operand,
        multiplier,
        observed,
        source,
      })?;
    }
    Ok(())
  }
}
