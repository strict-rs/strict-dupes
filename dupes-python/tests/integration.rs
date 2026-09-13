//! Python analyzer integration: extraction, normalization, and fingerprint
//! expectations over real Python sources.

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;
  use std::path::Path;

  use dupes_core::analyzer::LanguageAnalyzer as _;
  use dupes_core::code_unit::CodeUnit;
  use dupes_core::code_unit::CodeUnitKind;
  use dupes_core::config::AnalysisConfig;
  use dupes_core::source::SourceFile;
  use dupes_python::PythonAnalyzer;
  use dupes_python::PythonAnalyzerError;
  use dupes_treesitter::analyzer::TreeSitterParseError;
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;

  /// The fingerprint relation required by a pair of source fixtures.
  #[derive(Debug, Clone, Copy)]
  enum FingerprintExpectation {
    /// Identifier or value differences preserve normalized content identity.
    Same,
    /// A behavior-bearing syntax difference changes normalized content identity.
    Different,
  }

  /// Retain native analyzer failures and complete units when an assertion fails.
  #[derive(Debug, thiserror::Error)]
  enum PythonTestFailure {
    /// The built-in Python query could not be initialized.
    #[error(transparent)]
    Initialization(#[from] PythonAnalyzerError),
    /// Parsing a fixture failed with its native cause and source input.
    #[error(transparent)]
    Parse(#[from] TreeSitterParseError),
    /// The returned code units violated their expected contract.
    #[error("{source}; extracted units: {units:?}")]
    Units {
      /// Complete extracted units, including kinds, spans, and normalized syntax.
      units:  Vec<CodeUnit>,
      /// Failed semantic expectation.
      source: TestFailure,
    },
    /// Extraction changed expected category identities or test-code tags.
    #[error("extraction identity expectation failed: {source}; input: {input:?}; expected: {expected:?}; units: {units:?}")]
    Identities {
      /// Complete original Python source and its path.
      input:    Box<SourceFile>,
      /// Independently expected names, categories, and test-code tags.
      expected: Vec<(String, CodeUnitKind, bool)>,
      /// Complete extraction result across all categories.
      units:    Vec<CodeUnit>,
      /// Native assertion failure.
      source:   Box<TestFailure>,
    },
    /// A node or line admission floor violated its complete before-and-after contract.
    #[error(
      "admission expectation failed: {source}; input: {input:?}; configs: {configs:?}; expected: {expected:?}; outcomes: {outcomes:?}"
    )]
    Admission {
      /// Full source submitted to both configurations.
      input:    Box<SourceFile>,
      /// Original permissive and restrictive extraction configurations.
      configs:  [AnalysisConfig; 2],
      /// Name and category of the unit admitted by the permissive configuration.
      expected: (String, CodeUnitKind),
      /// Complete results or native parser failures from both attempts.
      outcomes: Box<[PythonParseResult; 2]>,
      /// Native assertion failure.
      source:   Box<TestFailure>,
    },
  }

  /// Complete native Python extraction outcome for one source and configuration.
  type PythonParseResult = Result<Vec<CodeUnit>, TreeSitterParseError>;

  /// Include every nonempty fixture unit unless a test specifies a higher threshold.
  const fn default_config() -> AnalysisConfig {
    AnalysisConfig {
      min_nodes: 1,
      min_lines: 1,
    }
  }

  /// Parse a fixture with the integration suite's normal extraction thresholds.
  fn parse(source: &str) -> Result<Vec<CodeUnit>, PythonTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    Ok(analyzer.parse_file(Path::new("test.py"), source, default_config())?)
  }

  /// Check a unit population without discarding it when an assertion fails.
  fn check_units(units: Vec<CodeUnit>, check: impl FnOnce(&[CodeUnit]) -> Result<(), TestFailure>) -> Result<(), PythonTestFailure> {
    check(&units).map_err(|source| PythonTestFailure::Units {
      units,
      source,
    })
  }

  /// Preserve the complete population while checking names and tags in source order within each
  /// category.
  fn check_identities(source: &str, expected: &[(&str, CodeUnitKind, bool)]) -> Result<(), PythonTestFailure> {
    let units = parse(source)?;
    let kinds: BTreeSet<_> = expected.iter().map(|entry| entry.1).collect();
    ensure(
      units.len() == expected.len()
        && kinds.iter().all(|&kind| {
          units
            .iter()
            .filter(|unit| unit.kind == kind)
            .map(|unit| (unit.name.as_str(), unit.is_test))
            .eq(expected.iter().filter(|entry| entry.1 == kind).map(|entry| (entry.0, entry.2)))
        }),
      "extraction retains every independently named unit and its test-code tag in source order within its category",
    )
    .map_err(|error| PythonTestFailure::Identities {
      input: Box::new(SourceFile {
        path:     Path::new("test.py").to_path_buf(),
        contents: source.to_owned(),
      }),
      expected: expected
        .iter()
        .map(|&(name, kind, is_test)| (name.to_owned(), kind, is_test))
        .collect(),
      units,
      source: Box::new(error),
    })
  }

  /// Require exactly two complete units before comparing their content identities.
  fn assert_two_unit_fingerprints(
    source: &str,
    expectation: FingerprintExpectation,
    message: &'static str,
  ) -> Result<(), PythonTestFailure> {
    check_units(parse(source)?, |units| {
      let [ref left, ref right] = *units else {
        return ensure(false, "the fingerprint fixture must produce exactly two code units");
      };
      assert_fingerprint_expectation(left, right, expectation, message)
    })
  }

  /// Compare the selected unit kind while retaining the entire extracted population.
  fn assert_kind_fingerprints(
    source: &str,
    kind: CodeUnitKind,
    expectation: FingerprintExpectation,
    message: &'static str,
  ) -> Result<(), PythonTestFailure> {
    check_units(parse(source)?, |units| {
      let selected: Vec<_> = units.iter().filter(|unit| unit.kind == kind).collect();
      let [left, right] = *selected.as_slice() else {
        return ensure(false, "the fixture must produce exactly two units of the selected kind");
      };
      assert_fingerprint_expectation(left, right, expectation, message)
    })
  }

  /// Compare fingerprints according to the fixture's declared semantic relation.
  fn assert_fingerprint_expectation(
    left: &CodeUnit,
    right: &CodeUnit,
    expectation: FingerprintExpectation,
    message: &'static str,
  ) -> Result<(), TestFailure> {
    match expectation {
      FingerprintExpectation::Same => ensure(left.fingerprint == right.fingerprint, message),
      FingerprintExpectation::Different => ensure(left.fingerprint != right.fingerprint, message),
    }
  }

  // -- Basic parsing --

  /// Free, nested, and async functions retain independent identities in source order.
  #[test]
  fn parses_free_nested_and_async_function_identities() -> Result<(), PythonTestFailure> {
    let free = "
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
";
    let nested = "
def outer(a, b):
    def inner(x):
        return x * 2
    return inner(a) + inner(b)
";
    let asynchronous = "
async def fetch(url):
    result = await get(url)
    return result

def sync_fetch(url):
    result = get(url)
    return result
";
    for (source, names) in [
      (free, ["add", "subtract"]),
      (nested, ["outer", "inner"]),
      (asynchronous, ["fetch", "sync_fetch"]),
    ] {
      check_identities(source, &names.map(|name| (name, CodeUnitKind::Function, false)))?;
    }
    Ok(())
  }

  /// Classes and their methods remain independently extractable.
  #[test]
  fn classes_and_methods_keep_independent_identities() -> Result<(), PythonTestFailure> {
    let calculator = "
class Calculator:
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b
";
    let methods = "
class MyClass:
    def method_a(self, x):
        return x + 1

    def method_b(self, x):
        return x * 2
";
    for (source, class, first, second) in [
      (calculator, "Calculator", "add", "subtract"),
      (methods, "MyClass", "method_a", "method_b"),
    ] {
      check_identities(source, &[
        (class, CodeUnitKind::Class, false),
        (first, CodeUnitKind::Function, false),
        (second, CodeUnitKind::Function, false),
      ])?;
    }
    Ok(())
  }

  // -- Test detection --

  /// The test-name convention tags matching functions while ordinary names remain untagged.
  #[test]
  fn function_names_determine_test_tags() -> Result<(), PythonTestFailure> {
    let tests = "
def test_addition():
    assert 1 + 1 == 2

def test_subtraction():
    assert 2 - 1 == 1
";
    let ordinary = "
def add(a, b):
    return a + b

def helper():
    return 42
";
    for (source, names, is_test) in [
      (tests, ["test_addition", "test_subtraction"], true),
      (ordinary, ["add", "helper"], false),
    ] {
      check_identities(source, &names.map(|name| (name, CodeUnitKind::Function, is_test)))?;
    }
    Ok(())
  }

  // -- Fingerprinting --

  /// The recorded Python content identity survives Rust-specific normalization changes.
  #[test]
  fn python_fingerprints_unchanged_by_method_name_preservation() -> Result<(), PythonTestFailure> {
    // Python method calls normalize as Call + FieldAccess, never
    // NodeKind::MethodCall, so Rust-side method-name preservation must not
    // move Python fingerprints; this pinned hex holds across Rust
    // normalization regimes.
    let parsed = parse(
      "
class Adder:
    def compute(self, a, b):
        result = a + b
        return result
",
    )?;
    check_units(parsed, |units| {
      let fingerprints: Vec<_> = units
        .iter()
        .filter(|unit| unit.name == "compute")
        .map(|unit| unit.fingerprint.to_hex())
        .collect();
      ensure(
        fingerprints == ["9ee8e92bc616589a"],
        "the Python method-call fingerprint remains stable",
      )
    })
  }

  /// Renamed equivalent functions retain the same content identity.
  #[test]
  fn duplicate_functions_same_fingerprint() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def add(a, b):
    result = a + b
    return result

def add2(x, y):
    result = x + y
    return result
",
      FingerprintExpectation::Same,
      "Structurally identical functions should have the same fingerprint",
    )
  }

  /// Changing an operator changes the function's content identity.
  #[test]
  fn different_functions_different_fingerprint() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def add(a, b):
    return a + b

def mul(a, b):
    return a * b
",
      FingerprintExpectation::Different,
      "Structurally different functions should have different fingerprints",
    )
  }

  /// Parameter spelling does not alter positional placeholder identity.
  #[test]
  fn renamed_variables_same_fingerprint() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def foo(a, b):
    return a + b

def bar(x, y):
    return x + y
",
      FingerprintExpectation::Same,
      "Functions with renamed variables should have the same fingerprint",
    )
  }

  /// Distinct loop-control effects remain distinguishable.
  #[test]
  fn break_and_continue_have_different_fingerprints() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def with_break(items):
    for x in items:
        if x > 10:
            break
    return x

def with_continue(items):
    for x in items:
        if x > 10:
            continue
    return x
",
      FingerprintExpectation::Different,
      "break and continue should produce different fingerprints",
    )
  }

  /// Null and boolean literals remain different semantic kinds.
  #[test]
  fn none_literal_distinguished_from_bool() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def returns_none(x):
    y = None
    return y

def returns_true(x):
    y = True
    return y
",
      FingerprintExpectation::Different,
      "None and True should produce different fingerprints",
    )
  }

  /// Compound assignments preserve their selected arithmetic operation.
  #[test]
  fn augmented_assignment_operators_distinguished() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def add_assign(a, b):
    a += b
    return a

def sub_assign(a, b):
    a -= b
    return a
",
      FingerprintExpectation::Different,
      "+= and -= should produce different fingerprints",
    )
  }

  /// Comparison kind changes remain visible alongside their operands.
  #[test]
  fn comparison_operators_preserve_operands() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def check_eq(a, b):
    if a == b:
        return a
    return b

def check_lt(a, b):
    if a < b:
        return a
    return b
",
      FingerprintExpectation::Different,
      "== and < should produce different fingerprints",
    )
  }

  /// Tuple and list construction retain distinct container semantics.
  #[test]
  fn tuple_and_list_distinguished() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def make_tuple(a, b):
    x = (a, b)
    return x

def make_list(a, b):
    x = [a, b]
    return x
",
      FingerprintExpectation::Different,
      "Tuple and list should produce different fingerprints",
    )
  }

  // -- Filtering --

  /// Node and line floors admit the same complete function or class before excluding it at a higher
  /// limit.
  #[test]
  fn admission_floors_preserve_function_and_class_boundaries() -> Result<(), PythonTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    for (document, name, kind, restrictive) in [
      ("def tiny():\n    pass\n", "tiny", CodeUnitKind::Function, AnalysisConfig {
        min_nodes: 100,
        min_lines: 1,
      }),
      ("def short():\n    return 1\n", "short", CodeUnitKind::Function, AnalysisConfig {
        min_nodes: 1,
        min_lines: 10,
      }),
      ("class Empty:\n    pass\n", "Empty", CodeUnitKind::Class, AnalysisConfig {
        min_nodes: 100,
        min_lines: 1,
      }),
    ] {
      let input = SourceFile {
        path:     Path::new("test.py").to_path_buf(),
        contents: document.to_owned(),
      };
      let configs = [default_config(), restrictive];
      let outcomes = configs.map(|config| analyzer.parse_file(&input.path, &input.contents, config));
      ensure(
        matches!(&outcomes, [Ok(admitted), Ok(rejected)]
          if matches!(admitted.as_slice(), [unit] if unit.name == name && unit.kind == kind && unit.file == input.path)
            && rejected.is_empty()),
        "the permissive configuration retains the complete named unit and the selected higher floor excludes it",
      )
      .map_err(|source| PythonTestFailure::Admission {
        input: Box::new(input),
        configs,
        expected: (name.to_owned(), kind),
        outcomes: Box::new(outcomes),
        source: Box::new(source),
      })?;
    }
    Ok(())
  }

  // -- Edge cases --

  /// An empty source file contributes no code units.
  #[test]
  fn empty_file_returns_no_units() -> Result<(), PythonTestFailure> {
    check_units(parse("")?, |units| {
      ensure(units.is_empty(), "empty source has no extractable code units")
    })
  }

  /// Comments do not create function, class, or lambda definitions.
  #[test]
  fn comments_only_file_returns_no_units() -> Result<(), PythonTestFailure> {
    check_units(parse("# This is a comment\n# Another comment\n")?, |units| {
      ensure(units.is_empty(), "comments alone do not form code units")
    })
  }

  /// Recoverable syntax errors do not fabricate absent definition bodies.
  #[test]
  fn syntax_errors_do_not_invent_code_units() -> Result<(), PythonTestFailure> {
    check_units(parse("def broken(\n    pass\n)))\n")?, |units| {
      ensure(
        units.is_empty(),
        "malformed syntax without a function body has no extractable units",
      )
    })
  }

  /// Decorators do not hide or change an otherwise equal normalized function body.
  #[test]
  fn decorated_functions_are_parsed() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
@some_decorator
def decorated(x):
    return x * 2

def plain(x):
    return x * 2
",
      FingerprintExpectation::Same,
      "decorated and ordinary functions with the same normalized body retain equal fingerprints",
    )
  }

  /// Stub declarations retain their source paths and function identities.
  #[test]
  fn pyi_stub_file_parses() -> Result<(), PythonTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    let path = Path::new("stubs.pyi");
    let parsed = analyzer.parse_file(path, "def foo(x: int) -> int: ...\ndef bar(x: str) -> str: ...\n", default_config())?;
    check_units(parsed, |units| {
      let observed: Vec<_> = units
        .iter()
        .map(|unit| (unit.name.as_str(), unit.kind, unit.file.as_path()))
        .collect();
      ensure(
        observed == [("foo", CodeUnitKind::Function, path), ("bar", CodeUnitKind::Function, path)],
        "stub definitions preserve their source path and function identities",
      )
    })
  }

  /// An intermediate comparison operand remains part of content identity.
  #[test]
  fn chained_comparison_preserves_all_operands() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def chained(a, b, c):
    if a < b < c:
        return a
    return c

def simple(a, b, c):
    if a < c:
        return a
    return c
",
      FingerprintExpectation::Different,
      "a < b < c and a < c should produce different fingerprints",
    )
  }

  /// Set and list construction retain distinct container semantics.
  #[test]
  fn set_and_list_distinguished() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def make_set(a, b):
    x = {a, b}
    return x

def make_list(a, b):
    x = [a, b]
    return x
",
      FingerprintExpectation::Different,
      "Set and list should produce different fingerprints",
    )
  }

  /// Floor division remains distinct from ordinary division.
  #[test]
  fn floor_div_and_regular_div_different_fingerprint() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def floor_div(a, b):
    return a // b

def regular_div(a, b):
    return a / b
",
      FingerprintExpectation::Different,
      "// and / should produce different fingerprints",
    )
  }

  /// Exponentiation remains distinct from multiplication.
  #[test]
  fn pow_and_mul_different_fingerprint() -> Result<(), PythonTestFailure> {
    assert_two_unit_fingerprints(
      "
def power(a, b):
    return a ** b

def multiply(a, b):
    return a * b
",
      FingerprintExpectation::Different,
      "** and * should produce different fingerprints",
    )
  }

  // -- Lambda extraction --

  /// Lambda identities retain source positions and remain separate from enclosing functions.
  #[test]
  fn lambda_extraction_preserves_locations_and_enclosing_functions() -> Result<(), PythonTestFailure> {
    let top_level = "
f = lambda x: x + 1
g = lambda y: y * 2
";
    let nested = "
def outer(items):
    result = list(map(lambda x: x + 1, items))
    return result
";
    for (source, expected) in [
      (top_level, [
        ("anonymous at test.py:2", CodeUnitKind::Closure, false),
        ("anonymous at test.py:3", CodeUnitKind::Closure, false),
      ]),
      (nested, [
        ("outer", CodeUnitKind::Function, false),
        ("anonymous at test.py:3", CodeUnitKind::Closure, false),
      ]),
    ] {
      check_identities(source, &expected)?;
    }
    Ok(())
  }

  /// Equivalent lambda bodies retain equal content identities.
  #[test]
  fn duplicate_lambdas_same_fingerprint() -> Result<(), PythonTestFailure> {
    assert_kind_fingerprints(
      "
f = lambda x: x + 1
g = lambda y: y + 1
",
      CodeUnitKind::Closure,
      FingerprintExpectation::Same,
      "Structurally identical lambdas should have the same fingerprint",
    )
  }

  /// Behavior-bearing lambda differences change content identity.
  #[test]
  fn different_lambdas_different_fingerprint() -> Result<(), PythonTestFailure> {
    assert_kind_fingerprints(
      "
f = lambda x: x + 1
g = lambda x: x * 2
",
      CodeUnitKind::Closure,
      FingerprintExpectation::Different,
      "Structurally different lambdas should have different fingerprints",
    )
  }

  // -- Class extraction --

  /// Ordinary, inherited, nested, and test classes retain their own identities and every method.
  #[test]
  fn class_extraction_preserves_nesting_inheritance_and_test_tags() -> Result<(), PythonTestFailure> {
    let ordinary = "
class Foo:
    def method(self):
        return 1
";
    let inherited = "
class Child(Parent):
    def method(self):
        return self + 1
";
    let nested = "
class Outer:
    class Inner:
        def method(self):
            return 1
    def outer_method(self):
        return 2
";
    let test_class = "
class TestCalculator:
    def test_add(self):
        assert 1 + 1 == 2
";
    for (source, expected) in [
      (ordinary, vec![
        ("Foo", CodeUnitKind::Class, false),
        ("method", CodeUnitKind::Function, false),
      ]),
      (inherited, vec![
        ("Child", CodeUnitKind::Class, false),
        ("method", CodeUnitKind::Function, false),
      ]),
      (nested, vec![
        ("Outer", CodeUnitKind::Class, false),
        ("Inner", CodeUnitKind::Class, false),
        ("method", CodeUnitKind::Function, false),
        ("outer_method", CodeUnitKind::Function, false),
      ]),
      (test_class, vec![
        ("TestCalculator", CodeUnitKind::Class, true),
        ("test_add", CodeUnitKind::Function, true),
      ]),
    ] {
      check_identities(source, &expected)?;
    }
    Ok(())
  }

  /// Renamed classes with equal bodies retain equal content identities.
  #[test]
  fn duplicate_classes_same_fingerprint() -> Result<(), PythonTestFailure> {
    assert_kind_fingerprints(
      "
class Foo:
    def method(self):
        return self + 1

class Bar:
    def method(self):
        return self + 1
",
      CodeUnitKind::Class,
      FingerprintExpectation::Same,
      "Structurally identical classes should have the same fingerprint",
    )
  }

  // -- Lambda edge cases --

  /// Parameterless lambdas preserve structural equivalence across literal values.
  #[test]
  fn lambda_with_no_parameters() -> Result<(), PythonTestFailure> {
    assert_kind_fingerprints(
      "
f = lambda: 42
g = lambda: 99
",
      CodeUnitKind::Closure,
      FingerprintExpectation::Same,
      "Parameterless lambdas with same structure should match",
    )
  }

  /// Multi-parameter lambdas canonicalize renamed bindings consistently.
  #[test]
  fn lambda_with_multiple_parameters() -> Result<(), PythonTestFailure> {
    assert_kind_fingerprints(
      "
f = lambda x, y: x + y
g = lambda a, b: a + b
",
      CodeUnitKind::Closure,
      FingerprintExpectation::Same,
      "Lambdas with renamed multi-params and same body should match",
    )
  }

  // -- Class edge cases --

  /// Decoration does not alter an otherwise equal normalized class body.
  #[test]
  fn decorated_class_same_fingerprint_as_plain() -> Result<(), PythonTestFailure> {
    assert_kind_fingerprints(
      "
@some_decorator
class Foo:
    def method(self):
        return self + 1

class Bar:
    def method(self):
        return self + 1
",
      CodeUnitKind::Class,
      FingerprintExpectation::Same,
      "Decorated and plain classes with same body should have same fingerprint",
    )
  }
}
