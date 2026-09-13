//! `dupes-core` grouping and similarity behavior exercised through units
//! parsed by the Python analyzer.

#[cfg(test)]
mod tests {
  use std::cmp::Ordering;
  use std::fs;
  use std::io;
  use std::path::Path;

  use dupes_core::AnalysisResult;
  use dupes_core::analyzer::LanguageAnalyzer as _;
  use dupes_core::code_unit::CodeUnit;
  use dupes_core::config::AnalysisConfig;
  use dupes_core::config::Config;
  use dupes_core::error::AnalysisError;
  use dupes_core::grouper::DuplicateGroup;
  use dupes_core::grouper::DuplicationStats;
  use dupes_core::grouper::NearGroupingFailure;
  use dupes_core::grouper::StatisticsFailure;
  use dupes_core::grouper::compute_stats;
  use dupes_core::grouper::find_near_duplicates;
  use dupes_core::grouper::group_exact_duplicates;
  use dupes_core::grouper::member_fingerprints;
  use dupes_core::similarity::SimilarityFailure;
  use dupes_core::similarity::SimilarityScore;
  use dupes_core::similarity::similarity_score;
  use dupes_python::PythonAnalyzer;
  use dupes_python::PythonAnalyzerError;
  use dupes_treesitter::analyzer::TreeSitterParseError;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use tempfile::TempDir;

  /// Preserve native failures and complete pipeline values when an assertion fails.
  #[derive(Debug, thiserror::Error)]
  enum PipelineTestFailure {
    /// Near grouping rejected a calculation after exact grouping completed.
    #[error("near grouping failed: {source}; exact groups: {exact:?}; units: {units:?}")]
    Grouping {
      /// Original unit population.
      units:  Vec<CodeUnit>,
      /// Complete exact groups computed before the failure.
      exact:  Vec<DuplicateGroup>,
      /// Complete pair calculations and native failure.
      source: Box<NearGroupingFailure>,
    },
    /// Statistics failed after both grouping operations completed.
    #[error("statistics failed: {source}; units: {units:?}; exact: {exact:?}; near: {near:?}")]
    Measurement {
      /// Original parsed corpus.
      units:  Vec<CodeUnit>,
      /// Complete exact groups.
      exact:  Vec<DuplicateGroup>,
      /// Complete near groups.
      near:   Vec<DuplicateGroup>,
      /// Native interval or accumulation failure.
      source: Box<StatisticsFailure>,
    },
    /// The built-in Python query could not be compiled.
    #[error(transparent)]
    Initialization(#[from] PythonAnalyzerError),
    /// Parsing failed with its native source context.
    #[error(transparent)]
    Parse(#[from] TreeSitterParseError),
    /// Fixture I/O failed with its native cause.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Parsed units did not satisfy their required contract.
    #[error("{source}; units: {units:?}")]
    Units {
      /// Complete parsed unit population.
      units:  Vec<CodeUnit>,
      /// Failed semantic expectation.
      source: ConditionFailure,
    },
    /// Exact grouping did not satisfy its required contract.
    #[error("{source}; units: {units:?}; exact groups: {groups:?}")]
    Exact {
      /// Complete units supplied to grouping.
      units:  Vec<CodeUnit>,
      /// Complete exact groups returned by the owner.
      groups: Vec<DuplicateGroup>,
      /// Failed semantic expectation.
      source: ConditionFailure,
    },
    /// Near grouping did not satisfy its required contract.
    #[error("{source}; units: {units:?}; exact groups: {exact:?}; near groups: {near:?}")]
    Near {
      /// Complete units supplied to grouping.
      units:  Vec<CodeUnit>,
      /// Complete exact-group result supplied to near grouping.
      exact:  Vec<DuplicateGroup>,
      /// Complete near groups returned by the owner.
      near:   Vec<DuplicateGroup>,
      /// Failed semantic expectation.
      source: Box<ConditionFailure>,
    },
    /// A similarity result violated the fixture's expected relation.
    #[error("{source}; document: {document:?}; expected {expected:?} against {threshold}; units: {units:?}; similarity: {score:?}")]
    Similarity {
      /// Complete Python input whose bodies are compared.
      document:  String,
      /// Rounded threshold used by the scenario.
      threshold: f64,
      /// Required relation between the calculated value and threshold.
      expected:  Ordering,
      /// Complete units whose bodies were compared.
      units:     Vec<CodeUnit>,
      /// Complete calculation outcome, absent only when extraction did not produce a pair.
      score:     Box<Option<Result<SimilarityScore, SimilarityFailure>>>,
      /// Failed semantic expectation.
      source:    Box<ConditionFailure>,
    },
    /// Statistics did not satisfy the expected exact-duplication contract.
    #[error(
      "{source}; document: {document:?}; expected exact family: {has_exact}; units: {units:?}; exact: {exact:?}; near: {near:?}; \
       statistics: {stats:?}"
    )]
    Statistics {
      /// Complete Python corpus used by the statistics scenario.
      document:  String,
      /// Whether exact groups, units, and duplicate lines must be present.
      has_exact: bool,
      /// Complete units supplied to grouping and statistics.
      units:     Vec<CodeUnit>,
      /// Complete exact groups supplied to statistics.
      exact:     Vec<DuplicateGroup>,
      /// Complete near groups supplied to statistics.
      near:      Vec<DuplicateGroup>,
      /// Complete statistics returned by the owner.
      stats:     Box<DuplicationStats>,
      /// Failed semantic expectation.
      source:    Box<ConditionFailure>,
    },
    /// Test exclusion did not satisfy its contract across both complete analyses.
    #[error("{source}; analysis outcomes: {outcomes:?}")]
    Analysis {
      /// Both native results, including successful or partially failed analyses.
      outcomes: Box<[PythonAnalysisOutcome; 2]>,
      /// Failed semantic expectation.
      source:   ConditionFailure,
    },
  }

  /// Complete Python pipeline result with its concrete native parser failure.
  type PythonAnalysisOutcome = Result<AnalysisResult<TreeSitterParseError>, AnalysisError<TreeSitterParseError>>;

  /// Ordinary renamed definitions shared by statistics and test-exclusion scenarios.
  const EXACT_CORPUS: &str = "
def add(a, b):
    result = a + b
    return result

def add2(x, y):
    result = x + y
    return result
";

  /// Include small fixture definitions in the cross-pipeline scenarios.
  const fn default_config() -> AnalysisConfig {
    AnalysisConfig {
      min_nodes: 1,
      min_lines: 1,
    }
  }

  /// Parse fixture source without erasing initialization or parsing failures.
  fn parse(source: &str) -> Result<Vec<CodeUnit>, PipelineTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    Ok(analyzer.parse_file(Path::new("test.py"), source, default_config())?)
  }

  /// Preserve completed exact groups when a subsequent pair calculation fails.
  fn near_groups(units: &[CodeUnit], exact: &[DuplicateGroup], threshold: f64) -> Result<Vec<DuplicateGroup>, PipelineTestFailure> {
    find_near_duplicates(units, threshold, &member_fingerprints(exact)).map_err(|source| PipelineTestFailure::Grouping {
      units:  units.to_vec(),
      exact:  exact.to_vec(),
      source: Box::new(source),
    })
  }

  /// Exact grouping joins the matching definitions while keeping different operators out.
  #[test]
  fn exact_duplicates_grouped() -> Result<(), PipelineTestFailure> {
    let units = parse(
      "
def add(a, b):
    result = a + b
    return result

def add2(x, y):
    result = x + y
    return result

def mul(a, b):
    result = a * b
    return result
",
    )?;
    let groups = group_exact_duplicates(&units);
    let members: Vec<Vec<_>> = groups
      .iter()
      .map(|group| group.members.iter().map(|unit| unit.name.as_str()).collect())
      .collect();
    ensure(
      units.len() == 3 && members == [vec!["add", "add2"]],
      "only the two equivalent functions form an exact group",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::Exact {
      units,
      groups,
      source,
    })
  }

  /// Different operators prevent exact grouping of the fixture definitions.
  #[test]
  fn no_exact_duplicates_when_all_different() -> Result<(), PipelineTestFailure> {
    let units = parse(
      "
def add(a, b):
    return a + b

def mul(a, b):
    return a * b

def div(a, b):
    return a / b
",
    )?;
    let groups = group_exact_duplicates(&units);
    ensure(
      units.len() == 3 && groups.is_empty(),
      "different function operators produce no exact group",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::Exact {
      units,
      groups,
      source,
    })
  }

  /// Near grouping retains both similar definitions without misclassifying them as exact.
  #[test]
  fn near_duplicates_found() -> Result<(), PipelineTestFailure> {
    let units = parse(
      "
def process_add(a, b):
    result = a + b
    x = result * 2
    return x

def process_mul(a, b):
    result = a * b
    x = result * 2
    return x
",
    )?;
    let exact = group_exact_duplicates(&units);

    let near = near_groups(&units, &exact, 0.5)?;
    let members: Vec<Vec<_>> = near
      .iter()
      .map(|group| group.members.iter().map(|unit| unit.name.as_str()).collect())
      .collect();
    ensure(
      units.len() == 2 && exact.is_empty() && members == [vec!["process_add", "process_mul"]],
      "similar definitions form one near group and no exact group",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::Near {
      units,
      exact,
      near,
      source: Box::new(source),
    })
  }

  /// Renamed identical bodies score one, while strongly different bodies remain below one half.
  #[test]
  fn similarity_scores_preserve_identity_and_structural_difference() -> Result<(), PipelineTestFailure> {
    for (document, threshold, expected) in [
      (
        "
def foo(a, b):
    return a + b

def bar(x, y):
    return x + y
",
        1.0,
        Ordering::Equal,
      ),
      (
        "
def simple(a):
    return a

def complex(a, b, c):
    x = a + b
    y = x * c
    z = y - a
    return z
",
        0.5,
        Ordering::Less,
      ),
    ] {
      let units = parse(document)?;
      let score = if let [ref left, ref right] = *units.as_slice() {
        Some(similarity_score(&left.body, &right.body))
      } else {
        None
      };
      ensure(
        matches!(&score, Some(Ok(value)) if value.value.total_cmp(&threshold) == expected),
        "the extracted pair satisfies its required similarity relation",
      )
      .map(drop)
      .map_err(|source| PipelineTestFailure::Similarity {
        document: document.to_owned(),
        threshold,
        expected,
        units,
        score: Box::new(score),
        source: Box::new(source),
      })?;
    }
    Ok(())
  }

  /// Exact statistics account for participating groups, units, and lines only when duplicates
  /// exist.
  #[test]
  fn exact_statistics_follow_duplicate_membership() -> Result<(), PipelineTestFailure> {
    for (document, has_exact) in [
      (EXACT_CORPUS, true),
      (
        "
def add(a, b):
    return a + b

def mul(a, b):
    return a * b
",
        false,
      ),
    ] {
      let units = parse(document)?;
      let exact = group_exact_duplicates(&units);
      let near = near_groups(&units, &exact, 0.8)?;
      let stats = compute_stats(&units, &exact, &near).map_err(|source| PipelineTestFailure::Measurement {
        units:  units.clone(),
        exact:  exact.clone(),
        near:   near.clone(),
        source: Box::new(source),
      })?;
      let accepts = if has_exact {
        stats.exact_duplicate_groups > 0 && stats.exact_duplicate_units > 0 && stats.exact_duplicate_lines > 0 && near.is_empty()
      } else {
        (
          stats.exact_duplicate_groups, stats.exact_duplicate_units, stats.exact_duplicate_lines,
        ) == (0, 0, 0)
      };
      ensure(accepts, "exact statistics follow the participating duplicate population")
        .map(drop)
        .map_err(|source| PipelineTestFailure::Statistics {
          document: document.to_owned(),
          has_exact,
          units,
          exact,
          near,
          stats: Box::new(stats),
          source: Box::new(source),
        })?;
    }
    Ok(())
  }

  /// Trait-level test detection preserves both matching and ordinary function names.
  #[test]
  fn is_test_code_through_trait() -> Result<(), PipelineTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    let units = analyzer.parse_file(
      Path::new("test.py"),
      "
def test_something():
    assert 1 == 1

def regular():
    return 42
",
      default_config(),
    )?;
    let observed: Vec<_> = units
      .iter()
      .map(|unit| (unit.name.as_str(), analyzer.is_test_code(unit)))
      .collect();
    ensure(
      observed == [("test_something", true), ("regular", false)],
      "the analyzer trait retains positive and negative test-name classification",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::Units {
      units,
      source,
    })
  }

  /// End-to-end test exclusion changes the selected population within an isolated root.
  #[test]
  fn analyze_end_to_end_with_exclude_tests() -> Result<(), PipelineTestFailure> {
    let analyzer = PythonAnalyzer::new()?;
    let workspace = TempDir::new()?;
    let python_file = workspace.path().join("example.py");
    fs::write(
      &python_file,
      [
        EXACT_CORPUS,
        "
def test_add():
    assert add(1, 2) == 3

def test_add2():
    assert add2(1, 2) == 3
",
      ]
      .concat(),
    )?;

    let files = [python_file];

    // Without excluding tests — use low thresholds so test functions are included
    let config_with_tests = Config {
      root: workspace.path().to_path_buf(),
      exclude_tests: false,
      min_nodes: 1,
      min_lines: 1,
      ..Default::default()
    };
    // With excluding tests
    let config_no_tests = Config {
      exclude_tests: true,
      ..config_with_tests.clone()
    };
    let outcomes = [
      dupes_core::analyze(&analyzer, &files, &config_with_tests),
      dupes_core::analyze(&analyzer, &files, &config_no_tests),
    ];
    ensure(
      matches!(outcomes, [Ok(ref with_tests), Ok(ref without_tests)]
      if with_tests.stats.total_code_units == 4 && without_tests.stats.total_code_units == 2),
      "test exclusion removes both test definitions while retaining both ordinary functions",
    )
    .map(drop)
    .map_err(|source| PipelineTestFailure::Analysis {
      outcomes: Box::new(outcomes),
      source,
    })
  }
}
