use super::*;
use crate::evidence::Evidence;

fn model() -> StatisticModel {
    StatisticModel::new(&Evidence::from_json(include_str!("../../evidence/k4.json")).unwrap())
}

#[test]
fn minor_distance_handles_wrap_antipodes_and_equality() {
    assert_eq!(
        [minor(0, 25), minor(0, 13), minor(4, 4), minor(25, 0)],
        [1, 13, 0, 1]
    );
}

#[test]
fn observed_statistics_match_published_sums_and_pair_counts() {
    let m = model();
    assert_eq!((m.selected.len(), m.pairs.len()), (10, 13));
    assert_eq!(m.measure_digits(&m.original), [11, 21, 47, 10, 6]);
}

#[test]
fn repeated_types_count_once_and_adjacent_pairs_overlap() {
    let m = model();
    let values = m.measure(&"A".repeat(97)).unwrap();
    assert_eq!((values[0], values[2], values[3], values[4]), (1, 0, 13, 96));
}

#[test]
fn invalid_text_and_lengths_are_rejected() {
    for text in ["", "A", &"A".repeat(98), &"?".repeat(97), &"é".repeat(97)] {
        assert!(model().measure(text).is_err());
    }
}

#[test]
fn bad_requests_fail_before_sampling() {
    for (schema_version, samples) in [(2, 1), (1, 0), (1, 10_000_001), (1, u32::MAX)] {
        assert!(
            simulate(
                &model(),
                SimulationRequest {
                    schema_version,
                    samples,
                    seed: 0
                }
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_str::<SimulationRequest>(
            r#"{"schema_version":1,"samples":1,"seed":0,"extra":1}"#
        )
        .is_err()
    );
}

#[test]
fn deterministic_simulation_preserves_multiset_and_complete_histograms() {
    let m = model();
    let request = SimulationRequest {
        schema_version: 1,
        samples: 20,
        seed: u64::MAX,
    };
    let report = simulate(&m, request.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(simulate(&m, request).unwrap()).unwrap()
    );
    assert!(
        report
            .histograms
            .iter()
            .all(|histogram| histogram.iter().sum::<u32>() == 20)
    );
    let mut expected = m.original.clone();
    expected.sort_unstable();
    for text in report.first_permutations {
        let mut actual: Vec<_> = text.bytes().map(|b| b - b'A').collect();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }
}

#[test]
fn single_sample_is_retained_and_measured() {
    let m = model();
    let report = simulate(
        &m,
        SimulationRequest {
            schema_version: 1,
            samples: 1,
            seed: 0,
        },
    )
    .unwrap();
    assert_eq!(report.first_permutations.len(), 1);
    for (histogram, value) in report
        .histograms
        .iter()
        .zip(m.measure(&report.first_permutations[0]).unwrap())
    {
        assert_eq!(histogram[usize::try_from(value).unwrap()], 1);
    }
}
