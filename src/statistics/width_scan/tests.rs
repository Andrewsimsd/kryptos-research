use super::*;

fn evidence() -> Evidence {
    Evidence::from_json(include_str!("../../../evidence/k4.json")).unwrap()
}

#[test]
fn width_twenty_one_matches_existing_measurement() {
    let e = evidence();
    let fixed = crate::statistics::StatisticModel::new(&e);
    assert_eq!(
        measure_widths(e.ciphertext()).unwrap()[20],
        fixed.measure(e.ciphertext()).unwrap()[0]
    );
}

#[test]
fn repeated_types_and_available_pairs_have_correct_boundaries() {
    assert_eq!(measure_widths(&"A".repeat(97)).unwrap(), vec![1; 48]);
    assert_eq!(
        (empty_histograms()[0].len(), empty_histograms()[47].len()),
        (49, 25)
    );
    let text: String = (0_u8..97).map(|i| char::from(b'A' + i % 26)).collect();
    assert_eq!(measure_widths(&text).unwrap()[47], 23);
}

#[test]
fn invalid_text_is_rejected() {
    for text in ["", "A", &"A".repeat(98), &"a".repeat(97), &"é".repeat(97)] {
        assert!(measure_widths(text).is_err());
    }
}

#[test]
fn exact_comparison_handles_signs_scaling_and_ties() {
    let a = Score {
        numerator: 1,
        variance: 1,
    };
    let b = Score {
        numerator: 2,
        variance: 4,
    };
    assert_eq!(a.compare(b), Ordering::Equal);
    let negative = Score {
        numerator: -1,
        variance: 1,
    };
    assert_eq!(negative.compare(a), Ordering::Less);
    assert_eq!(
        negative.compare(Score {
            numerator: -2,
            variance: 1
        }),
        Ordering::Greater
    );
    assert_eq!(
        a.compare(Score {
            numerator: 0,
            variance: 1
        }),
        Ordering::Greater
    );
    assert_eq!(winner(&[0, 0], &[vec![a], vec![b]]), 0);
}

#[test]
fn zero_calibration_variance_is_an_error() {
    assert!(score_table(10, &[10; 48], &[10; 48]).is_err());
}

#[test]
fn request_bounds_and_equal_seeds_are_errors() {
    for (schema_version, calibration_samples, samples, seed) in [
        (2, 100, 10, 2),
        (1, 1, 10, 2),
        (1, 1_000_001, 10, 2),
        (1, 100, 0, 2),
        (1, 100, 1_000_001, 2),
        (1, 100, 10, 1),
    ] {
        assert!(
            scan(
                &evidence(),
                ScanRequest {
                    schema_version,
                    calibration_samples,
                    samples,
                    calibration_seed: 1,
                    seed
                }
            )
            .is_err()
        );
    }
}

#[test]
fn histograms_cover_every_trial_and_preserve_multisets() {
    let e = evidence();
    let report = scan(
        &e,
        ScanRequest {
            schema_version: 1,
            calibration_samples: 100,
            samples: 20,
            calibration_seed: 0,
            seed: u64::MAX,
        },
    )
    .unwrap();
    assert!(
        report
            .calibration
            .histograms
            .iter()
            .all(|h| h.iter().sum::<u32>() == 100)
    );
    assert!(
        report
            .evaluation
            .histograms
            .iter()
            .all(|h| h.iter().sum::<u32>() == 20)
    );
    assert_eq!(report.maxima_histograms.iter().flatten().sum::<u32>(), 20);
    let mut original = e.ciphertext().as_bytes().to_vec();
    original.sort_unstable();
    for text in report.evaluation.first_permutations {
        let mut actual = text.into_bytes();
        actual.sort_unstable();
        assert_eq!(actual, original);
    }
}
