use super::*;
use serde_json::json;

fn request() -> Request {
    serde_json::from_str(include_str!(
        "../../fixtures/keyword-alphabets-request.json"
    ))
    .unwrap()
}

fn evidence() -> Evidence {
    Evidence::from_json(include_str!("../../evidence/k4.json")).unwrap()
}

#[test]
fn six_forward_orders_and_reversals_are_stable() {
    let bases = request().base_orders().unwrap();
    let forwards: Vec<_> = bases
        .iter()
        .step_by(2)
        .map(|base| base.alphabet.order())
        .collect();
    assert_eq!(forwards.len(), 6);
    assert_eq!(
        forwards,
        [
            "KRYPTOSABCDEFGHIJLMNQUVWXZ",
            "KAHUOFNPDLXRBIVSGQTEMZYCJW",
            "PALIMSETBCDFGHJKNOQRUVWXYZ",
            "ACOZEJWIFRLDQMGUPBNYSHVTKX",
            "ABSCIDEFGHJKLMNOPQRTUVWXYZ",
            "ADJOUZBEKPVCGMRXIHNTYSFLQW",
        ]
    );
    for pair in bases.chunks_exact(2) {
        assert_eq!(pair[1].alphabet, pair[0].alphabet.reversed());
    }
    assert_eq!(
        aca_transposed_alphabet("ENIGMA").unwrap().order(),
        "AJRXEBKSYGFPVIDOUMHQWNCLTZ"
    );
}

#[test]
fn candidate_index_round_trips_boundaries() {
    for index in [0, 25, 26, CANDIDATE_COUNT - 1] {
        assert_eq!(
            encode_candidate(&decode_candidate(index).unwrap()).unwrap(),
            index
        );
    }
    assert!(decode_candidate(CANDIDATE_COUNT).is_err());
    let invalid = CandidateCoordinates {
        primer_index: PRIMER_COUNT,
        plaintext_base_index: 0,
        ciphertext_base_index: 0,
        ciphertext_rotation: 0,
    };
    assert!(encode_candidate(&invalid).is_err());
}

#[test]
fn malformed_request_domains_are_rejected() {
    for field in [
        "schema_version",
        "primers",
        "keywords",
        "constructors",
        "orientations",
        "ciphertext_rotations",
        "key_offset",
        "calibration",
    ] {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/keyword-alphabets-request.json"
        ))
        .unwrap();
        match field {
            "schema_version" => value[field] = json!(2),
            "key_offset" => value[field] = json!(1),
            "calibration" => value[field]["case_count"] = json!(143),
            _ => {
                value[field].as_array_mut().unwrap().pop();
            }
        }
        let parsed: Request = serde_json::from_value(value).unwrap();
        assert!(parsed.validate().is_err(), "{field}");
    }
}

#[test]
fn sorted_but_unregistered_primer_domain_is_rejected() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "../../fixtures/keyword-alphabets-request.json"
    ))
    .unwrap();
    value["primers"][0] = json!("10318");
    let parsed: Request = serde_json::from_value(value).unwrap();
    assert!(parsed.validate().is_err());
}

#[test]
fn calibration_schema_rejects_unknown_fields() {
    let mut value = serde_json::to_value(calibrate(&evidence(), &request()).unwrap()).unwrap();
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<CalibrationReport>(value).is_err());
}

#[test]
fn census_matches_registered_design_analysis() {
    let evidence = evidence();
    let request = request();
    let bases = request.base_orders().unwrap();
    let report = calibrate(&evidence, &request).unwrap();
    assert_eq!(
        (
            report.signature_census.distinct_signatures,
            report.signature_census.singleton_buckets,
            report.signature_census.doubleton_buckets,
            report.signature_census.unique_physical_candidates,
            report.signature_census.maximum_bucket_size,
        ),
        (123_552, 101_088, 22_464, 101_088, 2)
    );
    let first = encode_candidate(&CandidateCoordinates {
        primer_index: 19,
        plaintext_base_index: 1,
        ciphertext_base_index: 1,
        ciphertext_rotation: 16,
    })
    .unwrap();
    let second = encode_candidate(&CandidateCoordinates {
        primer_index: 20,
        plaintext_base_index: 0,
        ciphertext_base_index: 0,
        ciphertext_rotation: 0,
    })
    .unwrap();
    let buckets = signature_index(&evidence, &request, &bases).unwrap();
    assert!(buckets.values().any(|bucket| bucket == &[first, second]));
}

#[test]
fn all_planted_cases_retain_and_reencrypt_true_candidate() {
    let report = calibrate(&evidence(), &request()).unwrap();
    assert!(report.passed);
    assert_eq!(
        (
            report.cases.len(),
            report.retained_cases,
            report.plaintext_recovery_cases,
            report.reencryption_cases
        ),
        (144, 144, 144, 144)
    );
    assert_eq!(report.full_message_recovery_cases, 144);
    assert_eq!(report.operation_counts.total(), 3_546_288);
    assert!(report.cases.iter().all(|case| {
        case.recovered_candidate_indices
            .contains(&case.true_candidate_index)
            && case.full_message.passed
    }));
}

#[test]
fn recovered_candidate_round_trips_empty_single_and_full_messages() {
    let request = request();
    let bases = request.base_orders().unwrap();
    let coordinates = CandidateCoordinates {
        primer_index: 0,
        plaintext_base_index: 11,
        ciphertext_base_index: 10,
        ciphertext_rotation: 25,
    };
    let candidate = encode_candidate(&coordinates).unwrap();
    let full_key = expanded_key(&request.primers[0]).unwrap();
    for length in [0, 1, MESSAGE_LENGTH] {
        let plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            .chars()
            .cycle()
            .take(length)
            .collect::<String>();
        let cipher = bases[10].alphabet.rotated(25);
        let ciphertext = encrypt(
            &plaintext,
            &full_key[..length],
            &bases[11].alphabet,
            &cipher,
        )
        .unwrap();
        let recovered = decrypt(
            &ciphertext,
            &full_key[..length],
            &bases[11].alphabet,
            &cipher,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
        if length == MESSAGE_LENGTH {
            assert_eq!(
                recover_full_message(candidate, &ciphertext, &plaintext, &request, &bases).unwrap(),
                (true, true)
            );
        }
    }
}

#[test]
fn wrong_model_and_tampered_ciphertext_fail_full_message_recovery() {
    let request = request();
    let bases = request.base_orders().unwrap();
    let plaintext = "A".repeat(MESSAGE_LENGTH);
    let key = expanded_key(&request.primers[0]).unwrap();
    let ciphertext = encrypt(&plaintext, &key, &bases[0].alphabet, &bases[0].alphabet).unwrap();
    let wrong_model = encode_candidate(&CandidateCoordinates {
        primer_index: 1,
        plaintext_base_index: 0,
        ciphertext_base_index: 0,
        ciphertext_rotation: 0,
    })
    .unwrap();
    assert_eq!(
        recover_full_message(wrong_model, &ciphertext, &plaintext, &request, &bases).unwrap(),
        (false, true)
    );
    let mut tampered = ciphertext.into_bytes();
    tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert_eq!(
        recover_full_message(0, &tampered, &plaintext, &request, &bases).unwrap(),
        (false, true)
    );
    assert!(encrypt("A", &[], &bases[0].alphabet, &bases[0].alphabet).is_err());
    assert!(decrypt("A", &[], &bases[0].alphabet, &bases[0].alphabet).is_err());
}

#[test]
fn k4_gate_rejects_tampered_or_failed_calibration() {
    let request = request();
    let evidence = evidence();
    let mut report = calibrate(&evidence, &request).unwrap();
    report.passed = false;
    assert!(evaluate_k4(&evidence, &request, &report).is_err());
}
