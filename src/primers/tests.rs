use super::*;

fn constraints(plain: &str, cipher: &str) -> PrimerConstraints {
    let cribs: Vec<_> = plain
        .chars()
        .enumerate()
        .map(|(position, letter)| Crib { position, letter })
        .collect();
    PrimerConstraints::new(cipher, &cribs).unwrap()
}

#[test]
fn repeated_pair_requires_equal_key_digits() {
    let model = constraints("AA", "BB");
    assert!(model.first_violation(&[0, 1]).unwrap().is_some());
    assert_eq!(model.first_violation(&[25, 25]).unwrap(), None);
}

#[test]
fn sharing_only_one_letter_requires_different_digits() {
    for model in [constraints("AA", "BC"), constraints("AB", "CC")] {
        assert!(model.first_violation(&[0, 0]).unwrap().is_some());
        assert_eq!(model.first_violation(&[0, 25]).unwrap(), None);
    }
}

#[test]
fn four_edge_cycle_detects_contradiction_after_pair_checks_pass() {
    let model = constraints("AABB", "CDCD");
    let index = model.first_violation(&[0, 1, 2, 4]).unwrap().unwrap();
    assert!(index >= model.simple_count && model.relations[index].equal_zero);
    assert_eq!(model.first_violation(&[0, 1, 2, 3]).unwrap(), None);
}

#[test]
fn distant_letters_cannot_collide_within_an_alphabet() {
    let model = constraints("AABBC", "XYZYZ");
    assert!(model.first_violation(&[1, 2, 3, 1, 4]).unwrap().is_some());
}

#[test]
fn alphabet_arithmetic_wraps_modulo_twenty_six() {
    let model = constraints("AABB", "CDCD");
    assert_eq!(model.first_violation(&[25, 0, 0, 1]).unwrap(), None);
}

#[test]
fn independent_components_do_not_impose_a_common_offset() {
    assert_eq!(
        constraints("AB", "CD").first_violation(&[0, 0]).unwrap(),
        None
    );
}

#[test]
fn empty_singleton_and_duplicate_cribs_are_supported() {
    assert!(constraints("", "").relations().is_empty());
    assert!(constraints("A", "B").relations().is_empty());
    let crib = Crib {
        position: 0,
        letter: 'A',
    };
    assert!(
        PrimerConstraints::new("B", &[crib, crib])
            .unwrap()
            .relations()
            .is_empty()
    );
}

#[test]
fn malformed_inputs_are_rejected() {
    for (cipher, cribs) in [
        ("?", vec![]),
        ("é", vec![]),
        (
            "A",
            vec![Crib {
                position: usize::MAX,
                letter: 'A',
            }],
        ),
        (
            "A",
            vec![Crib {
                position: 0,
                letter: 'é',
            }],
        ),
        (
            "A",
            vec![
                Crib {
                    position: 0,
                    letter: 'A',
                },
                Crib {
                    position: 0,
                    letter: 'B',
                },
            ],
        ),
    ] {
        assert!(PrimerConstraints::new(cipher, &cribs).is_err());
    }
    let model = constraints("AA", "BC");
    assert!(model.first_violation(&[0]).is_err());
    assert!(model.first_violation(&[0, 26]).is_err());
    assert!(model.first_violation(&[0, 1, 255]).is_err());
}

#[test]
fn planted_permutations_never_reject_their_true_key() {
    // 12 invertible affine maps modulo 26 exercise both alphabet directions.
    for multiplier in [1_u8, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25] {
        for shift in [0_u8, 1, 13, 25] {
            let plain: Vec<_> = (0_u8..97).map(|i| i % 26).collect();
            let key = Recurrence::new(10, vec![shift % 10, multiplier % 10, 0, 9, 1])
                .unwrap()
                .generate(97)
                .unwrap();
            let cipher: String = plain
                .iter()
                .zip(&key)
                .map(|(&letter, &digit)| {
                    let coordinate = (u16::from(letter) * u16::from(multiplier)
                        + u16::from(shift)
                        + u16::from(digit))
                        % 26;
                    // Reverse the ciphertext alphabet independently of the plaintext map.
                    char::from(b'Z' - u8::try_from(coordinate).unwrap())
                })
                .collect();
            let text: String = plain
                .iter()
                .map(|&letter| char::from(b'A' + letter))
                .collect();
            assert_eq!(
                constraints(&text, &cipher).first_violation(&key).unwrap(),
                None
            );
        }
    }
}

#[test]
fn reordered_cribs_generate_identical_relations() {
    let cribs = [
        Crib {
            position: 0,
            letter: 'A',
        },
        Crib {
            position: 1,
            letter: 'A',
        },
    ];
    assert_eq!(
        PrimerConstraints::new("BC", &cribs).unwrap().relations(),
        PrimerConstraints::new("BC", &[cribs[1], cribs[0]])
            .unwrap()
            .relations()
    );
}
