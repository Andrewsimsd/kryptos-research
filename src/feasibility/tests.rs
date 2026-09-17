use super::*;
use crate::cipher::alphabet::Alphabet;

fn cribs(text: &str) -> Vec<Crib> {
    text.chars()
        .enumerate()
        .map(|(position, letter)| Crib { position, letter })
        .collect()
}

#[test]
fn empty_problem_completes_both_alphabets_without_search() {
    let result = solve("", &[], &[], 1).unwrap();
    assert_eq!(result.attempted_offsets, 0);
    if let Decision::Feasible {
        plaintext_alphabet,
        ciphertext_alphabet,
        offsets,
    } = result.decision
    {
        assert_eq!(
            (plaintext_alphabet, ciphertext_alphabet, offsets),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ".into(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ".into(),
                vec![]
            )
        );
    } else {
        panic!("expected empty feasible problem");
    }
}

#[test]
fn repeated_edges_cycles_and_local_collisions_are_exact_contradictions() {
    for (plain, cipher, key) in [
        ("AA", "BB", vec![0, 1]),
        ("AB", "CC", vec![0, 0]),
        ("AA", "BC", vec![0, 0]),
        ("AABB", "CDCD", vec![0, 1, 2, 4]),
    ] {
        let result = solve(cipher, &cribs(plain), &key, 100).unwrap();
        assert!(matches!(result.decision, Decision::Infeasible { .. }));
        assert_eq!(result.attempted_offsets, 0);
    }
}

#[test]
fn independent_components_can_overlap_between_different_alphabets_only() {
    let result = solve("BC", &cribs("AB"), &[1, 1], 100).unwrap();
    if let Decision::Feasible {
        plaintext_alphabet,
        ciphertext_alphabet,
        offsets,
    } = result.decision
    {
        let p = Alphabet::from_order(&plaintext_alphabet).unwrap();
        let c = Alphabet::from_order(&ciphertext_alphabet).unwrap();
        assert_eq!(offsets, [0, 1]);
        assert_eq!((p.index(b'A').unwrap() + 1) % 26, c.index(b'B').unwrap());
        assert_eq!((p.index(b'B').unwrap() + 1) % 26, c.index(b'C').unwrap());
    } else {
        panic!("expected compatible components");
    }
}

#[test]
fn invalid_inputs_and_attempt_limits_are_errors() {
    for (cipher, known, key, limit) in [
        ("?", vec![], vec![0], 100),
        ("A", cribs("a"), vec![0], 100),
        ("A", cribs("AA"), vec![0], 100),
        ("A", cribs("A"), vec![], 100),
        ("A", cribs("A"), vec![26], 100),
        ("A", cribs("A"), vec![0], 0),
        ("A", cribs("A"), vec![0], 10_000_001),
    ] {
        assert!(solve(cipher, &known, &key, limit).is_err());
    }
}

#[test]
fn cap_is_distinct_from_impossibility() {
    assert!(matches!(
        solve("BC", &cribs("AB"), &[1, 1], 1).unwrap().decision,
        Decision::BudgetExhausted
    ));
}

#[test]
fn locally_consistent_components_can_be_globally_infeasible() {
    let plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let cipher = format!("{}{}", "A".repeat(13), "B".repeat(13));
    let key: Vec<_> = (0_u8..13)
        .map(|i| (26 - 2 * i) % 26)
        .chain((0_u8..13).map(|i| (26 - i) % 26))
        .collect();
    let result = solve(&cipher, &cribs(plain), &key, 27).unwrap();
    assert_eq!(result.components.len(), 2);
    assert!(matches!(result.decision, Decision::Infeasible { .. }));
    assert_eq!(result.attempted_offsets, 27);
}

#[test]
fn wrapping_edges_and_planted_alphabets_are_satisfiable() {
    for multiplier in [1_u16, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25] {
        let plain: String = (0_u8..97).map(|i| char::from(b'A' + i % 26)).collect();
        let key: Vec<_> = (0_u8..97).map(|i| i % 10).collect();
        let cipher: String = plain
            .bytes()
            .zip(&key)
            .map(|(p, &k)| {
                char::from(
                    b'Z' - u8::try_from(
                        (u16::from(p - b'A') * multiplier + 25 + u16::from(k)) % 26,
                    )
                    .unwrap(),
                )
            })
            .collect();
        let result = solve(&cipher, &cribs(&plain), &key, 10000).unwrap();
        if let Decision::Feasible {
            plaintext_alphabet,
            ciphertext_alphabet,
            ..
        } = result.decision
        {
            let p = Alphabet::from_order(&plaintext_alphabet).unwrap();
            let c = Alphabet::from_order(&ciphertext_alphabet).unwrap();
            for ((a, b), &k) in plain.bytes().zip(cipher.bytes()).zip(&key) {
                assert_eq!((p.index(a).unwrap() + k) % 26, c.index(b).unwrap());
            }
        } else {
            panic!("planted alphabets must be feasible");
        }
    }
}
