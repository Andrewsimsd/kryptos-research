//! Published known answers, not merely mutually consistent round trips.

use kryptos_research::transforms::execute_batch;
use serde_json::{Value, json};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../fixtures/known-answers.json")).unwrap()
}

#[test]
fn every_published_fixture_matches_in_both_directions() {
    for fixture in fixtures()["cases"].as_array().unwrap() {
        for (direction, input, expected) in [
            ("encrypt", "plaintext", "ciphertext"),
            ("decrypt", "ciphertext", "plaintext"),
        ] {
            let request = json!({"schema_version":1,"cases":[{"id":fixture["id"],"input":fixture[input],"direction":direction,"stages":fixture["stages"]}]});
            let result =
                serde_json::to_value(execute_batch(&request.to_string()).unwrap()).unwrap();
            assert_eq!(
                result["cases"][0]["output"], fixture[expected],
                "{} {direction}",
                fixture["id"]
            );
        }
    }
}

#[test]
fn k3_trace_composition_matches_all_336_frozen_source_indices() {
    let data = fixtures();
    let fixture = &data["cases"][3];
    let request = json!({"schema_version":1,"cases":[{"id":"K3","input":fixture["ciphertext"],"direction":"decrypt","stages":fixture["stages"]}]});
    let result = serde_json::to_value(execute_batch(&request.to_string()).unwrap()).unwrap();
    let stages = &result["cases"][0]["stages"];
    let actual: Vec<_> = stages[1]["trace"]
        .as_array()
        .unwrap()
        .iter()
        .map(|position| {
            let intermediate = usize::try_from(position["input_index"].as_u64().unwrap()).unwrap();
            stages[0]["trace"][intermediate]["input_index"].clone()
        })
        .collect();
    assert_eq!(Value::Array(actual), data["k3_decryption_source_indices"]);
}

#[test]
fn corrected_k2_is_exactly_one_declared_insertion() {
    let data = fixtures();
    let original = data["cases"][1]["ciphertext"].as_str().unwrap();
    let mut corrected = original.to_owned();
    corrected.insert(361, 'S');
    assert_eq!(corrected, data["cases"][2]["ciphertext"].as_str().unwrap());
}
