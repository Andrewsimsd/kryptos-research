# Milestone 8 workload clarification

This supplemental note clarifies the workload labels in the frozen
`KEYWORD-ALPHABETS-0003` specification and convention document. It does not
change the model, evidence, operation unit, result, or immutable run-001.

The specification's `execution_operation_cap` of **10,596,960** applies to the
primary Rust keyword workload executed by the coordinator:

| Primary Rust stage | Equation/position operations |
| --- | ---: |
| Produce calibration | 3,546,288 |
| Evaluator regenerates calibration | 3,546,288 |
| Evaluate K4 | 3,504,384 |
| **Primary Rust total and registered cap** | **10,596,960** |

The coordinator also runs two independently derived Python stages. They use the
same scientific unit and must be reported separately:

| Python verification stage | Equation/position operations |
| --- | ---: |
| Pre-search calibration regeneration | 3,546,288 |
| Post-search calibration plus K4 regeneration | 7,050,672 |
| **Python total** | **10,596,960** |

The combined keyword equation/position workload is therefore **21,193,920**.
Builds, JSON parsing and comparison, foundations fixtures, and baseline/primer/
feasibility/structured regression commands are not measured in this scientific
unit. The registered 600-second wall-time cap bounds the entire coordinator,
including those uncounted activities.

Run-001 performed all of these stages and its artifacts pass the tightened
semantic verifier. Its completion document predates this split and retains only
the primary Rust total. Later completions record the primary Rust, Python, and
combined totals explicitly. This reporting correction does not alter the exact
zero-survivor conclusion for the unchanged 146,016-model family.
