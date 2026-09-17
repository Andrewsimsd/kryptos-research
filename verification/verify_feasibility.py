#!/usr/bin/env python3
"""Independently solve component offsets and validate complete alphabet witnesses."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

from verify_baseline import read_json, validate_evidence
from verify_primers import expand

ROOT = Path(__file__).resolve().parents[1]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def components(edges, key):
    graph = defaultdict(list)
    for i, plain, cipher in edges:
        p, c = "p" + plain, "c" + cipher
        graph[p].append((c, key[i]))
        graph[c].append((p, -key[i]))
    potentials, result = {}, []
    for root in sorted(node for node in graph if node[0] == "p"):
        if root in potentials:
            continue
        potentials[root] = 0
        stack, members = [root], []
        while stack:
            node = stack.pop()
            members.append(node)
            for neighbor, shift in graph[node]:
                expected = (potentials[node] + shift) % 26
                if neighbor in potentials:
                    if potentials[neighbor] != expected:
                        return None
                else:
                    potentials[neighbor] = expected
                    stack.append(neighbor)
        component = {}
        for side, name in [("p", "plaintext"), ("c", "ciphertext")]:
            coordinates = [{"letter": node[1], "index": potentials[node]} for node in sorted(members) if node[0] == side]
            if len({entry["index"] for entry in coordinates}) != len(coordinates):
                return None
            component[name] = coordinates
        result.append(component)
    return sorted(result, key=lambda c: (-len(c["plaintext"]) - len(c["ciphertext"]), c["plaintext"][0]["letter"]))


def search_components(parts, node_limit):
    """Choose the component with the fewest currently legal offsets, using sets."""
    if type(node_limit) is not int or node_limit < 1:
        raise ValueError("positive reference node limit required")
    choices = [[({(c["index"] + offset) % 26 for c in part["plaintext"]},
                 {(c["index"] + offset) % 26 for c in part["ciphertext"]})
                for offset in range(26)] for part in parts]
    visited = 0

    def visit(remaining, plain, cipher, assignments):
        nonlocal visited
        if visited >= node_limit:
            return "budget_exhausted", None
        visited += 1
        if not remaining:
            return "feasible", assignments
        domains = {}
        for index in remaining:
            domains[index] = [offset for offset in ([0] if index == 0 else range(26))
                              if not choices[index][offset][0] & plain and not choices[index][offset][1] & cipher]
        index = min(remaining, key=lambda i: (len(domains[i]), i))
        for offset in domains[index]:
            p, c = choices[index][offset]
            result, solution = visit(remaining - {index}, plain | p, cipher | c, {**assignments, index: offset})
            if result != "infeasible":
                return result, solution
        return "infeasible", None

    status, offsets = visit(set(range(len(parts))), set(), set(), {})
    return status, offsets, visited


def check_witness(decision, parts, edges, key, equations):
    if set(decision) != {"status", "plaintext_alphabet", "ciphertext_alphabet", "offsets"}:
        raise ValueError("invalid feasible decision schema")
    maps = {}
    for side in ("plaintext", "ciphertext"):
        alphabet = decision[side + "_alphabet"]
        if not isinstance(alphabet, str) or sorted(alphabet) != list(AZ):
            raise ValueError("witness alphabet is not a permutation of A-Z")
        maps[side] = {letter: index for index, letter in enumerate(alphabet)}
    offsets = decision["offsets"]
    if (len(offsets) != len(parts) or any(type(v) is not int or not 0 <= v < 26 for v in offsets)
            or (offsets and offsets[0] != 0)):
        raise ValueError("invalid offsets or common-rotation normalization")
    for part, offset in zip(parts, offsets):
        for side in ("plaintext", "ciphertext"):
            for entry in part[side]:
                if maps[side][entry["letter"]] != (entry["index"] + offset) % 26:
                    raise ValueError("witness alphabet disagrees with component offset")
    expected = []
    for position, p, c in edges:
        pi, ci = maps["plaintext"][p], maps["ciphertext"][c]
        if (ci - pi) % 26 != key[position]:
            raise ValueError("complete alphabets violate a crib equation")
        expected.append({"position": position, "plaintext": p, "ciphertext": c,
                         "key": key[position], "plaintext_index": pi, "ciphertext_index": ci})
    if json.dumps(equations, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("crib equation trace differs")


def verify(report, request, evidence, primer_report, node_limit=1_000_000):
    known = validate_evidence(evidence)
    expected_primers = [record["primer"] for record in primer_report["survivors"]]
    if (set(request) != {"schema_version", "primers", "attempt_limit"} or type(request["schema_version"]) is not int
            or request["schema_version"] != 1 or request["primers"] != expected_primers
            or type(request["attempt_limit"]) is not int or not 1 <= request["attempt_limit"] <= 10_000_000):
        raise ValueError("request must bind the exact registered survivor list and valid budget")
    if (set(report) != {"schema_version", "evidence_id", "attempt_limit", "results"}
            or type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["evidence_id"] != evidence["evidence_id"]
            or type(report["attempt_limit"]) is not int or report["attempt_limit"] != request["attempt_limit"]
            or [r["primer"] for r in report["results"]] != expected_primers):
        raise ValueError("report schema, evidence, budget or primer coverage differs")
    edges = [(i, p, evidence["ciphertext"][i]) for i, p in sorted(known.items())]
    results = []
    for record in report["results"]:
        if set(record) != {"primer", "expanded_key", "report", "crib_equations"}:
            raise ValueError("invalid primer result schema")
        key = expand(record["primer"])[:97]
        if record["expanded_key"] != "".join(map(str, key)):
            raise ValueError("numeric key expansion differs")
        parts = components(edges, key)
        search = record["report"]
        if set(search) != {"components", "attempted_offsets", "decision"}:
            raise ValueError("invalid solver report schema")
        if json.dumps(search["components"], sort_keys=True) != json.dumps(parts or [], sort_keys=True):
            raise ValueError("component derivation differs")
        attempts = search["attempted_offsets"]
        if type(attempts) is not int or not 0 <= attempts <= request["attempt_limit"]:
            raise ValueError("invalid attempt accounting")
        decision = search["decision"]
        if decision["status"] == "feasible":
            if parts is None:
                raise ValueError("claimed witness despite local contradiction")
            check_witness(decision, parts, edges, key, record["crib_equations"])
        elif decision["status"] == "infeasible":
            if set(decision) != {"status", "reason"} or not isinstance(decision["reason"], str) or record["crib_equations"]:
                raise ValueError("invalid infeasible record")
        elif decision["status"] == "budget_exhausted":
            if set(decision) != {"status"} or attempts != request["attempt_limit"] or record["crib_equations"]:
                raise ValueError("invalid incomplete-search record")
        else:
            raise ValueError("unknown solver status")
        if parts is None:
            reference_status, states = "infeasible", 0
        else:
            reference_status, _, states = search_components(parts, node_limit)
        resolved = decision["status"] != "budget_exhausted" and reference_status != "budget_exhausted"
        if resolved and decision["status"] != reference_status:
            raise ValueError(f"independent feasibility decision disagrees: {record['primer']}")
        results.append({"primer": record["primer"], "rust_status": decision["status"], "reference_status": reference_status,
                        "resolved": resolved, "components": len(parts or []), "rust_offset_attempts": attempts,
                        "reference_states": states, "crib_equations_checked": len(record["crib_equations"])})
    return {"status": "verified", "primers_checked": len(results),
            "feasible": sum(r["resolved"] and r["rust_status"] == "feasible" for r in results),
            "infeasible": sum(r["resolved"] and r["rust_status"] == "infeasible" for r in results),
            "unresolved": sum(not r["resolved"] for r in results), "results": results,
            "limitations": "Compatibility witnesses only; arbitrary unconstrained alphabet completion, no intended plaintext recovery. Same coordinator, not fresh-context A7."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = read_json(args.report)
        result = verify(report, read_json(args.request), read_json(ROOT / "evidence/k4.json"),
                        read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json"))
        result["report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"feasibility verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
