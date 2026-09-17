#!/usr/bin/env python3
"""Check all decimal primers using numeric graph traversal and signed certificates.

Separately implemented by the same coordinator, not a fresh-context A7 review.
Uses no Rust-generated relations for its independent primer classification.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

from verify_baseline import read_json, validate_evidence
ROOT = Path(__file__).resolve().parents[1]


def expand(primer):
    if len(primer) != 5 or any(c not in "0123456789" for c in primer):
        raise ValueError("primer requires exactly five ASCII decimal digits")
    key = [int(c) for c in primer]
    for index in range(93):
        key.append((key[index] + key[index + 1]) % 10)
    return key


def edges_from_evidence(evidence):
    # Independent strict evidence parsing also checks hashes via the runner.
    evidence = read_json(evidence)
    known = validate_evidence(evidence)
    ciphertext = evidence["ciphertext"]
    return [(i, "p" + p, "c" + ciphertext[i]) for i, p in sorted(known.items())]


def pair_conditions(edges):
    return [(a[0], b[0], a[1:] == b[1:])
            for n, a in enumerate(edges) for b in edges[n + 1:]
            if a[1] == b[1] or a[2] == b[2]]


def adjacency(edges):
    graph = defaultdict(list)
    for position, plain, cipher in edges:
        graph[plain].append((cipher, position, 1))
        graph[cipher].append((plain, position, -1))
    return graph


def graph_consistent(graph, key):
    """Assign numeric coordinates by DFS; test cycles and local injectivity."""
    values = {}
    for root in sorted(graph):
        if root in values:
            continue
        values[root] = 0
        occupied = {"p": set(), "c": set()}
        stack = [root]
        while stack:
            node = stack.pop()
            if values[node] in occupied[node[0]]:
                return False
            occupied[node[0]].add(values[node])
            for neighbor, position, sign in graph[node]:
                expected = (values[node] + sign * key[position]) % 26
                if neighbor in values:
                    if values[neighbor] != expected:
                        return False
                else:
                    values[neighbor] = expected
                    stack.append(neighbor)
    return True


def validate_relation(relation, edges):
    """Prove a certificate follows from signed crib equations, not a fitted rule."""
    if set(relation) != {"equal_zero", "terms"} or type(relation["equal_zero"]) is not bool:
        raise ValueError("invalid relation schema")
    lookup = {position: (plain, cipher) for position, plain, cipher in edges}
    balance = Counter()
    positions = []
    for term in relation["terms"]:
        if set(term) != {"position", "coefficient"}:
            raise ValueError("invalid term schema")
        position, coefficient = term["position"], term["coefficient"]
        if type(position) is not int or position not in lookup or type(coefficient) is not int or coefficient == 0:
            raise ValueError("invalid relation term")
        plain, cipher = lookup[position]
        balance[plain] -= coefficient
        balance[cipher] += coefficient
        positions.append(position)
    if not positions or positions != sorted(set(positions)) or relation["terms"][0]["coefficient"] < 0:
        raise ValueError("relation is not canonical")
    balance = {node: value for node, value in balance.items() if value}
    if relation["equal_zero"]:
        valid = not balance
    else:
        valid = (len(balance) == 2 and sorted(balance.values()) == [-1, 1]
                 and len({node[0] for node in balance}) == 1)
    if not valid:
        raise ValueError("relation does not follow from crib equations and bijections")


def holds(relation, key):
    residue = sum(term["coefficient"] * key[term["position"]] for term in relation["terms"]) % 26
    return (residue == 0) == relation["equal_zero"]


def parse_upstream(text):
    records = []
    for line in text.splitlines():
        number, count, expanded = line.split()
        primer = f"{int(number):05d}"
        if not 1 <= int(number) <= 99999:
            raise ValueError("upstream primer outside domain")
        key = expand(primer)
        if expanded != "".join(map(str, key)) or int(count) != len(set(key[:97])):
            raise ValueError("upstream expansion or distinct-digit count disagrees")
        records.append({"primer": primer, "expanded_key": expanded, "distinct_digits": int(count)})
    if [r["primer"] for r in records] != sorted({r["primer"] for r in records}):
        raise ValueError("upstream primers must be unique and increasing")
    return records


def verify(report, edges, upstream):
    if set(report) != {"schema_version", "evidence_id", "examined", "simple_survivors", "constraints", "rejected_by_relation", "survivors"}:
        raise ValueError("invalid report schema")
    if any(type(report[name]) is not int for name in ("schema_version", "examined", "simple_survivors")):
        raise ValueError("integer report counts required")
    if report["evidence_id"] != "K4-v1" or set(report["constraints"]) != {"length", "simple_count", "relations"}:
        raise ValueError("incorrect evidence or constraints schema")
    relations = report["constraints"]["relations"]
    simple_count = report["constraints"]["simple_count"]
    if report["schema_version"] != 1 or report["examined"] != 99999 or type(report["constraints"]["length"]) is not int or report["constraints"]["length"] != 97:
        raise ValueError("incorrect report domain")
    if type(simple_count) is not int or not 0 <= simple_count <= len(relations):
        raise ValueError("invalid simple constraint count")
    for relation in relations:
        validate_relation(relation, edges)
    if any(len(r["terms"]) != 2 for r in relations[:simple_count]):
        raise ValueError("simple relation is not a pair")
    groups = report["rejected_by_relation"]
    if len(groups) != len(relations):
        raise ValueError("one rejection group required per relation")
    classification = {}
    for index, numbers in enumerate(groups):
        if numbers != sorted(set(numbers)):
            raise ValueError("rejection group is not sorted and unique")
        for number in numbers:
            if type(number) is not int or not 1 <= number <= 99999 or number in classification:
                raise ValueError("invalid or multiply classified primer")
            classification[number] = index
    survivor_numbers = []
    for record in report["survivors"]:
        key = expand(record["primer"])
        number = int(record["primer"])
        if not 1 <= number <= 99999 or number in classification:
            raise ValueError("invalid or multiply classified survivor")
        expected = {"primer": f"{number:05d}", "expanded_key": "".join(map(str, key)), "distinct_digits": len(set(key[:97]))}
        if json.dumps(record, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError("incorrect survivor record")
        classification[number] = None
        survivor_numbers.append(number)
    if survivor_numbers != sorted(survivor_numbers) or set(classification) != set(range(1, 100000)):
        raise ValueError("missing or unordered domain coverage")
    graph = adjacency(edges)
    pairs = pair_conditions(edges)
    simple_survivors = 0
    survivors = []
    for number in range(1, 100000):
        key = expand(f"{number:05d}")
        simple_pass = all((key[a] == key[b]) == equal for a, b, equal in pairs)
        simple_survivors += simple_pass
        survives = simple_pass and graph_consistent(graph, key)
        first_failure = next((i for i, relation in enumerate(relations) if not holds(relation, key)), None)
        if first_failure != classification[number] or survives != (first_failure is None):
            raise ValueError(f"certificate/graph/classification disagreement for {number:05d}")
        if simple_pass != (first_failure is None or first_failure >= simple_count):
            raise ValueError("simple-stage disagreement")
        if survives:
            survivors.append(f"{number:05d}")
    if simple_survivors != report["simple_survivors"]:
        raise ValueError("simple-stage count disagrees")
    reference = parse_upstream(upstream)
    rust_set, c_set = set(survivors), {r["primer"] for r in reference}
    # A discrepancy is preserved as data, not concealed by stopping artifact creation.
    return {"status": "verified", "examined": 99999, "simple_survivors": simple_survivors,
            "graph_survivors": len(survivors), "upstream_survivors": len(reference),
            "exact_upstream_match": report["survivors"] == reference,
            "only_graph": sorted(rust_set - c_set), "only_upstream": sorted(c_set - rust_set),
            "relations_verified": len(relations), "rejections_verified": 99999 - len(survivors),
            "survivors": survivors, "reference_implementation": "same coordinator; no fresh-context review"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    args = parser.parse_args()
    try:
        edges = edges_from_evidence(ROOT / "evidence/k4.json")
        result = verify(read_json(args.report), edges, args.upstream.read_text())
        result["report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"primer verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
