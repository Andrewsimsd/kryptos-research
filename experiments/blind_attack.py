#!/usr/bin/env python3
"""Crib-only exact reference attack for BLIND-0001; no controller import."""

import argparse
import json
from pathlib import Path
import sys
import time

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ROUTES = ("identity", "reverse")
EQUATIONS = ("add", "reflect")


def canonical_id(route, equation, key):
    """Identify a transform after reducing repeated key cycles."""
    if len(key) == 2 and key[0] == key[1]:
        key = key[:1]
    return f"{route}:{equation}:{len(key)}:{key}"


def route_index(index, length, route):
    return index if route == "identity" else length - 1 - index


def encrypt(plaintext, route, equation, key):
    """Encrypt with canonical add or reflect equation and output route."""
    output = [None] * len(plaintext)
    for index, letter in enumerate(plaintext):
        p = ord(letter) - 65
        k = ord(key[index % len(key)]) - 65
        c = (p + k if equation == "add" else k - p) % 26
        output[route_index(index, len(plaintext), route)] = ALPHABET[c]
    return "".join(output)


def validate_case(case):
    ciphertext = case["ciphertext"]
    clues = case["clues"]
    budget = case["budget"]
    if not isinstance(ciphertext, str) or any(c not in ALPHABET for c in ciphertext):
        raise ValueError("ciphertext must contain uppercase ASCII A-Z only")
    if not isinstance(clues, list):
        raise ValueError("clues must be a list")
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 0:
        raise ValueError("budget must be a nonnegative integer")
    seen = {}
    for clue in clues:
        if not isinstance(clue, dict) or set(clue) != {"position", "letter"}:
            raise ValueError("each clue needs position and letter")
        i, letter = clue["position"], clue["letter"]
        if not isinstance(i, int) or isinstance(i, bool) or i < 0 or i >= len(ciphertext):
            raise ValueError("clue position outside ciphertext")
        if not isinstance(letter, str) or len(letter) != 1 or letter not in ALPHABET:
            raise ValueError("clue letter must be uppercase ASCII A-Z")
        if i in seen and seen[i] != letter:
            raise ValueError("contradictory duplicate clue")
        seen[i] = letter
    return ciphertext, sorted(seen.items()), budget


def attack(case):
    """Return complete ranked survivors or an explicitly unknown partial run."""
    ciphertext, clues, budget = validate_case(case)
    start = time.monotonic()
    survivors = []
    checks = 0
    unresolved = False
    seen_ids = set()
    for route in ROUTES:
        for equation in EQUATIONS:
            for period in (1, 2):
                if checks >= budget:
                    return {"id": case["id"], "status": "unknown", "checks": checks,
                            "survivors": survivors, "elapsed_seconds": time.monotonic() - start}
                checks += 1
                key = [None] * period
                valid = True
                for i, p_letter in clues:
                    p = ord(p_letter) - 65
                    c = ord(ciphertext[route_index(i, len(ciphertext), route)]) - 65
                    needed = (c - p if equation == "add" else c + p) % 26
                    residue = i % period
                    if key[residue] is not None and key[residue] != needed:
                        valid = False
                        break
                    key[residue] = needed
                if not valid:
                    continue
                if any(value is None for value in key):
                    unresolved = True
                    continue
                key_text = "".join(ALPHABET[value] for value in key)
                model_id = canonical_id(route, equation, key_text)
                if model_id in seen_ids:
                    continue
                seen_ids.add(model_id)
                plaintext = [None] * len(ciphertext)
                for i in range(len(ciphertext)):
                    c = ord(ciphertext[route_index(i, len(ciphertext), route)]) - 65
                    k = key[i % period]
                    plaintext[i] = ALPHABET[(c - k if equation == "add" else k - c) % 26]
                plaintext = "".join(plaintext)
                if encrypt(plaintext, route, equation, key_text) != ciphertext:
                    raise AssertionError("reencryption mismatch")
                survivors.append({"model_id": model_id, "plaintext": plaintext})
    return {"id": case["id"], "status": "unknown" if unresolved else "complete",
            "checks": checks, "survivors": survivors, "elapsed_seconds": time.monotonic() - start}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_cases", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.public_cases.open(encoding="utf-8") as source, args.output.open("x", encoding="utf-8") as output:
            for line in source:
                if line.strip():
                    output.write(json.dumps(attack(json.loads(line)), allow_nan=False) + "\n")
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"blind attack failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
