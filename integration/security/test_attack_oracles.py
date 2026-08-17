#!/usr/bin/env python3
"""Unit tests for the PBNS RQ3 adversarial attack matrix oracles and schema."""

import json
import pathlib
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
ATTACK_CASES_FILE = ROOT_DIR / "integration" / "security" / "attack_cases.json"

REQUIRED_FIELDS = {
    "id",
    "category",
    "target",
    "description",
    "threat",
    "expectedOutcome",
    "expectedErrorCode",
    "executionPrevented",
    "stateModified",
}

VALID_CATEGORIES = {"Framing", "TLS", "Trusted Time", "Recovery", "Attestation"}


class AttackOraclesTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(ATTACK_CASES_FILE.exists(), f"Missing {ATTACK_CASES_FILE}")
        with open(ATTACK_CASES_FILE, "r", encoding="utf-8") as file:
            self.data = json.load(file)

    def test_schema_and_version(self):
        self.assertEqual(self.data.get("schemaVersion"), 1)
        self.assertEqual(self.data.get("suite"), "PBNS-RQ3-Adversarial-Matrix")
        self.assertIsInstance(self.data.get("cases"), list)
        self.assertGreaterEqual(len(self.data["cases"]), 15)

    def test_case_structure_and_unique_ids(self):
        seen_ids = set()
        for entry in self.data["cases"]:
            for field in REQUIRED_FIELDS:
                self.assertIn(field, entry, f"Case {entry.get('id')} missing {field}")

            case_id = entry["id"]
            self.assertNotIn(case_id, seen_ids, f"Duplicate case ID: {case_id}")
            seen_ids.add(case_id)

            self.assertIn(entry["category"], VALID_CATEGORIES)
            self.assertEqual(entry["expectedOutcome"], "REJECT_FAIL_CLOSED")
            self.assertTrue(entry["executionPrevented"], f"Execution not prevented in {case_id}")
            self.assertFalse(entry["stateModified"], f"State modified in {case_id}")
            self.assertTrue(len(entry["expectedErrorCode"]) > 0)


if __name__ == "__main__":
    unittest.main()
