from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "calibrate_profile.py"


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load calibrate_profile.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PseudonymisationTests(unittest.TestCase):
    def test_default_key_is_random_and_not_serialised(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CODEPROBE_PSEUDONYM_KEY_HEX", None)
            first = load_module("calibrate_profile_pseudonym_random_first")
            second = load_module("calibrate_profile_pseudonym_random_second")
        raw = "students/low-entropy-name/project.py"
        self.assertNotEqual(
            first._pseudonymous_identifier(raw),
            second._pseudonymous_identifier(raw),
        )
        metadata = first.pseudonymisation_metadata()
        rendered = json.dumps(metadata, sort_keys=True)
        self.assertNotIn(first._PSEUDONYM_KEY.hex(), rendered)
        self.assertEqual(metadata["algorithm"], "HMAC-SHA-256")
        self.assertEqual(metadata["key_scope"], "process-private")

    def test_private_key_can_reproduce_one_controlled_run(self) -> None:
        key = "11" * 32
        with mock.patch.dict(
            os.environ,
            {"CODEPROBE_PSEUDONYM_KEY_HEX": key},
            clear=False,
        ):
            first = load_module("calibrate_profile_pseudonym_keyed_first")
            second = load_module("calibrate_profile_pseudonym_keyed_second")
        raw = "student-0001"
        expected = hmac.new(bytes.fromhex(key), raw.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        self.assertEqual(first._pseudonymous_identifier(raw), expected)
        self.assertEqual(second._pseudonymous_identifier(raw), expected)
        self.assertEqual(first.pseudonymisation_metadata()["key_source"], "environment-private")

    def test_invalid_private_key_fails_closed(self) -> None:
        for invalid in ("", "abcd", "zz" * 32, "00" * 31):
            with self.subTest(invalid=invalid), mock.patch.dict(
                os.environ,
                {"CODEPROBE_PSEUDONYM_KEY_HEX": invalid},
                clear=False,
            ):
                with self.assertRaises(ValueError):
                    load_module(f"calibrate_profile_bad_key_{len(invalid)}_{invalid[:2]}")

    def test_tokens_are_not_public_unsalted_hashes(self) -> None:
        key = "a5" * 32
        raw = "known-course/student42/submission"
        with mock.patch.dict(
            os.environ,
            {"CODEPROBE_PSEUDONYM_KEY_HEX": key},
            clear=False,
        ):
            module = load_module("calibrate_profile_pseudonym_not_unsalted")
        token = module._pseudonymous_identifier(raw)
        self.assertNotEqual(token, hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24])
        self.assertRegex(token, r"^[0-9a-f]{24}$")
        self.assertRegex(module._group_token(raw), r"^[0-9a-f]{16}$")

    def test_domain_separation_prevents_sample_group_equivalence(self) -> None:
        key = "5a" * 32
        with mock.patch.dict(
            os.environ,
            {"CODEPROBE_PSEUDONYM_KEY_HEX": key},
            clear=False,
        ):
            module = load_module("calibrate_profile_pseudonym_domains")
        raw = "same-source"
        self.assertNotEqual(
            module._pseudonymous_identifier(raw)[:16],
            module._group_token(raw),
        )


if __name__ == "__main__":
    unittest.main()
