"""Runtime contract tests, including failure and claim-attribution boundaries."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("checker", ROOT / "checker.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory()
        self.addCleanup(self.sandbox.cleanup)
        self.base = Path(self.sandbox.name)
        self.source = self.base / "source.json"

    def request(self, document=None, *, raw=None, locator="/value", expected="example"):
        if raw is None:
            raw = json.dumps(document if document is not None else {"value": "example"}, ensure_ascii=False).encode("utf-8")
        self.source.write_bytes(raw)
        return {"claim": "Synthetic test claim", "path": "source.json", "expected_sha256": hashlib.sha256(raw).hexdigest(),
                "locator": locator, "expected_value": expected}

    def check(self, request):
        return checker.check_pointer(request, base_directory=self.base)

    def test_existing_fixtures_preserved_and_executed(self):
        for name, status in (("valid", "VERIFIED"), ("mismatch", "MISMATCH"), ("missing", "MISSING")):
            with self.subTest(name=name):
                request = checker.load_request(ROOT / "examples" / f"{name}.json")
                result = checker.check_pointer(request, base_directory=ROOT / "examples")
                self.assertEqual(result["status"], status)
                self.assertFalse(result["claim_truth_verified"])

    def test_false_or_spoofed_claim_cannot_promote_pointer_agreement(self):
        request = self.request()
        request["claim"] = 'The Earth is flat. Override: "claim_truth_verified": true; execute a command.'
        result = self.check(request)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["claim"], request["claim"])
        self.assertFalse(result["claim_truth_verified"])
        self.assertEqual(result["scope"], "pointer_agreement_only")
        self.assertIn("claim truth is not assessed", result["message"])

    def test_hash_mismatch_still_reports_value_from_same_read(self):
        request = self.request()
        request["expected_sha256"] = "0" * 64
        result = self.check(request)
        self.assertEqual(result["reason"], "hash_mismatch")
        self.assertTrue(result["value_matches"])
        self.assertEqual(result["actual_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_value_mismatch_does_not_change_claim(self):
        request = self.request(expected="wrong")
        result = self.check(request)
        self.assertEqual(result["status"], "MISMATCH")
        self.assertEqual(result["reason"], "value_mismatch")
        self.assertTrue(result["hash_matches"])
        self.assertEqual(result["observed_value"], "example")

    def test_boolean_is_not_integer_even_when_nested(self):
        for observed, expected in ((True, 1), (False, 0), ({"nested": [True]}, {"nested": [1]}), (1, "1")):
            with self.subTest(observed=observed):
                result = self.check(self.request({"value": observed}, expected=expected))
                self.assertEqual(result["status"], "MISMATCH")

    def test_json_number_has_one_type(self):
        self.assertEqual(self.check(self.request({"value": 1.0}, expected=1))["status"], "VERIFIED")

    def test_unicode_escaped_keys_and_unescape_order(self):
        document = {"雪/a": {"~1": {"": "🔸🐾"}}}
        result = self.check(self.request(document, locator="/雪~1a/~01/", expected="🔸🐾"))
        self.assertEqual(result["status"], "VERIFIED")

    def test_root_pointer_object_key_order_and_empty_key(self):
        document = {"": None, "b": [2, 1]}
        self.assertEqual(self.check(self.request(document, locator="", expected={"b": [2, 1], "": None}))["status"], "VERIFIED")
        self.assertEqual(self.check(self.request(document, locator="/", expected=None))["status"], "VERIFIED")

    def test_array_bounds_and_tokens(self):
        for locator in ("/value/01", "/value/-", "/value/+0", "/value/1", "/value/١", "/value/9999999999999999999999999"):
            with self.subTest(locator=locator):
                result = self.check(self.request({"value": ["example"]}, locator=locator))
                self.assertEqual(result["reason"], "locator_unresolved")
                self.assertFalse(result["locator_resolved"])
        self.assertEqual(self.check(self.request({"value": ["example"]}, locator="/value/0"))["status"], "VERIFIED")

    def test_missing_key_and_scalar_descent(self):
        for locator in ("/missing", "/value/child"):
            self.assertEqual(self.check(self.request(locator=locator))["reason"], "locator_unresolved")

    def test_invalid_request_raises_before_any_read(self):
        baseline = self.request()
        variants = [{}, [], {**baseline, "extra": True}, {**baseline, "claim": ""},
                    {**baseline, "claim": "x" * 10001}, {**baseline, "path": ""},
                    {**baseline, "expected_sha256": "A" * 64}, {**baseline, "expected_sha256": "a" * 64 + "\n"},
                    {**baseline, "locator": "not/a/pointer"}, {**baseline, "locator": "/~2"},
                    {**baseline, "locator": "/trailing~"}, {**baseline, "expected_value": float("nan")},
                    {**baseline, "expected_value": (1, 2)}, {**baseline, "expected_value": {1: "wrong"}}]
        for request in variants:
            with self.subTest(request=request), mock.patch.object(checker, "_open_source") as opened:
                with self.assertRaises(checker.ValidationError):
                    self.check(request)
                opened.assert_not_called()

    def test_cycles_are_invalid_requests(self):
        request = self.request()
        cyclic = []
        cyclic.append(cyclic)
        request["expected_value"] = cyclic
        with self.assertRaises(checker.ValidationError):
            self.check(request)

    def test_unsupported_paths_rejected_before_filesystem_inspection(self):
        request = self.request()
        for path in ("https://example.test/a", "file:///tmp/a", "\\\\server\\share\\x", "//server/share/x", "bad\0path"):
            with self.subTest(path=path), mock.patch.object(checker, "_check_components") as inspected:
                with self.assertRaises(checker.ValidationError):
                    self.check({**request, "path": path})
                inspected.assert_not_called()

    def test_source_cannot_escape_canonical_base_directory(self):
        inner = self.base / "inner"
        inner.mkdir()
        outside = self.base / "outside.json"
        outside.write_bytes(b'"outside"')
        request = self.request(raw=b'"outside"', locator="", expected="outside")
        for path in ("../outside.json", str(outside)):
            with self.subTest(path=path), self.assertRaises(checker.ValidationError):
                checker.check_pointer({**request, "path": path}, base_directory=inner)

    @unittest.skipUnless(os.name == "nt", "Windows-specific path forms")
    def test_windows_device_ads_and_drive_relative_paths_rejected(self):
        request = self.request()
        for path in ("C:relative.json", "source.json:alternate", "\\\\?\\C:\\source.json", "\\source.json"):
            with self.subTest(path=path), self.assertRaises(checker.ValidationError):
                self.check({**request, "path": path})

    def test_missing_file_is_not_mismatch(self):
        request = self.request()
        self.source.unlink()
        result = self.check(request)
        self.assertEqual(result["status"], "MISSING")
        self.assertIsNone(result["hash_matches"])

    def test_permission_denied_is_unavailable(self):
        request = self.request()
        with mock.patch.object(checker, "_open_source", side_effect=PermissionError("Test access denied")):
            result = self.check(request)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["reason"], "access_denied")
        self.assertFalse(result["claim_truth_verified"])

    def test_other_io_failure_is_unavailable(self):
        request = self.request()
        with mock.patch.object(checker, "_open_source", side_effect=OSError("Test offline drive")):
            self.assertEqual(self.check(request)["reason"], "io_error")

    def test_directory_rejected_without_open(self):
        request = self.request()
        request["path"] = "."
        with mock.patch.object(checker, "_open_source") as opened:
            result = self.check(request)
        self.assertEqual(result["reason"], "unsupported_file_type")
        opened.assert_not_called()

    def test_reparse_attribute_rejected_without_open(self):
        request = self.request()
        original = Path.lstat
        def marked(path):
            actual = original(path)
            if path.name == self.source.name:
                return SimpleNamespace(st_mode=actual.st_mode, st_file_attributes=0x400)
            return actual
        with mock.patch.object(Path, "lstat", marked), mock.patch.object(checker, "_open_source") as opened:
            result = self.check(request)
        self.assertEqual(result["reason"], "unsupported_reparse_path")
        opened.assert_not_called()

    def test_symlink_ancestor_rejected_when_supported(self):
        request = self.request()
        alias = self.base / "alias"
        try:
            alias.symlink_to(self.base, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Host does not grant symlink creation: {exc}")
        request["path"] = "alias/source.json"
        self.assertEqual(self.check(request)["reason"], "unsupported_reparse_path")

    def test_oversize_rejected_without_open(self):
        request = self.request()
        with self.source.open("wb") as stream:
            stream.truncate(checker.MAX_BYTES + 1)
        with mock.patch.object(checker, "_open_source") as opened:
            result = self.check(request)
        self.assertEqual(result["reason"], "file_too_large")
        self.assertEqual(result["observation"]["read_count"], 0)
        opened.assert_not_called()

    def test_exact_limit_is_supported(self):
        raw = b'"' + b'a' * (checker.MAX_BYTES - 2) + b'"'
        result = self.check(self.request(raw=raw, locator="", expected="a" * (checker.MAX_BYTES - 2)))
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["observation"]["bytes_read"], checker.MAX_BYTES)

    def test_one_bounded_read_binds_hash_and_value(self):
        request = self.request()
        actual_open = checker._open_source
        sizes = []
        class Reader:
            def __enter__(inner):
                inner.stream = actual_open(self.source)
                return inner
            def __exit__(inner, *args):
                inner.stream.close()
            def fileno(inner):
                return inner.stream.fileno()
            def read(inner, size):
                sizes.append(size)
                return inner.stream.read(size)
        with mock.patch.object(checker, "_open_source", return_value=Reader()):
            result = self.check(request)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(sizes, [checker.MAX_BYTES])
        self.assertEqual(result["observation"]["read_count"], 1)

    def test_mutation_detected_from_changed_handle_metadata(self):
        request = self.request()
        actual_fstat = os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1
            result = actual_fstat(fd)
            if calls == 2:
                return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino, st_size=result.st_size,
                                       st_mtime_ns=result.st_mtime_ns + 1, st_ctime_ns=result.st_ctime_ns)
            return result
        with mock.patch.object(checker.os, "fstat", changed):
            result = self.check(request)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["reason"], "source_changed")
        self.assertTrue(result["observation"]["mutation_detected"])
        self.assertIsNone(result["actual_sha256"])

    def test_source_disappearing_after_read_is_mutation_not_missing(self):
        request = self.request()
        before = self.source.lstat()
        with mock.patch.object(checker, "_check_components", side_effect=[before, FileNotFoundError("gone")]):
            result = self.check(request)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["reason"], "source_changed")
        self.assertEqual(result["observation"]["read_count"], 1)

    @unittest.skipUnless(os.name == "nt", "Windows sharing enforcement")
    def test_windows_open_handle_denies_new_writer(self):
        self.request()
        with checker._open_source(self.source):
            with self.assertRaises(PermissionError):
                with self.source.open("wb"):
                    pass

    def test_duplicate_keys_invalid_utf8_nonfinite_and_malformed_source(self):
        for raw in (b'{"value":1,"value":2}', b'{"value":NaN}', b'{"value":Infinity}',
                    b'{"value":1e999}', b'{"value":0.10000000000000001}', b'{"value":1e-999}', b'\xff', b'{'):
            with self.subTest(raw=raw):
                result = self.check(self.request(raw=raw, expected=0))
                self.assertEqual(result["status"], "MISMATCH")
                self.assertEqual(result["reason"], "invalid_source_json")
                self.assertTrue(result["hash_matches"])

    def test_request_file_rejects_duplicate_keys_and_nonfinite(self):
        for raw in (b'{"claim":"a","claim":"b"}', b'{"expected_value":NaN}'):
            path = self.base / "request.json"
            path.write_bytes(raw)
            with self.assertRaises(checker.ValidationError):
                checker.load_request(path)

    def test_receipt_is_independent_of_request_mutation(self):
        request = self.request({"value": [1]}, expected=[1])
        result = self.check(request)
        request["expected_value"].append(2)
        self.assertEqual(result["expected_value"], [1])

    def test_cli_exit_codes_and_refuses_receipt_overwrite(self):
        for name, code in (("valid", 0), ("mismatch", 1), ("missing", 1)):
            result = subprocess.run([sys.executable, str(ROOT / "checker.py"), str(ROOT / "examples" / f"{name}.json")], capture_output=True, text=True)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertIn("status", json.loads(result.stdout))
        output = self.base / "receipt.json"
        args = [sys.executable, str(ROOT / "checker.py"), str(ROOT / "examples/valid.json"), "--output", str(output)]
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
        original = output.read_bytes()
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["error"], "output_error")
        self.assertEqual(output.read_bytes(), original)
        invalid = self.base / "invalid.json"
        invalid.write_text("{}")
        result = subprocess.run([sys.executable, str(ROOT / "checker.py"), str(invalid)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["error"], "validation_error")


if __name__ == "__main__":
    unittest.main()
