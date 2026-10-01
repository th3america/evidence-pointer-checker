"""Check one local JSON evidence pointer. A match never establishes claim truth.

Public API: check_pointer(request, *, base_directory) -> JSON-compatible receipt.
Invalid requests raise ValidationError. Standard library only.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 10 * 1024 * 1024
PROTOCOL = "EvidencePointer/1"
FIELDS = {"claim", "path", "expected_sha256", "locator", "expected_value"}
LIMITATIONS = [
    "VERIFIED means agreement with the supplied hash, JSON locator and value only; claim truth and authority are not assessed.",
    "Hash and value use one bounded read of the same bytes. Metadata checks detect some mutations, not all races or later changes.",
    "Observation timestamps do not establish source freshness, authenticity, completeness or permission to act.",
]


class ValidationError(ValueError):
    """The request is invalid; no evidence judgment has been made."""


class _InspectionError(Exception):
    def __init__(self, reason, message, observation=None):
        super().__init__(message)
        self.reason = reason
        self.observation = observation or {}


class _SourceJsonError(ValueError):
    pass


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _validate_json_value(value, ancestors=None):
    """Do not accept Python-only types, cycles, or nonfinite numbers."""
    ancestors = set() if ancestors is None else ancestors
    kind = type(value)
    if value is None or kind in (str, bool, int):
        return
    if kind is float:
        if not math.isfinite(value):
            raise ValidationError("JSON numbers must be finite")
        return
    if kind not in (list, dict):
        raise ValidationError("expected_value must contain only JSON types")
    if id(value) in ancestors:
        raise ValidationError("JSON values cannot contain cycles")
    ancestors.add(id(value))
    try:
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise ValidationError("JSON object keys must be strings")
            children = value.values()
        else:
            children = value
        for child in children:
            _validate_json_value(child, ancestors)
    finally:
        ancestors.remove(id(value))


def validate_request(request):
    """Implement pointer.schema.json's small contract without dependencies."""
    if type(request) is not dict:
        raise ValidationError("Request must be a JSON object")
    if set(request) != FIELDS:
        missing = sorted(FIELDS - set(request))
        extra = sorted(str(key) for key in set(request) - FIELDS)
        raise ValidationError(f"Request fields differ from contract; missing={missing}, extra={extra}")
    for name, maximum in (("claim", 10000), ("path", 32767)):
        if type(request[name]) is not str or not 1 <= len(request[name]) <= maximum:
            raise ValidationError(f"{name} must be a string of 1..{maximum} characters")
    if type(request["expected_sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", request["expected_sha256"]):
        raise ValidationError("expected_sha256 must be 64 lowercase hexadecimal characters")
    locator = request["locator"]
    if type(locator) is not str or not re.fullmatch(r"(?:/(?:[^~/]|~[01])*)*", locator):
        raise ValidationError("locator must be an RFC 6901 JSON Pointer; only ~0 and ~1 escapes are valid")
    try:
        _validate_json_value(request["expected_value"])
    except RecursionError as exc:
        raise ValidationError("expected_value exceeds the supported JSON nesting depth") from exc
    _validate_local_path_syntax(request["path"])


def _validate_local_path_syntax(path):
    if "\x00" in path:
        raise ValidationError("path cannot contain NUL")
    if path.startswith(("\\\\", "//")):
        raise ValidationError("UNC, device and network paths are outside the local-file contract")
    drive_path = os.name == "nt" and re.match(r"^[A-Za-z]:[\\/]", path)
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", path) and not drive_path:
        raise ValidationError("URI schemes and drive-relative paths are not supported")
    if os.name == "nt" and ":" in path[2 if drive_path else 0:]:
        raise ValidationError("Alternate data streams are not supported")
    if os.name == "nt" and path.startswith(("\\", "/")):
        raise ValidationError("Root-relative Windows paths are not supported; provide a drive or a relative path")


def _local_path(path, base_directory):
    _validate_local_path_syntax(path)
    try:
        base = os.fspath(base_directory)
        _validate_local_path_syntax(base)
        boundary = Path(os.path.realpath(os.path.abspath(base)))
        candidate = path if os.path.isabs(path) else os.path.join(boundary, path)
        candidate = os.fspath(candidate)
        absolute = Path(os.path.realpath(os.path.dirname(candidate))) / os.path.basename(candidate)
        try:
            absolute.relative_to(boundary)
        except ValueError as exc:
            raise ValidationError("path must remain within base_directory") from exc
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError("base_directory must be a local filesystem path") from exc
    if os.name == "nt":
        import ctypes
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(absolute.anchor))
        if drive_type == 4:
            raise ValidationError("Mapped network drives are outside the local-file contract")
    return absolute, boundary


def _check_components(path, boundary):
    """Inspect every component from the trusted base boundary to the source."""
    components = []
    component = path
    while True:
        components.append(component)
        if component == boundary:
            break
        if component.parent == component:
            raise _InspectionError("unsupported_path_component", "Source escaped the trusted base directory")
        component = component.parent
    for component in reversed(components):
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise _InspectionError("unsupported_reparse_path", "Symbolic links and reparse paths are not inspected")
        if component != path and not stat.S_ISDIR(metadata.st_mode):
            raise _InspectionError("unsupported_path_component", "A parent path component is not a directory")
    return metadata


def _metadata(value):
    return {
        "device": value.st_dev, "inode": value.st_ino, "size": value.st_size,
        "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns,
    }


def _same_path_and_handle(path_stat, handle_stat):
    left, right = _metadata(path_stat), _metadata(handle_stat)
    # Some Windows Python versions expose creation time from lstat but change
    # time from fstat under the legacy ctime name. Compare like observations.
    if os.name == "nt":
        left.pop("ctime_ns")
        right.pop("ctime_ns")
    return left == right


def _open_source(path):
    """Open without following the final symlink; Windows also denies writers."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        create.restype = wintypes.HANDLE
        handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000 | 0x08000000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            close = kernel.CloseHandle
            close.argtypes = (wintypes.HANDLE,)
            close(handle)
            raise
    else:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    return os.fdopen(fd, "rb", buffering=0)


def _read_snapshot(path, boundary):
    before_path = _check_components(path, boundary)
    if not stat.S_ISREG(before_path.st_mode):
        raise _InspectionError("unsupported_file_type", "Only regular local files are supported")
    if before_path.st_size > MAX_BYTES:
        raise _InspectionError("file_too_large", "Source exceeds the 10 MiB limit; no content was read")
    observation = {"read_count": 0, "bytes_read": 0, "metadata_before": _metadata(before_path)}
    with _open_source(path) as stream:
        before_fd = os.fstat(stream.fileno())
        if not stat.S_ISREG(before_fd.st_mode) or getattr(before_fd, "st_file_attributes", 0) & 0x400:
            raise _InspectionError("unsupported_file_type", "Opened handle is not a regular file", observation)
        if not _same_path_and_handle(before_path, before_fd):
            observation["mutation_detected"] = True
            raise _InspectionError("source_changed", "Source changed between path inspection and opening", observation)
        observation["read_count"] = 1
        try:
            data = stream.read(MAX_BYTES)  # The only source-content read, at most 10 MiB.
            observation["bytes_read"] = len(data)
            after_fd = os.fstat(stream.fileno())
        except OSError as exc:
            raise _InspectionError("io_error", str(exc), observation) from exc
        try:
            after_path = _check_components(path, boundary)
        except (OSError, _InspectionError) as exc:
            observation["mutation_detected"] = True
            raise _InspectionError("source_changed", "Source path could not be confirmed after reading", observation) from exc
        observation["metadata_after"] = _metadata(after_path)
        observation["handle_metadata_before"] = _metadata(before_fd)
        observation["handle_metadata_after"] = _metadata(after_fd)
        observation["mutation_detected"] = not (
            _metadata(before_fd) == _metadata(after_fd)
            and _metadata(before_path) == _metadata(after_path)
            and _same_path_and_handle(after_path, after_fd)
        )
        if observation["mutation_detected"]:
            raise _InspectionError("source_changed", "Source metadata changed during the observation", observation)
        if len(data) > MAX_BYTES:
            raise _InspectionError("file_too_large", "Bounded read exceeded the 10 MiB limit", observation)
        if len(data) != after_fd.st_size:
            raise _InspectionError("incomplete_read", "The bounded read did not yield the observed file size", observation)
    return data, observation


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _SourceJsonError(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value):
    raise _SourceJsonError(f"Nonfinite JSON number: {value}")


def _parse_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise _SourceJsonError("Nonfinite or overflowing JSON number")
    if Decimal(token) != Decimal(str(value)):
        raise _SourceJsonError("JSON number exceeds supported round-trip precision; comparison refused")
    return value


def _decode_json(data):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_float=_parse_float)
        _validate_json_value(value)
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise _SourceJsonError(str(exc)) from exc


def _resolve_pointer(document, locator):
    value = document
    if locator == "":
        return value
    for encoded in locator[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if type(value) is dict:
            if token not in value:
                raise LookupError("Object key is absent")
            value = value[token]
        elif type(value) is list:
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise LookupError("Array token is not a canonical nonnegative index")
            if len(token) > len(str(len(value))) or int(token) >= len(value):
                raise LookupError("Array index is outside the array")
            value = value[int(token)]
        else:
            raise LookupError("Pointer attempts to descend into a scalar")
    return value


def _json_equal(left, right):
    """JSON has one number type, but booleans are a distinct type at every depth."""
    pending = [(left, right)]
    while pending:
        left, right = pending.pop()
        left_kind, right_kind = type(left), type(right)
        if left_kind in (int, float) and right_kind in (int, float):
            if left != right:
                return False
        elif left_kind is not right_kind:
            return False
        elif left_kind is dict:
            if left.keys() != right.keys():
                return False
            pending.extend((left[key], right[key]) for key in left)
        elif left_kind is list:
            if len(left) != len(right):
                return False
            pending.extend(zip(left, right))
        elif left != right:
            return False
    return True


def check_pointer(request, *, base_directory):
    """Return a receipt for one observation. Invalid requests raise ValidationError."""
    validate_request(request)
    try:
        request = copy.deepcopy(request)
    except RecursionError as exc:
        raise ValidationError("Request exceeds the supported JSON nesting depth") from exc
    path, boundary = _local_path(request["path"], base_directory)
    receipt = {
        "protocol": PROTOCOL, "status": "UNAVAILABLE", "scope": "pointer_agreement_only",
        "claim": request["claim"], "claim_truth_verified": False, "path": str(path),
        "locator": request["locator"], "expected_sha256": request["expected_sha256"],
        "actual_sha256": None, "hash_matches": None, "locator_resolved": None,
        "expected_value": request["expected_value"], "value_matches": None,
        "observation": {"started_utc": _utc_now(), "read_count": 0, "bytes_read": 0},
        "limitations": list(LIMITATIONS),
    }

    def finish(status, reason, message):
        receipt.update(status=status, reason=reason, message=message)
        receipt["observation"]["finished_utc"] = _utc_now()
        return receipt

    try:
        data, observation = _read_snapshot(path, boundary)
        receipt["observation"].update(observation)
    except FileNotFoundError:
        return finish("MISSING", "file_not_found", "The local filesystem explicitly reported file not found")
    except _InspectionError as exc:
        receipt["observation"].update(exc.observation)
        return finish("UNAVAILABLE", exc.reason, str(exc))
    except OSError as exc:
        return finish("UNAVAILABLE", "access_denied" if isinstance(exc, PermissionError) else "io_error", str(exc))
    receipt["actual_sha256"] = hashlib.sha256(data).hexdigest()
    receipt["hash_matches"] = receipt["actual_sha256"] == request["expected_sha256"]
    try:
        document = _decode_json(data)
    except _SourceJsonError as exc:
        return finish("MISMATCH", "invalid_source_json", str(exc))
    try:
        observed = _resolve_pointer(document, request["locator"])
    except LookupError as exc:
        receipt["locator_resolved"] = False
        return finish("MISMATCH", "locator_unresolved", str(exc))
    receipt["locator_resolved"] = True
    receipt["observed_value"] = observed
    receipt["value_matches"] = _json_equal(observed, request["expected_value"])
    if not receipt["hash_matches"]:
        return finish("MISMATCH", "hash_mismatch", "Source bytes do not match the supplied SHA-256")
    if not receipt["value_matches"]:
        return finish("MISMATCH", "value_mismatch", "Located JSON value does not match the expected JSON value")
    return finish("VERIFIED", "pointer_agreement", "Hash, locator and expected JSON value agree for the observed bytes; claim truth is not assessed")


def load_request(path):
    """Load a request strictly; duplicate keys and nonfinite values are errors."""
    requested = Path(path).absolute()
    source, boundary = _local_path(os.fspath(requested), requested.parent)
    try:
        data, _ = _read_snapshot(source, boundary)
        request = _decode_json(data)
    except (OSError, _InspectionError, _SourceJsonError) as exc:
        raise ValidationError(f"Cannot load request: {exc}") from exc
    validate_request(request)
    return request


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="JSON request; relative evidence paths use this file's directory")
    parser.add_argument("--output", type=Path, help="Write a new receipt file (refuses overwrite), as well as stdout")
    args = parser.parse_args(argv)
    try:
        receipt = check_pointer(load_request(args.request), base_directory=args.request.absolute().parent)
        rendered = json.dumps(receipt, ensure_ascii=True, allow_nan=False, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        sys.stdout.write(rendered)
    except (ValidationError, OSError) as exc:
        sys.stderr.write(json.dumps({"error": "validation_error" if isinstance(exc, ValidationError) else "output_error", "message": str(exc)}) + "\n")
        return 2
    return 0 if receipt["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
