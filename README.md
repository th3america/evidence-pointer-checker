# Evidence Pointer Checker v1

This reusable standard-library Python component checks whether one local JSON evidence pointer agrees with supplied expectations. **A VERIFIED pointer never establishes the truth of its claim.**

The original scaffold was selected by Greyfoot; Ember implemented and hardened the component under Jason Moore's direction. Collaborative publication and licensing remain explicit release decisions.

## Python API

```python
from checker import check_pointer, ValidationError

request = {
    "claim": "Synthetic fixture demonstrates a pointer contract only",
    "path": "fixture.json",
    "expected_sha256": "f472a12eb21e201e42dc6242abb1ab307ed6c97cff6e4916fda9577bfd6a5dac",
    "locator": "/checks/summary",
    "expected_value": "Synthetic example only",
}
receipt = check_pointer(request, base_directory="examples")
```

The five fields in [pointer.schema.json](pointer.schema.json) are required; additional fields are rejected. Invalid requests raise `ValidationError`, a `ValueError` subclass, before evidence reading. `base_directory` is required; relative evidence paths use that directory. Use `load_request(path)` when loading external request JSON: it rejects duplicate keys, nonfinite numbers and ambiguous parsing. Do not silently parse those inputs with a permissive JSON decoder first.

Every returned receipt contains `protocol: "EvidencePointer/1"`, `status`, the preserved `claim`, absolute `path`, `locator`, expected and actual SHA-256, `hash_matches`, `locator_resolved`, `expected_value`, `value_matches`, `reason`, `message`, `observation` and `limitations`. `observed_value` is present only when a locator resolves. Unperformed comparisons are `null`. `scope` always equals `pointer_agreement_only`, and `claim_truth_verified` is always `false`, even when source content or a claim says otherwise.

| Status | Meaning |
|---|---|
| VERIFIED | Read bytes, SHA-256, locator and expected JSON value agree. Claim truth and authority remain unassessed. |
| MISMATCH | Readable bytes disagree with the hash/value, the locator cannot resolve, or source JSON cannot be interpreted safely. |
| MISSING | The local filesystem explicitly reports file not found before the observation. |
| UNAVAILABLE | Access denied, unsupported file type/reparse path, size limit, I/O failure, or detected mutation prevents a usable observation. |

`reason` distinguishes these cases, including `pointer_agreement`, `hash_mismatch`, `value_mismatch`, `locator_unresolved`, `invalid_source_json`, `file_not_found`, `access_denied`, `io_error`, `unsupported_file_type`, `unsupported_reparse_path`, `unsupported_path_component`, `file_too_large`, `source_changed` and `incomplete_read`.

## CLI

```text
python checker.py examples/valid.json
python checker.py examples/mismatch.json --output new-receipt.json
python -m unittest discover -s tests -v
```

The CLI resolves relative source paths against the request file's directory. It writes a JSON receipt to stdout and optionally a new UTF-8 receipt file; `--output` refuses to overwrite an existing file. Exit `0` means VERIFIED, `1` means an evidence status other than VERIFIED, and `2` means a validation or output error. Errors are JSON on stderr and do not fabricate an evidence status. The checker reads but never modifies the source or request file.

## Read and comparison boundaries

- One source-content read, bounded to 10 MiB. Known oversized files and nonregular files are rejected before content reading. SHA-256 and JSON value comparison use the same captured bytes.
- Regular local files only. URI schemes, UNC/device paths, mapped Windows network drives, Windows drive-relative paths and alternate data streams are rejected. Detected symlinks and reparse points in the file or its ancestors are unavailable. No network API, source execution, dispatch, retrieval, vault editing or automatic follow-up is provided.
- Path and open-handle identity/size/times are checked before and after reading. On Windows the read handle also denies new write/delete access while open. Legacy Windows `lstat`/`fstat` ctime differences are compared within their own observation type. These are mutation checks, not an atomic snapshot guarantee: undetectable races, hostile metadata restoration, memory-mapped changes and changes after the observation remain possible.
- UTF-8 JSON only. Duplicate object keys, nonfinite/overflowing numbers, invalid encoding and malformed JSON are rejected. Fractional numbers must preserve their decimal value through the runtime's float/string round trip; otherwise comparison is refused, rather than treating precision loss as agreement. JSON integer values remain exact within Python's supported parsing limits. Extreme nesting/number lengths may be rejected by runtime limits.
- RFC 6901 escapes are decoded in the correct order (`~1`, then `~0`), with no Unicode normalization or URI-fragment interpretation. Empty pointer selects the whole document. Array tokens must be canonical ASCII nonnegative indices; `-`, leading zeros and out-of-range indices do not resolve. Numeric-looking object keys remain literal strings.
- JSON objects compare without key-order significance; arrays retain order. Booleans and numbers differ at every nesting depth. JSON has one number type, so `1` and `1.0` agree. Source text and arbitrary claim text are data only.

## Verification

[Runtime tests](tests/test_checker.py) cover the four statuses, frozen synthetic examples, spoofed truth claims, strict request validation, nested boolean/number distinctions, Unicode/escaped keys, root/array pointers, access denial, reparse rejection, exact/oversized limits, one-read binding, metadata mutation, disappearance after reading, parser ambiguity and CLI exit/overwrite behavior. Access denial and mutation are injected deterministically; the Windows writer-denial check uses a real local file and OS handle.

The symlink-ancestor test skips when the executing account lacks symlink-creation privilege. A passing simulated reparse check must not be presented as a live junction/symlink test. Run the suite on the publication target rather than relying on a machine-specific retained log.

The examples remain synthetic fixtures, not real-world evidence. This component does not authenticate an actor, prove freshness, evaluate the Reality Verification Validation Chain, or grant permission to act.
