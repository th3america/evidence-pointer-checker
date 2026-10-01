# Porting Evidence Pointer Checker

This component is intentionally standard-library Python. Port the evidence
contract and filesystem semantics, not only the function names.

## Preserve these invariants

- `VERIFIED` means pointer agreement only; it never verifies claim truth or
  authority.
- Request validation completes before the evidence file is opened.
- Hash and value comparison use the same single bounded content read.
- Unsupported, ambiguous, nonregular, reparse, oversized, denied, or mutated
  sources do not become successful observations.
- The checker never modifies the request or evidence source.
- Exit codes and receipt fields keep their documented meaning.

## Replaceable adapters

| Adapter | Current implementation | Target contract |
|---|---|---|
| Local file open | Python `os.open` plus platform flags | Regular local file, no link following, bounded single read, best available writer/mutation resistance |
| Path classification | Python/OS path rules | Reject URI, network, device, drive-relative, ADS, and traversed reparse forms appropriate to the target |
| JSON parser | strict Python JSON hooks | UTF-8, no duplicate keys/nonfinite values, preserved comparison semantics |
| CLI wrapper | `argparse` | Preserve stdout/stderr JSON separation and exit codes 0/1/2 |
| Receipt transport | JSON object/file | Preserve protocol, scope, limitations, and null for unperformed comparisons |

If a target cannot enforce a Windows sharing denial or a POSIX no-follow
operation, report the weaker guarantee explicitly. Do not delete the mutation
limitation from the receipt.

## Target conversion

1. Record OS, filesystem type, Python/runtime version, link privileges, and
   container or network-mount behavior.
2. Run the complete suite before editing and record skips.
3. Implement target filesystem operations behind the existing private helper
   boundary or an equivalent narrow adapter.
4. Add target-specific negative tests for symlinks/reparse points, denied
   access, nonregular files, concurrent mutation, and path ambiguity.
5. Run with the synthetic examples in a fresh checkout.
6. Write a `PortableScaffoldConversion/1` receipt. A skipped security test is
   unresolved, not passed.

## Verification matrix

```text
python -m unittest discover -s tests -v
python checker.py examples/valid.json
python checker.py examples/mismatch.json
```

The valid example must exit `0` with `scope` equal to
`pointer_agreement_only`. The mismatch example must exit `1`. Cross-platform CI
records platform-specific skips; review them before declaring a target verified.

## Embedding in another AI system

Call `check_pointer` as a defensive observation tool. Keep its receipt separate
from the AI's interpretation and from permission to act. Never convert
`status == "VERIFIED"` into an unconditional truth or action gate.
