# Sparkitecture control flow — practice evidence

**Observed result: PASS within the tested practice scope.**

Jason: idea, concept and direction. Ember / AI collaborators: development, implementation and execution. The deterministic bot executes assigned scripts.

| Evidence group | Result |
|---|---|
| Docker behavior trials | 23 matched expected outcomes: 8 successful, 15 safely refused/stopped |
| Capability composition checks | 264 matched policy; 7 local combinations admitted |
| Deliberately corrupted evidence copies | 3 of 3 discrepancies detected |
| Watched flows | Normal and two-gate-held inspect + append runs passed |
| Legacy regression | Passed after correcting the host test expectation; original false alarm retained |

## Four capabilities and allowed mixing

Inspect, copy, compare, append. Each may run alone. Inspect may precede exactly one of the other three. Other mixtures, including upload/delete authority, are rejected. Append preserves the original prefix, binds the target hash, and permits at most 4096 assigned bytes.

## Watched behavior and receipts

### Normal flow

Run: `20261007-112223-cap-watched-normal-41091e`

Recorded bot interval: **33.185 ms**. Function call/return records: **128**.

Orientation → profile check → plan/hash validation → gate → inspect → gate → append → receipt → completion.

Final journal:

```text
Practice journal
Original entry preserved.
Observed append: assigned effect only.
```

Evidence SHA-256:

| Recorded file | Digest |
|---|---|
| `output/journal.txt` | `253ecc3371856d92949609d9a5182706811a8a1ef8d0f38626a96781e7fed555` |
| `output/receipt.json` | `d0385e09a54590ca6f5902220bdcf8a8fb6e9505e611d24c88709b0827f4d079` |
| `evidence/bot.jsonl` | `e41fce0c260de132e069d25eeccc852a2f3d69773ff47c1a40ed7508080945f9` |
| `evidence/bot-stderr.txt` | `bedb3374f795f98292b062fb527220dda9bef38cec478ce14c274a25e10fd7d3` |
| `evidence/environment-events.jsonl` | `1f65fb605974354b8b86f7db836001dbde3fe7506667ac34ad289daae7f3672a` |
| `evidence/live-observation.jsonl` | `d88bba75b31dc26ff4941b135f7b6a25c87afe4a801724f654fcb43e747945b9` |

### Paused at configured gates

Run: `20261007-112231-cap-watched-held-3281b5`

Recorded bot interval: **449.322 ms**. Function call/return records: **174**.

Orientation → profile check → plan/hash validation → gate → inspect → gate → append → receipt → completion.

| Held point | Completed actions | Journal state |
|---|---:|---|
| First gate | 0 | Original 43 bytes |
| Second gate | 1 (inspect) | Same 43 bytes and SHA-256 |

Final journal:

```text
Practice journal
Original entry preserved.
Observed append: assigned effect only.
```

Evidence SHA-256:

| Recorded file | Digest |
|---|---|
| `output/journal.txt` | `253ecc3371856d92949609d9a5182706811a8a1ef8d0f38626a96781e7fed555` |
| `output/receipt.json` | `6ca9b2a56b5b5529952a9c032f104c2c3c04abb92bab9557f3e7f159bc9ba133` |
| `evidence/bot.jsonl` | `e1a0ba125135e4ef3b5d2a75814885289fe450b586699aab45f3b156b9309f50` |
| `evidence/bot-stderr.txt` | `081861d97ffcefbd08f8bdf19692800f518c3c05856c7f2a579f2ad533d77e92` |
| `evidence/environment-events.jsonl` | `77aaae2054260bfb796b01156c5606e7295009952d98a28958bbbe9b540b0bd2` |
| `evidence/live-observation.jsonl` | `6623e5e59741624dd225b806709cb824697454555f4d2376c62c01a828e684e2` |

## Findings for the next design

1. The 33 ms normal sample is too fast for visual human intervention. This is an instrumented sample, not a performance benchmark.
2. Paused gates expose a stable intervention opportunity. The host recorded state before each resume.
3. Preflight performs file reads before task action events. Log phases distinctly; an absent action event does not imply absent environment activity.
4. Repeated gate names need an occurrence/action identity to address a future visit unambiguously.
5. Declare expected outcomes explicitly. The legacy false alarm came from inferring the expectation from the exercise label.

## Scope and attribution of evidence

Ember assembled this summary from retained run evidence; the bot publishes it in a separate upload-only assignment. Function traces are worker-generated; filesystem observation comes from the separate inotify collector. Inotify covers immediate practice input/output entries and supplies no actor PID. Host observation also reads outputs, so those reads must not be attributed automatically to the worker. The writable output mount is not an OS append-only boundary. This exercise does not establish general AI emergence safety, malicious-host resistance, or atomic rollback.
