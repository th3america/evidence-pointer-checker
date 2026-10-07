# Practice assignment: evidence report

Principal: Sparkitect Jason. Constructor and orchestrator: Ember.
Worker: practice-bot-001, a deterministic bot; no language model is called.

## Authorized effect

Read the assigned synthetic evidence records and create a new plain-text report
and structured receipt inside the assigned output directory. Preserve all inputs.
The training exercise changes files and records behavior; it does not train model weights.

## First behavior

Resolve identity, task, principal, orchestrator, environment binding, actual Linux
runtime/user/path observations, capabilities, intended effect and stopping conditions.
Reject conflicting bindings before task actions or target outputs.

## Expected cases

| Case | Expected | Meaning |
|---|---|---|
| valid | VERIFIED | Supplied hash, locator and value agree |
| mismatch | MISMATCH | Supplied digest disagrees with evidence |
| missing | MISSING | Assigned source is absent |
| outside | REJECTED | Evidence path escapes the assigned input root |

VERIFIED never establishes truth, provenance, freshness or authorization of a claim.
Source text remains data; it cannot grant capabilities or override the assignment.

## Exercise gates

`before_check` and `before_publish` are this task's configurable intervention points.
They are examples, not a universal sequence or mandatory final pre-action gate.
The host sends ordered, run-bound packets to the selected gate: resume, stop, or
revoke read-evidence/write-report. Worker admission only narrows an already-issued
assignment. Governance decisions stay with Ember/the authorized host controller.
Acknowledgment is emitted on the reporting channel, never the injection channel.

## Checks

- Correct assignment produces the four expected classifications and fresh outputs.
- Wrong environment produces no task actions or target writes.
- Paused gate waits; an authorized one-way resume permits continuation.
- Revoked reading stops the bot before an evidence check.
- Wrong-run injection is rejected.
- Docker stop and kill terminate the worker through external runtime control.
- Independent filesystem events, observed output hashes and Docker lifecycle records
  reconcile with the bot's claims. A discrepancy is ANOMALY, not silently accepted.

This exercise does not prove semantic judgment by an AI agent, complete syscall
coverage, resistance to a malicious Docker host, or instantaneous cancellation of
an operation already in progress.


## Architecture reference

![Supplied control architecture](architecture.png)
