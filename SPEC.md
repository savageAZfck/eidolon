# SPEC — eidolon (counterfactual replay)

## Input

Any hash-chained ledger of entries (`{"seq", …, "prev_hash", "hash"}`).
The chain is fully verified before replay — a forged history fails fast.

## Replay

`replay(chain, fork_seq, policy: Fn(entry) → outcome)`:

- Entries before `fork_seq` keep their actual outcomes.
- Entries at/after `fork_seq` are re-evaluated under `policy`.
- Per-entry result: `diverged` (alt outcome ≠ actual) or `convergent`.

## Report

```json
{
  "id": "sha256", "replayer": "pubkey",
  "source_head": "chain tip", "fork_seq": 0,
  "policy_hash": "identity of the alt policy",
  "entries": [{ "seq": 0, "actual": {…}, "alternate": {…},
               "outcome": "diverged|convergent" }],
  "divergences": n, "convergences": n,
  "ts": 0, "signature": "ed25519 over body"
}
```

`report.check(chain)` verifies the signature, the pinned head, and
re-runs deterministically: the same chain + same policy reproduces the
same report body.

## Invariants

- Replay never mutates the source — entries are copied at fork.
- Both divergences AND convergences are committed (nothing cherry-picks).
- A report is bound to exactly one source head and one policy hash.
