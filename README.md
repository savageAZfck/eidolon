# eidolon

**Counterfactual replay for audited agents — provable what-would-have-happened.**

An *eidolon* is a phantom — the self that might have been.

## Why this exists

Audit answers "what did you do?" Consent actually asks "what *would* you have done?" — if I'd denied that scope, if the policy were stricter, would the outcome have differed? `eidolon` makes counterfactuals checkable instead of rhetorical:

1. **Replay** — run a deterministic evaluation function over a slice of real history under an alternate policy. Determinism is the check: anyone with the same entries and same function reproduces the same alternate history.
2. **Diff** — align actual and counterfactual outcomes entry by entry.
3. **Sign** — the organism signs the `DiffReport`, bound to the real chain tip. The report can't be attached to a fabricated history, and `verify_replay` re-runs both functions to confirm the divergence set reproduces exactly — **a report that can't be reproduced is a lie.**

## What it gives you

- `replay_diff()` — forked slice + two policies → signed `DiffReport` (divergences with entry-hash evidence, convergent count, both policy labels).
- `verify_replay()` — independent reproduction: signature check *plus* full re-evaluation.
- Chain-tip anchoring — reports are bound to a real, notarizable history.
- The evaluation function is caller-supplied — eidolon judges nothing about what counts as an outcome, only that the comparison is honest.

## Try it

```bash
cargo run --example counterfactual
cargo test
```

## Pair with

- `wintercount` — the policy engine whose alternates get replayed.
- `flight_tape` — incident bundles whose histories get forked.
- `kola` — notarize the tip the report anchors to.
