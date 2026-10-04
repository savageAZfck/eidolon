# Threat model — eidolon

The replayed history was tampered before fork — the source chain is verified before replay. A diff is fabricated — the report is signed and independently reproducible from the same chain + policy. A replay is run on live state — the API operates on copies; callers must not fork the live ledger. A divergent outcome is hidden — both divergences and convergences are committed in the report body.

## What this crate guarantees

- The source chain is fully verified before replay begins.
- Reports are signed over chain head, policy identity, and per-entry outcomes.
- The same chain + policy reproduces the same report — verification needs no trust.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
