# Security

Report vulnerabilities privately to savagetism@icloud.com — do not open
public issues for exploitable weaknesses.

Scope: ledger verification before replay, fork-point integrity, alternate-policy application, signed diff/report correctness, report reproducibility.

Out of scope: the semantic meaning of replayed events, the quality of alternate policies, and side effects — replay MUST be run on copies, never the live ledger (see THREAT_MODEL.md).
