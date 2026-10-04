use eidolon::*;
use serde_json::json;

fn entries() -> Vec<serde_json::Value> {
    vec![
        json!({"seq":1,"tool":"read_file","path":"/tmp/a"}),
        json!({"seq":2,"tool":"send_mail","to":"ext@example.com"}),
        json!({"seq":3,"tool":"write_file","path":"/tmp/b"}),
    ]
}

fn tip() -> String {
    "cd".repeat(32)
}

fn permissive() -> Box<ReplayFn> {
    Box::new(|_| json!({"allowed": true}))
}

fn strict() -> Box<ReplayFn> {
    Box::new(|e| {
        let tool = e["tool"].as_str().unwrap_or("");
        let denied = matches!(tool, "send_mail" | "send_message");
        json!({"allowed": !denied})
    })
}

#[test]
fn replay_finds_divergence() {
    let id = Identity::generate();
    let report = replay_diff(
        &id,
        "ledger",
        &tip(),
        "strict-v2",
        "policy.yaml@abc",
        &entries(),
        &permissive(),
        &strict(),
    )
    .unwrap();
    assert!(report.diverged());
    assert_eq!(report.divergences.len(), 1);
    assert_eq!(report.divergences[0].index, 1);
    assert_eq!(report.convergent, 2);
    report.verify().unwrap();
}

#[test]
fn identical_policies_converge() {
    let id = Identity::generate();
    let report = replay_diff(
        &id,
        "ledger",
        &tip(),
        "same",
        "policy.yaml@abc",
        &entries(),
        &permissive(),
        &permissive(),
    )
    .unwrap();
    assert!(!report.diverged());
    assert_eq!(report.convergent, 3);
}

#[test]
fn verify_replay_reproduces() {
    let id = Identity::generate();
    let report = replay_diff(
        &id,
        "ledger",
        &tip(),
        "strict-v2",
        "policy.yaml@abc",
        &entries(),
        &permissive(),
        &strict(),
    )
    .unwrap();
    verify_replay(&report, &entries(), &permissive(), &strict()).unwrap();
}

#[test]
fn verify_replay_catches_lying_report() {
    let id = Identity::generate();
    let mut report = replay_diff(
        &id,
        "ledger",
        &tip(),
        "strict-v2",
        "policy.yaml@abc",
        &entries(),
        &permissive(),
        &strict(),
    )
    .unwrap();
    // Lie: claim the divergence was at index 0.
    report.divergences[0].index = 0;
    assert!(verify_replay(&report, &entries(), &permissive(), &strict()).is_err());
}

#[test]
fn report_binds_the_real_tip() {
    let id = Identity::generate();
    let report = replay_diff(
        &id,
        "ledger",
        &tip(),
        "alt",
        "actual",
        &entries(),
        &permissive(),
        &strict(),
    )
    .unwrap();
    assert_eq!(report.chain_tip, tip());
    // A report can't be transplanted to fabricated history — the tip is
    // in the signed body, so editing it breaks the signature.
    let mut forged = report.clone();
    forged.chain_tip = "00".repeat(32);
    assert!(forged.verify().is_err());
}

#[test]
fn bad_tip_rejected() {
    let id = Identity::generate();
    assert!(replay_diff(
        &id,
        "ledger",
        "short",
        "alt",
        "actual",
        &entries(),
        &permissive(),
        &strict(),
    )
    .is_err());
}

#[test]
fn report_serializes() {
    let id = Identity::generate();
    let report = replay_diff(
        &id,
        "ledger",
        &tip(),
        "alt",
        "actual",
        &entries(),
        &permissive(),
        &strict(),
    )
    .unwrap();
    let text = serde_json::to_string_pretty(&report).unwrap();
    let loaded: DiffReport = serde_json::from_str(&text).unwrap();
    loaded.verify().unwrap();
}
