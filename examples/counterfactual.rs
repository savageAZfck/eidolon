//! Counterfactual audit: "if the consent policy had been stricter,
//! what would I have done differently?"
use eidolon::*;
use serde_json::json;

fn main() {
    // A slice of an organism's real history — tool dispatches.
    let entries = vec![
        json!({"seq":11,"tool":"read_file","path":"~/notes.md"}),
        json!({"seq":12,"tool":"send_mail","to":"alice@example.com"}),
        json!({"seq":13,"tool":"screenshot"}),
        json!({"seq":14,"tool":"run_shell","cmd":"curl evil.example"}),
    ];
    let tip = "ab".repeat(32);

    // Actual policy at the time: allow everything.
    let permissive: Box<ReplayFn> = Box::new(|_| json!({"allowed": true}));

    // Alternate: a stricter consent policy that denies outbound tools.
    let strict: Box<ReplayFn> = Box::new(|e| {
        let tool = e["tool"].as_str().unwrap_or("");
        let outbound = matches!(tool, "send_mail" | "send_message")
            || e["cmd"]
                .as_str()
                .map(|c| c.contains("curl") || c.contains("wget"))
                .unwrap_or(false);
        if outbound {
            json!({"allowed": false, "reason": "egress"})
        } else {
            json!({"allowed": true})
        }
    });

    let me = Identity::generate();
    let report = replay_diff(
        &me,
        "ledger",
        &tip,
        "consent-strict-v2",
        "policy.yaml@current",
        &entries,
        &permissive,
        &strict,
    )
    .unwrap();

    println!(
        "counterfactual report — {} entries, {} diverged, {} convergent",
        report.span,
        report.divergences.len(),
        report.convergent
    );
    for d in &report.divergences {
        println!(
            "  entry {}…: actual {:?} -> alt {:?}",
            &d.entry_hash[..8],
            d.actual,
            d.counterfactual
        );
    }
    report.verify().unwrap();
    verify_replay(&report, &entries, &permissive, &strict).unwrap();
    println!(
        "report signed by {} and independently reproducible",
        &report.issuer[..12]
    );
}
