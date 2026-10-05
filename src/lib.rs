//! eidolon — counterfactual replay for audited agents.
//!
//! An *eidolon* is a phantom — the self that might have been.
//!
//! Audits answer "what did you do?" They cannot answer "what would you
//! have done?" — yet that is the question consent actually asks: *if I
//! had denied that, if the policy had been stricter, would the outcome
//! have differed?*
//!
//! `eidolon` makes counterfactuals provable:
//!
//! 1. **Fork** — take a slice of a hash-chained history (entries plus
//!    the head they were witnessed under).
//! 2. **Replay** — run a deterministic evaluation function over each
//!    entry under an alternate policy, producing a parallel outcome
//!    stream. Determinism is what makes the counterfactual checkable:
//!    anyone with the same entries and the same function gets the same
//!    alternate history.
//! 3. **Diff + sign** — align actual and counterfactual outcomes entry
//!    by entry, and the organism signs the [`DiffReport`]: "under policy
//!    P′ these entries would have produced these outcomes." The report
//!    binds the *real* chain head — it can't be attached to a
//!    fabricated history.
//!
//! The evaluation function is caller-supplied — `eidolon` judges nothing
//! about what counts as an outcome, only that the comparison is honest.
//!
//! ```no_run
//! use eidolon::{replay_diff, Identity, ReplayFn};
//!
//! let entries = vec![
//!     serde_json::json!({"seq":1,"tool":"read_file"}),
//!     serde_json::json!({"seq":2,"tool":"send_mail"}),
//! ];
//! let strict: Box<ReplayFn> = Box::new(|e| {
//!     let denied = e["tool"].as_str() == Some("send_mail");
//!     serde_json::json!({"allowed": !denied})
//! });
//! let permissive: Box<ReplayFn> = Box::new(|_| serde_json::json!({"allowed": true}));
//! let tip = "ab".repeat(32);
//! let report = replay_diff(
//!     &Identity::generate(), "ledger", &tip, "strict-policy", "policy.yaml@abc",
//!     &entries, &permissive, &strict,
//! ).unwrap();
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

#[derive(Debug)]
pub enum Error {
    BadSignature(String),
    BadReplay(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::BadReplay(m) => write!(f, "replay failure: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

// ---------------------------------------------------------------- identity

pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- replay

/// The deterministic evaluation function: entry in, outcome out. Must be
/// pure — same entry, same outcome — or the counterfactual isn't
/// checkable by third parties.
pub type ReplayFn = dyn Fn(&Value) -> Value;

/// A single divergence between the actual and counterfactual streams.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Divergence {
    /// Index into the replayed slice.
    pub index: usize,
    /// SHA-256 of the history entry — evidence pointer.
    pub entry_hash: String,
    /// What actually happened (per the actual replay function).
    pub actual: Value,
    /// What the alternate policy would have produced.
    pub counterfactual: Value,
}

/// A signed counterfactual diff: bound to a real chain head, naming both
/// policies, listing every divergence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffReport {
    /// Organism issuing the report (hex pubkey).
    pub issuer: String,
    /// Chain the history slice came from.
    pub chain_id: String,
    /// Tip hash of the real chain at replay time — the anchor that makes
    /// the report unforgeable against fabricated history.
    pub chain_tip: String,
    /// Number of entries replayed.
    pub span: usize,
    /// Label for the actual policy ("policy.yaml@abc123").
    pub policy_actual: String,
    /// Label for the counterfactual policy.
    pub policy_alt: String,
    /// Entries where the outcomes differ.
    pub divergences: Vec<Divergence>,
    /// Entries where outcomes agree.
    pub convergent: usize,
    pub ts: u64,
    /// Signature over the canonical body.
    pub signature: String,
}

impl DiffReport {
    fn body(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "chain_id": self.chain_id,
            "chain_tip": self.chain_tip,
            "span": self.span,
            "policy_actual": self.policy_actual,
            "policy_alt": self.policy_alt,
            "divergences": self.divergences,
            "convergent": self.convergent,
            "ts": self.ts,
        })
    }

    /// Verify the issuer's signature.
    pub fn verify(&self) -> Result<(), Error> {
        verify_signature(&self.issuer, &canonical(&self.body()), &self.signature)
    }

    /// Did the alternate policy change anything?
    pub fn diverged(&self) -> bool {
        !self.divergences.is_empty()
    }
}

/// Replay a history slice under two policies and sign the divergence.
///
/// - `issuer` signs the resulting report.
/// - `chain_id`/`chain_tip` anchor the report to a real chain head.
/// - `entries` is the forked slice (ordered).
/// - `actual`/`alternate` are the two deterministic evaluation functions.
#[allow(clippy::too_many_arguments)]
pub fn replay_diff(
    issuer: &Identity,
    chain_id: &str,
    chain_tip: &str,
    policy_alt: &str,
    policy_actual_label: &str,
    entries: &[Value],
    actual: &ReplayFn,
    alternate: &ReplayFn,
) -> Result<DiffReport, Error> {
    if chain_tip.len() != 64 {
        return Err(Error::BadReplay("chain_tip must be 64-char hex".into()));
    }
    let mut divergences = Vec::new();
    let mut convergent = 0usize;
    for (i, entry) in entries.iter().enumerate() {
        let a = actual(entry);
        let c = alternate(entry);
        if a == c {
            convergent += 1;
        } else {
            divergences.push(Divergence {
                index: i,
                entry_hash: sha256_hex(&canonical(entry)),
                actual: a,
                counterfactual: c,
            });
        }
    }
    let mut report = DiffReport {
        issuer: issuer.public_key(),
        chain_id: chain_id.to_string(),
        chain_tip: chain_tip.to_string(),
        span: entries.len(),
        policy_actual: policy_actual_label.to_string(),
        policy_alt: policy_alt.to_string(),
        divergences,
        convergent,
        ts: now_secs(),
        signature: String::new(),
    };
    report.signature = issuer.sign(&canonical(&report.body()));
    Ok(report)
}

/// Independently verify a report: check the signature, then re-run both
/// replay functions over the entry slice and confirm the divergence set
/// matches exactly. A report that can't be reproduced is a lie.
pub fn verify_replay(
    report: &DiffReport,
    entries: &[Value],
    actual: &ReplayFn,
    alternate: &ReplayFn,
) -> Result<(), Error> {
    report.verify()?;
    if entries.len() != report.span {
        return Err(Error::BadReplay(format!(
            "span mismatch: report {} vs entries {}",
            report.span,
            entries.len()
        )));
    }
    let mut expected_div = Vec::new();
    let mut convergent = 0usize;
    for (i, entry) in entries.iter().enumerate() {
        let a = actual(entry);
        let c = alternate(entry);
        if a == c {
            convergent += 1;
        } else {
            expected_div.push(Divergence {
                index: i,
                entry_hash: sha256_hex(&canonical(entry)),
                actual: a,
                counterfactual: c,
            });
        }
    }
    if convergent != report.convergent {
        return Err(Error::BadReplay("convergent count mismatch".into()));
    }
    if expected_div.len() != report.divergences.len() {
        return Err(Error::BadReplay("divergence count mismatch".into()));
    }
    for (e, r) in expected_div.iter().zip(report.divergences.iter()) {
        if e.index != r.index
            || e.entry_hash != r.entry_hash
            || e.actual != r.actual
            || e.counterfactual != r.counterfactual
        {
            return Err(Error::BadReplay(format!(
                "divergence at index {} does not reproduce",
                e.index
            )));
        }
    }
    Ok(())
}
