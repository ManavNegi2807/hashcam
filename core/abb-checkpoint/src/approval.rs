//! Signed approvals, signed mandates and salted field commitments
//! (`PROTOCOL.md` 5.5, 5.6, 5.7; decisions D-11 and D-16).
//!
//! All three are statements a *person or issuer* signs or commits to with a
//! key the control plane does not hold. This crate only builds, signs and
//! checks the bytes. Whether an approval is *enough* for a given action is the
//! verifier's call (`abb-receipt`).

use abb_jcs::{hex_decode, hex_lower, Value};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{hex64, tagged_bytes, tags, CheckpointError, Result};

fn verify_hex(bytes: &[u8], signature_hex: &str, key: &VerifyingKey) -> Result<()> {
    let raw = hex_decode(signature_hex).map_err(|_| CheckpointError::BadHashHex("signature"))?;
    let sig: [u8; 64] = raw
        .try_into()
        .map_err(|_| CheckpointError::BadKeyOrSignatureLength)?;
    key.verify_strict(bytes, &Signature::from_bytes(&sig))
        .map_err(|_| CheckpointError::BadSignature)
}

fn parse_exact(text: &str, expected: &[&str]) -> Result<Value> {
    let value = abb_jcs::parse(text)?;
    if abb_jcs::to_canonical(&value)? != text {
        return Err(CheckpointError::FieldInvalid("non-canonical bytes"));
    }
    let entries = value
        .as_object()
        .ok_or(CheckpointError::FieldInvalid("statement"))?;
    let mut names: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
    names.sort_unstable();
    let mut want: Vec<&str> = expected.to_vec();
    want.sort_unstable();
    if names != want {
        return Err(CheckpointError::FieldInvalid("statement fields"));
    }
    Ok(value)
}

fn text_of(value: &Value, name: &'static str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(CheckpointError::FieldInvalid(name))
}

fn int_of(value: &Value, name: &'static str) -> Result<i64> {
    value
        .get(name)
        .and_then(Value::as_int)
        .ok_or(CheckpointError::FieldInvalid(name))
}

fn strings_of(value: &Value, name: &'static str) -> Result<Vec<String>> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or(CheckpointError::FieldInvalid(name))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(CheckpointError::FieldInvalid(name))
        })
        .collect()
}

// --------------------------------------------------------------------------- //
// approvals (5.6)
// --------------------------------------------------------------------------- //

/// What a human approver signs: this action, as summarized, may or may not go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStatement {
    /// The approval request this answers.
    pub approval_id: String,
    /// The run it belongs to.
    pub run_id: String,
    /// The action being decided.
    pub action_id: String,
    /// Digest of exactly what the approver saw (action type, target, key parameters).
    pub summary_digest: String,
    /// `GRANTED` or `DENIED`.
    pub decision: String,
    /// Unix ms after which a grant no longer covers a dispatch. A claim.
    pub expires_at: i64,
}

impl ApprovalStatement {
    /// The JCS value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            (
                "approval_id".to_owned(),
                Value::Str(self.approval_id.clone()),
            ),
            ("run_id".to_owned(), Value::Str(self.run_id.clone())),
            ("action_id".to_owned(), Value::Str(self.action_id.clone())),
            (
                "summary_digest".to_owned(),
                Value::Str(self.summary_digest.clone()),
            ),
            ("decision".to_owned(), Value::Str(self.decision.clone())),
            ("expires_at".to_owned(), Value::Int(self.expires_at)),
        ])
    }

    /// Read a statement from canonical text, rejecting anything unexpected.
    pub fn from_canonical(text: &str) -> Result<Self> {
        let value = parse_exact(
            text,
            &[
                "approval_id",
                "run_id",
                "action_id",
                "summary_digest",
                "decision",
                "expires_at",
            ],
        )?;
        let statement = Self {
            approval_id: text_of(&value, "approval_id")?,
            run_id: text_of(&value, "run_id")?,
            action_id: text_of(&value, "action_id")?,
            summary_digest: text_of(&value, "summary_digest")?,
            decision: text_of(&value, "decision")?,
            expires_at: int_of(&value, "expires_at")?,
        };
        hex64(&statement.summary_digest, "summary_digest")?;
        if statement.decision != "GRANTED" && statement.decision != "DENIED" {
            return Err(CheckpointError::FieldInvalid("decision"));
        }
        Ok(statement)
    }

    /// `"ABB1-APPROVAL" || 0x00 || JCS(statement)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(tagged_bytes(
            tags::APPROVAL,
            &abb_jcs::canonical_bytes(&self.to_value())?,
        ))
    }

    /// Sign with the approver's key.
    pub fn sign(&self, key: &SigningKey) -> Result<String> {
        Ok(hex_lower(&key.sign(&self.signing_bytes()?).to_bytes()))
    }

    /// Verify a signature over this statement.
    pub fn verify(&self, signature_hex: &str, key: &VerifyingKey) -> Result<()> {
        verify_hex(&self.signing_bytes()?, signature_hex, key)
    }
}

// --------------------------------------------------------------------------- //
// mandates (5.7)
// --------------------------------------------------------------------------- //

/// A signed statement of what the agent was allowed to do in one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mandate {
    /// Identifier.
    pub mandate_id: String,
    /// The `mandate_issuer` key that signs it.
    pub issuer_key_id: String,
    /// The agent or adapter it applies to.
    pub subject: String,
    /// Exact hosts or `*.suffix` patterns.
    pub allowed_hosts: Vec<String>,
    /// Action types the agent may propose.
    pub allowed_action_types: Vec<String>,
    /// Upper bound on actions in the run.
    pub max_actions: i64,
    /// Optional spend bound, integer minor units.
    pub max_spend_minor_units: Option<i64>,
    /// Currency of the spend bound; present exactly when the bound is.
    pub currency: Option<String>,
    /// Unix ms. A claim.
    pub not_before: i64,
    /// Unix ms. A claim.
    pub not_after: i64,
}

impl Mandate {
    /// The JCS value. The two optional fields are omitted when unset.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let list = |items: &[String]| Value::Array(items.iter().cloned().map(Value::Str).collect());
        let mut entries = vec![
            ("mandate_id".to_owned(), Value::Str(self.mandate_id.clone())),
            (
                "issuer_key_id".to_owned(),
                Value::Str(self.issuer_key_id.clone()),
            ),
            ("subject".to_owned(), Value::Str(self.subject.clone())),
            ("allowed_hosts".to_owned(), list(&self.allowed_hosts)),
            (
                "allowed_action_types".to_owned(),
                list(&self.allowed_action_types),
            ),
            ("max_actions".to_owned(), Value::Int(self.max_actions)),
            ("not_before".to_owned(), Value::Int(self.not_before)),
            ("not_after".to_owned(), Value::Int(self.not_after)),
        ];
        if let (Some(amount), Some(currency)) = (self.max_spend_minor_units, &self.currency) {
            entries.push(("max_spend_minor_units".to_owned(), Value::Int(amount)));
            entries.push(("currency".to_owned(), Value::Str(currency.clone())));
        }
        Value::Object(entries)
    }

    /// Read a mandate from canonical text, rejecting anything unexpected.
    pub fn from_canonical(text: &str) -> Result<Self> {
        let parsed = abb_jcs::parse(text)?;
        let has_spend = parsed.get("max_spend_minor_units").is_some();
        let mut expected = vec![
            "mandate_id",
            "issuer_key_id",
            "subject",
            "allowed_hosts",
            "allowed_action_types",
            "max_actions",
            "not_before",
            "not_after",
        ];
        if has_spend {
            expected.push("max_spend_minor_units");
            expected.push("currency");
        }
        let value = parse_exact(text, &expected)?;
        let mandate = Self {
            mandate_id: text_of(&value, "mandate_id")?,
            issuer_key_id: text_of(&value, "issuer_key_id")?,
            subject: text_of(&value, "subject")?,
            allowed_hosts: strings_of(&value, "allowed_hosts")?,
            allowed_action_types: strings_of(&value, "allowed_action_types")?,
            max_actions: int_of(&value, "max_actions")?,
            max_spend_minor_units: if has_spend {
                Some(int_of(&value, "max_spend_minor_units")?)
            } else {
                None
            },
            currency: if has_spend {
                Some(text_of(&value, "currency")?)
            } else {
                None
            },
            not_before: int_of(&value, "not_before")?,
            not_after: int_of(&value, "not_after")?,
        };
        if mandate.max_actions < 0 || mandate.not_after < mandate.not_before {
            return Err(CheckpointError::FieldInvalid("mandate bounds"));
        }
        if mandate.max_spend_minor_units.is_some_and(|n| n < 0) {
            return Err(CheckpointError::FieldInvalid("max_spend_minor_units"));
        }
        Ok(mandate)
    }

    /// `"ABB1-MANDATE" || 0x00 || JCS(mandate)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(tagged_bytes(
            tags::MANDATE,
            &abb_jcs::canonical_bytes(&self.to_value())?,
        ))
    }

    /// `SHA-256(signing_bytes)`, lowercase hex (`PROTOCOL.md` 5.7).
    pub fn digest_hex(&self) -> Result<String> {
        Ok(hex_lower(&Sha256::digest(self.signing_bytes()?)))
    }

    /// Sign with the issuer's key.
    pub fn sign(&self, key: &SigningKey) -> Result<String> {
        Ok(hex_lower(&key.sign(&self.signing_bytes()?).to_bytes()))
    }

    /// Verify a signature over this mandate.
    pub fn verify(&self, signature_hex: &str, key: &VerifyingKey) -> Result<()> {
        verify_hex(&self.signing_bytes()?, signature_hex, key)
    }

    /// Does `host` fall inside the allowed hosts? Same rule as the gateway:
    /// an exact host, or a `*.suffix` pattern that also covers the bare suffix.
    #[must_use]
    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed_hosts.iter().any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            match pattern.strip_prefix("*.") {
                Some(rest) => host == rest || host.ends_with(&format!(".{rest}")),
                None => host == pattern,
            }
        })
    }
}

// --------------------------------------------------------------------------- //
// field commitments (5.5)
// --------------------------------------------------------------------------- //

/// `SHA-256("ABB1-FIELD" || 0x00 || salt || JCS(value))`, lowercase hex.
pub fn field_commitment(salt: &[u8], value: &Value) -> Result<String> {
    let mut data = Vec::with_capacity(salt.len() + 32);
    data.extend_from_slice(salt);
    data.extend_from_slice(&abb_jcs::canonical_bytes(value)?);
    Ok(hex_lower(&Sha256::digest(tagged_bytes(tags::FIELD, &data))))
}

/// Salts are exactly 16 bytes (`PROTOCOL.md` 5.5).
pub const SALT_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(label: &str) -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
    }

    fn statement() -> ApprovalStatement {
        ApprovalStatement {
            approval_id: "approval-a1".to_owned(),
            run_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            action_id: "a1".to_owned(),
            summary_digest: "ab".repeat(32),
            decision: "GRANTED".to_owned(),
            expires_at: 1_760_000_900_000,
        }
    }

    fn mandate() -> Mandate {
        Mandate {
            mandate_id: "m-1".to_owned(),
            issuer_key_id: "ed25519:aa".to_owned(),
            subject: "replay".to_owned(),
            allowed_hosts: vec!["vendor.example".to_owned(), "*.bank.example".to_owned()],
            allowed_action_types: vec!["NAVIGATE".to_owned(), "CLICK".to_owned()],
            max_actions: 5,
            max_spend_minor_units: Some(50_000),
            currency: Some("INR".to_owned()),
            not_before: 1_760_000_000_000,
            not_after: 1_760_086_400_000,
        }
    }

    #[test]
    fn an_approval_round_trips_and_binds_every_field() {
        let approver = key("approver");
        let s = statement();
        let sig = s.sign(&approver).unwrap();
        s.verify(&sig, &approver.verifying_key()).unwrap();

        let canonical = abb_jcs::to_canonical(&s.to_value()).unwrap();
        assert_eq!(ApprovalStatement::from_canonical(&canonical).unwrap(), s);

        // Changing any single field breaks the signature.
        let mut other = s.clone();
        other.action_id = "a2".to_owned();
        assert!(other.verify(&sig, &approver.verifying_key()).is_err());
        let mut other = s.clone();
        other.summary_digest = "cd".repeat(32);
        assert!(other.verify(&sig, &approver.verifying_key()).is_err());
        let mut other = s.clone();
        other.decision = "DENIED".to_owned();
        assert!(other.verify(&sig, &approver.verifying_key()).is_err());
        let mut other = s.clone();
        other.expires_at += 1;
        assert!(other.verify(&sig, &approver.verifying_key()).is_err());
        let mut other = s.clone();
        other.run_id = "22222222-2222-4222-8222-222222222222".to_owned();
        assert!(other.verify(&sig, &approver.verifying_key()).is_err());
    }

    #[test]
    fn a_different_key_cannot_have_signed_it() {
        let s = statement();
        let sig = s.sign(&key("approver")).unwrap();
        assert!(s
            .verify(&sig, &key("someone-else").verifying_key())
            .is_err());
    }

    #[test]
    fn an_approval_is_not_a_mandate_or_a_witness_statement() {
        // Domain separation: the same bytes under another tag must not verify.
        let s = statement();
        let wrong = tagged_bytes(
            tags::MANDATE,
            &abb_jcs::canonical_bytes(&s.to_value()).unwrap(),
        );
        let approver = key("approver");
        let sig = hex_lower(&approver.sign(&wrong).to_bytes());
        assert!(s.verify(&sig, &approver.verifying_key()).is_err());
    }

    #[test]
    fn approval_text_with_extra_or_odd_fields_is_refused() {
        let s = statement();
        let mut canonical = abb_jcs::to_canonical(&s.to_value()).unwrap();
        canonical.insert_str(canonical.len() - 1, ",\"x\":1");
        assert!(ApprovalStatement::from_canonical(&canonical).is_err());
        let spaced = abb_jcs::to_canonical(&s.to_value())
            .unwrap()
            .replace(':', ": ");
        assert!(ApprovalStatement::from_canonical(&spaced).is_err());
        let bad = abb_jcs::to_canonical(&s.to_value())
            .unwrap()
            .replace("GRANTED", "MAYBE");
        assert!(ApprovalStatement::from_canonical(&bad).is_err());
    }

    #[test]
    fn a_mandate_round_trips_and_has_a_stable_digest() {
        let issuer = key("issuer");
        let m = mandate();
        let sig = m.sign(&issuer).unwrap();
        m.verify(&sig, &issuer.verifying_key()).unwrap();
        let canonical = abb_jcs::to_canonical(&m.to_value()).unwrap();
        assert_eq!(Mandate::from_canonical(&canonical).unwrap(), m);
        assert_eq!(m.digest_hex().unwrap(), m.digest_hex().unwrap());
        let mut other = m.clone();
        other.max_actions = 6;
        assert_ne!(other.digest_hex().unwrap(), m.digest_hex().unwrap());
        assert!(other.verify(&sig, &issuer.verifying_key()).is_err());
    }

    #[test]
    fn a_mandate_without_a_spend_bound_omits_both_optional_fields() {
        let mut m = mandate();
        m.max_spend_minor_units = None;
        m.currency = None;
        let canonical = abb_jcs::to_canonical(&m.to_value()).unwrap();
        assert!(!canonical.contains("currency"));
        assert_eq!(Mandate::from_canonical(&canonical).unwrap(), m);
    }

    #[test]
    fn a_mandate_with_an_impossible_window_or_negative_bound_is_refused() {
        let mut m = mandate();
        m.not_after = m.not_before - 1;
        let canonical = abb_jcs::to_canonical(&m.to_value()).unwrap();
        assert!(Mandate::from_canonical(&canonical).is_err());
        let mut m = mandate();
        m.max_actions = -1;
        let canonical = abb_jcs::to_canonical(&m.to_value()).unwrap();
        assert!(Mandate::from_canonical(&canonical).is_err());
    }

    #[test]
    fn host_patterns_match_like_the_gateway() {
        let m = mandate();
        assert!(m.allows_host("vendor.example"));
        assert!(m.allows_host("VENDOR.example"));
        assert!(m.allows_host("pay.bank.example"));
        assert!(m.allows_host("bank.example"));
        assert!(!m.allows_host("evil-bank.example"));
        assert!(!m.allows_host("vendor.example.evil.test"));
        assert!(!m.allows_host("other.example"));
    }

    #[test]
    fn a_commitment_binds_salt_and_value() {
        let value = Value::Str("4111111111111111".to_owned());
        let a = field_commitment(&[1u8; SALT_LEN], &value).unwrap();
        let b = field_commitment(&[2u8; SALT_LEN], &value).unwrap();
        let c = field_commitment(&[1u8; SALT_LEN], &Value::Str("other".to_owned())).unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, field_commitment(&[1u8; SALT_LEN], &value).unwrap());
    }

    #[test]
    fn a_commitment_does_not_collide_with_a_plain_digest_of_the_value() {
        // The value alone, hashed with no tag and no salt, must differ.
        let value = Value::Str("hunter2".to_owned());
        let plain = hex_lower(&Sha256::digest(abb_jcs::canonical_bytes(&value).unwrap()));
        assert_ne!(field_commitment(&[0u8; SALT_LEN], &value).unwrap(), plain);
    }
}
