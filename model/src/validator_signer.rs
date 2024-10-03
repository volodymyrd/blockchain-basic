use crate::block::{Approval, ApprovalInner};
use crate::signature::{KeyType, PublicKey, SecretKey, Signature};
use crate::types::{AccountId, BlockHeight};
use std::fmt;
use std::sync::Arc;

/// Test-only signer that "signs" everything with 0s.
/// Don't use in any production or code that requires signature verification.
#[derive(Clone, Debug, PartialEq)]
pub struct EmptyValidatorSigner {
    account_id: AccountId,
}

impl EmptyValidatorSigner {
    fn validator_id(&self) -> &AccountId {
        &self.account_id
    }

    fn sign_approval(&self, _inner: &ApprovalInner, _target_height: BlockHeight) -> Signature {
        Signature::default()
    }
}

/// Signer that keeps secret key in memory and signs locally.
#[derive(Clone, Debug, PartialEq)]
pub struct InMemoryValidatorSigner {
    account_id: AccountId,
    signer: Arc<Signer>,
}

impl InMemoryValidatorSigner {
    pub fn validator_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn from_seed(account_id: AccountId, key_type: KeyType, seed: &str) -> Self {
        let signer = Arc::new(InMemorySigner::from_seed(account_id.clone(), key_type, seed).into());
        Self { account_id, signer }
    }

    fn sign_approval(&self, inner: &ApprovalInner, target_height: BlockHeight) -> Signature {
        self.signer
            .sign(&Approval::get_data_for_sig(inner, target_height))
    }
}

/// Enum for validator signer, that holds validator id and key used for signing data.
#[derive(Clone, Debug, PartialEq)]
pub enum ValidatorSigner {
    /// Dummy validator signer, does not hold a key. Use for tests only!
    Empty(EmptyValidatorSigner),
    /// Default validator signer that holds data in memory.
    InMemory(InMemoryValidatorSigner),
}

/// Validator signer that is used to sign blocks and approvals.
impl ValidatorSigner {
    /// Account id of the given validator.
    pub fn validator_id(&self) -> &AccountId {
        match self {
            ValidatorSigner::Empty(signer) => signer.validator_id(),
            ValidatorSigner::InMemory(signer) => signer.validator_id(),
        }
    }

    /// Signs approval of given parent hash and reference hash.
    pub fn sign_approval(&self, inner: &ApprovalInner, target_height: BlockHeight) -> Signature {
        match self {
            ValidatorSigner::Empty(signer) => signer.sign_approval(inner, target_height),
            ValidatorSigner::InMemory(signer) => signer.sign_approval(inner, target_height),
        }
    }
}
impl From<InMemoryValidatorSigner> for ValidatorSigner {
    fn from(signer: InMemoryValidatorSigner) -> Self {
        ValidatorSigner::InMemory(signer)
    }
}

// Signer that returns empty signature. Used for transaction testing.
#[derive(Debug, PartialEq)]
pub struct EmptySigner {}

impl EmptySigner {
    pub fn sign(&self, _data: &[u8]) -> Signature {
        Signature::empty(KeyType::ED25519)
    }
}

/// Signer that keeps secret key in memory.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InMemorySigner {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl InMemorySigner {
    pub fn from_seed(account_id: AccountId, key_type: KeyType, seed: &str) -> Self {
        let secret_key = SecretKey::from_seed(key_type, seed);
        Self {
            account_id,
            public_key: secret_key.public_key(),
            secret_key,
        }
    }
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.secret_key.sign(data)
    }
}

impl fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InMemorySigner(account_id: {}, public_key: {})",
            self.account_id, self.public_key
        )
    }
}

/// Enum for Signer, that can sign with some subset of supported curves.
#[derive(Debug, PartialEq)]
pub enum Signer {
    /// Dummy signer, does not hold a key. Use for tests only!
    Empty(EmptySigner),
    /// Default signer that holds data in memory.
    InMemory(InMemorySigner),
}

impl Signer {
    pub fn sign(&self, data: &[u8]) -> Signature {
        match self {
            Signer::Empty(signer) => signer.sign(data),
            Signer::InMemory(signer) => signer.sign(data),
        }
    }
}
impl From<InMemorySigner> for Signer {
    fn from(signer: InMemorySigner) -> Self {
        Signer::InMemory(signer)
    }
}
