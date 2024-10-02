use crate::signature::{KeyType, PublicKey, SecretKey};
use crate::types::AccountId;
use std::fmt;
use std::sync::Arc;

/// Test-only signer that "signs" everything with 0s.
/// Don't use in any production or code that requires signature verification.
#[derive(Clone, Debug, PartialEq)]
pub struct EmptyValidatorSigner {
    account_id: AccountId,
}

/// Signer that keeps secret key in memory and signs locally.
#[derive(Clone, Debug, PartialEq)]
pub struct InMemoryValidatorSigner {
    account_id: AccountId,
    signer: Arc<Signer>,
}

impl InMemoryValidatorSigner {
    pub fn from_seed(account_id: AccountId, key_type: KeyType, seed: &str) -> Self {
        let signer = Arc::new(InMemorySigner::from_seed(account_id.clone(), key_type, seed).into());
        Self { account_id, signer }
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

impl From<InMemoryValidatorSigner> for ValidatorSigner {
    fn from(signer: InMemoryValidatorSigner) -> Self {
        ValidatorSigner::InMemory(signer)
    }
}

// Signer that returns empty signature. Used for transaction testing.
#[derive(Debug, PartialEq)]
pub struct EmptySigner {}

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

impl From<InMemorySigner> for Signer {
    fn from(signer: InMemorySigner) -> Self {
        Signer::InMemory(signer)
    }
}
