use crate::signature::{KeyType, SecretKey};
use crate::validator_signer::ValidatorSigner;

// Helper function that creates a new signer for a given account, that uses the account name as seed.
// Should be used only in tests.
pub fn create_test_signer(account_name: &str) -> ValidatorSigner {
    crate::validator_signer::InMemoryValidatorSigner::from_seed(
        account_name.parse().unwrap(),
        KeyType::ED25519,
        account_name,
    )
    .into()
}

fn ed25519_key_pair_from_seed(seed: &str) -> ed25519_dalek::SigningKey {
    let seed_bytes = seed.as_bytes();
    let len = std::cmp::min(ed25519_dalek::SECRET_KEY_LENGTH, seed_bytes.len());
    let mut seed: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = [b' '; ed25519_dalek::SECRET_KEY_LENGTH];
    seed[..len].copy_from_slice(&seed_bytes[..len]);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

impl SecretKey {
    pub fn from_seed(key_type: KeyType, seed: &str) -> Self {
        match key_type {
            KeyType::ED25519 => {
                let keypair = ed25519_key_pair_from_seed(seed);
                SecretKey::ED25519(crate::signature::ED25519SecretKey(
                    keypair.to_keypair_bytes(),
                ))
            }
        }
    }
}
