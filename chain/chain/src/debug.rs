use model::block::ApprovalInner;
use model::clock::Utc;
use model::types::{AccountId, BlockHeight};
use std::collections::HashMap;

// Information about the approvals that we received.
#[derive(serde::Serialize, Debug, Default, Clone)]
pub struct ApprovalAtHeightStatus {
    // Map from validator id to the type of approval that they sent and timestamp.
    pub approvals: HashMap<AccountId, (ApprovalInner, Utc)>,
    // Time at which we received 2/3 approvals (doomslug threshold).
    pub ready_at: Option<Utc>,
}

// Information about the approval created by this node.
// Used for debug purposes only.
#[derive(serde::Serialize, Debug, Clone)]
pub struct ApprovalHistoryEntry {
    // If target_height == base_height + 1  - this is endorsement.
    // Otherwise this is a skip.
    pub parent_height: BlockHeight,
    pub target_height: BlockHeight,
    // Time when we actually created the approval and sent it out.
    pub approval_creation_time: Utc,
    // The moment when we were ready to send this approval (or skip)
    pub timer_started_ago_millis: u64,
    // But we had to wait at least this long before doing it.
    pub expected_delay_millis: u64,
}
