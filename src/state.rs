use serde::{Deserialize, Serialize};

use crate::protocol::validate_note;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Host,
    Peer,
}

impl Side {
    pub fn index(self) -> usize {
        match self {
            Self::Host => 0,
            Self::Peer => 1,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub seq: u64,
    pub accepted: bool,
}

// Intentionally no Debug: a diagnostic must never accidentally log note text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub text: String,
    pub revision: u64,
    pub epoch: u64,
    pub owner: Side,
    pub receipts: [Receipt; 2],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub epoch: u64,
    pub base_revision: u64,
    pub seq: u64,
    pub text: String,
}

pub struct Authority {
    pub snapshot: Snapshot,
}

impl Authority {
    pub fn new(text: String) -> Result<Self, &'static str> {
        validate_note(&text)?;
        Ok(Self {
            snapshot: Snapshot {
                text,
                revision: 0,
                epoch: 1,
                owner: Side::Host,
                receipts: [Receipt::default(); 2],
            },
        })
    }

    pub fn take_control(&mut self, side: Side) {
        if self.snapshot.owner != side {
            self.snapshot.owner = side;
            self.snapshot.epoch += 1;
        }
    }

    /// Both edges invalidate all work from an old connection, even if ownership
    /// has changed away and back by the time a delayed edit arrives (ABA).
    pub fn connection_changed(&mut self) {
        self.snapshot.owner = Side::Host;
        self.snapshot.epoch += 1;
        self.snapshot.receipts[Side::Peer.index()] = Receipt::default();
    }

    pub fn edit(&mut self, side: Side, edit: Edit) -> bool {
        let receipt = &mut self.snapshot.receipts[side.index()];
        if edit.seq == 0 || edit.seq <= receipt.seq {
            return false;
        }
        let accepted = self.snapshot.owner == side
            && self.snapshot.epoch == edit.epoch
            && self.snapshot.revision == edit.base_revision
            && validate_note(&edit.text).is_ok();
        *receipt = Receipt {
            seq: edit.seq,
            accepted,
        };
        if accepted {
            self.snapshot.text = edit.text;
            self.snapshot.revision += 1;
        }
        accepted
    }
}
