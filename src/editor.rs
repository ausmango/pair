//! UI-side synchronization. At most one edit is in flight. New keystrokes
//! remain local until that edit is acknowledged by the host.
use crate::{
    protocol::validate_note,
    state::{Edit, Side, Snapshot},
};

pub const MAX_DRAFTS: usize = 8;

pub struct Editor {
    pub side: Side,
    pub text: String,
    pub snapshot: Option<Snapshot>,
    pub drafts: Vec<String>,
    pub connected: bool,
    pub running: bool,
    dirty: bool,
    in_flight: Option<Edit>,
    next_seq: u64,
    sync_serial: u64,
}

impl Default for Editor {
    fn default() -> Self {
        Self {
            side: Side::Host,
            text: String::new(),
            snapshot: None,
            drafts: Vec::new(),
            connected: false,
            running: false,
            dirty: false,
            in_flight: None,
            next_seq: 1,
            sync_serial: 0,
        }
    }
}

impl Editor {
    pub fn can_edit(&self) -> bool {
        self.running
            && (self.side == Side::Host || self.connected)
            && self.snapshot.as_ref().is_some_and(|s| s.owner == self.side)
            && self.drafts.len() < MAX_DRAFTS
    }

    pub fn has_unsent(&self) -> bool {
        self.dirty || self.in_flight.is_some()
    }

    pub fn needs_flush(&self) -> bool {
        self.dirty && self.in_flight.is_none() && self.can_edit()
    }

    fn keep_draft(&mut self) {
        if self.has_unsent() && !self.drafts.contains(&self.text) {
            // can_edit reserves a slot before allowing any new local work.
            assert!(self.drafts.len() < MAX_DRAFTS);
            self.drafts.push(self.text.clone());
        }
        self.dirty = false;
        self.in_flight = None;
    }

    pub fn start(&mut self, side: Side) {
        self.keep_draft();
        self.side = side;
        self.snapshot = None;
        self.connected = false;
        self.running = true;
        self.next_seq = 1;
        self.sync_serial = 0;
    }

    pub fn connection(&mut self, connected: bool, running: bool) {
        if (self.connected && !connected) || (self.running && !running) {
            self.keep_draft();
        }
        self.connected = connected;
        self.running = running;
    }

    pub fn set_text(&mut self, text: String) -> Result<(), &'static str> {
        if !self.can_edit() {
            return Err("Take editing control before changing the shared note.");
        }
        validate_note(&text)?;
        if text != self.text {
            self.text = text;
            self.dirty = true;
        }
        Ok(())
    }

    pub fn prepare_edit(&mut self) -> Option<Edit> {
        if !self.can_edit() || !self.dirty || self.in_flight.is_some() {
            return None;
        }
        let snapshot = self.snapshot.as_ref()?;
        let edit = Edit {
            epoch: snapshot.epoch,
            base_revision: snapshot.revision,
            seq: self.next_seq,
            text: self.text.clone(),
        };
        self.next_seq += 1;
        self.in_flight = Some(edit.clone());
        self.dirty = false;
        Some(edit)
    }

    pub fn enqueue_failed(&mut self) {
        self.in_flight = None;
        self.dirty = true;
    }

    pub fn receive(&mut self, snapshot: Snapshot, sync_serial: u64) {
        let reset = self.sync_serial != sync_serial
            || self
                .snapshot
                .as_ref()
                .is_none_or(|old| old.epoch != snapshot.epoch);
        if reset {
            // Even if an unacknowledged edit made it to the host, keep its draft;
            // the UI cannot establish that until it has received the receipt.
            self.keep_draft();
            self.text = snapshot.text.clone();
        } else if let Some(pending) = &self.in_flight {
            let receipt = snapshot.receipts[self.side.index()];
            if receipt.seq == pending.seq {
                if receipt.accepted {
                    self.in_flight = None;
                    if !self.dirty {
                        self.text = snapshot.text.clone();
                    }
                } else {
                    self.keep_draft();
                    self.text = snapshot.text.clone();
                }
            }
        } else if !self.dirty {
            self.text = snapshot.text.clone();
        }
        self.sync_serial = sync_serial;
        self.snapshot = Some(snapshot);
    }

    pub fn restore_draft(&mut self, index: usize) -> Result<(), &'static str> {
        if self.has_unsent() {
            return Err("Wait for the current edit to synchronize first.");
        }
        if !self.running
            || (self.side == Side::Peer && !self.connected)
            || self.snapshot.as_ref().is_none_or(|s| s.owner != self.side)
        {
            return Err("Take Control before restoring a draft.");
        }
        if index >= self.drafts.len() {
            return Err("Draft no longer exists.");
        }
        self.text = self.drafts.remove(index);
        self.dirty = true;
        Ok(())
    }
}
