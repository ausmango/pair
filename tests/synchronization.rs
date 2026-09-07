use pair::{
    editor::{Editor, MAX_DRAFTS},
    state::{Authority, Edit, Side},
};

fn setup() -> (Authority, Editor) {
    let mut host = Authority::new("host state".into()).unwrap();
    host.connection_changed();
    host.take_control(Side::Peer);
    let mut editor = Editor::default();
    editor.start(Side::Peer);
    editor.connection(true, true);
    editor.receive(host.snapshot.clone(), 1);
    (host, editor)
}

#[test]
fn only_the_host_granted_owner_can_edit_and_old_epochs_cannot_return() {
    let mut host = Authority::new("original".into()).unwrap();
    let edit = Edit {
        epoch: 1,
        base_revision: 0,
        seq: 1,
        text: "unauthorized".into(),
    };
    assert!(!host.edit(Side::Peer, edit));
    assert_eq!(host.snapshot.text, "original");
    host.take_control(Side::Peer);
    let old_epoch = host.snapshot.epoch;
    host.take_control(Side::Host);
    host.take_control(Side::Peer);
    assert!(!host.edit(
        Side::Peer,
        Edit {
            epoch: old_epoch,
            base_revision: 0,
            seq: 2,
            text: "stale".into()
        }
    ));
    assert_eq!(host.snapshot.text, "original");
    assert!(host.edit(
        Side::Peer,
        Edit {
            epoch: host.snapshot.epoch,
            base_revision: 0,
            seq: 3,
            text: "authorized".into()
        }
    ));
    assert_eq!(host.snapshot.text, "authorized");
}

#[test]
fn revisions_replays_and_invalid_notes_cannot_replace_host_state() {
    let mut host = Authority::new(String::new()).unwrap();
    let valid = Edit {
        epoch: 1,
        base_revision: 0,
        seq: 1,
        text: "accepted".into(),
    };
    assert!(host.edit(Side::Host, valid.clone()));
    assert!(!host.edit(Side::Host, valid));
    assert!(!host.edit(
        Side::Host,
        Edit {
            epoch: 1,
            base_revision: 0,
            seq: 2,
            text: "stale revision".into()
        }
    ));
    assert!(!host.edit(
        Side::Host,
        Edit {
            epoch: 1,
            base_revision: 1,
            seq: 3,
            text: "bad\0text".into()
        }
    ));
    assert_eq!(host.snapshot.text, "accepted");
    assert_eq!(host.snapshot.revision, 1);
}

#[test]
fn keystrokes_during_an_in_flight_edit_survive_acknowledgement() {
    let (mut host, mut editor) = setup();
    editor.set_text("first".into()).unwrap();
    let first = editor.prepare_edit().unwrap();
    editor.set_text("first + second".into()).unwrap();
    assert!(editor.prepare_edit().is_none());
    assert!(host.edit(Side::Peer, first));
    editor.receive(host.snapshot.clone(), 1);
    assert_eq!(editor.text, "first + second");
    assert!(host.edit(Side::Peer, editor.prepare_edit().unwrap()));
    editor.receive(host.snapshot.clone(), 1);
    assert!(!editor.has_unsent());
    assert_eq!(host.snapshot.text, "first + second");
    assert!(editor.drafts.is_empty());
}

#[test]
fn losing_control_before_debounce_keeps_a_recoverable_draft() {
    let (mut host, mut editor) = setup();
    editor.set_text("unsent\n\t梨".into()).unwrap();
    host.take_control(Side::Host);
    editor.receive(host.snapshot.clone(), 1);
    assert!(!editor.can_edit());
    assert_eq!(editor.text, "host state");
    assert_eq!(editor.drafts, vec!["unsent\n\t梨"]);
    assert!(editor.prepare_edit().is_none());
    assert!(editor.restore_draft(0).is_err());
    host.take_control(Side::Peer);
    editor.receive(host.snapshot.clone(), 1);
    editor.restore_draft(0).unwrap();
    assert!(host.edit(Side::Peer, editor.prepare_edit().unwrap()));
    assert_eq!(host.snapshot.text, "unsent\n\t梨");
}

#[test]
fn rejected_edit_is_preserved_and_never_automatically_overwrites_host() {
    let (mut host, mut editor) = setup();
    editor.set_text("local draft".into()).unwrap();
    let mut edit = editor.prepare_edit().unwrap();
    edit.base_revision = 99;
    assert!(!host.edit(Side::Peer, edit));
    editor.receive(host.snapshot.clone(), 1);
    assert_eq!(editor.text, "host state");
    assert_eq!(editor.drafts, vec!["local draft"]);
    assert!(!editor.has_unsent());
}

#[test]
fn reconnect_adopts_latest_host_state_and_preserves_unacknowledged_text() {
    let (mut host, mut editor) = setup();
    editor.set_text("unacknowledged".into()).unwrap();
    let in_flight = editor.prepare_edit().unwrap();
    // It may or may not have reached the host before the cable was pulled.
    assert!(host.edit(Side::Peer, in_flight));
    editor.connection(false, true);
    assert_eq!(editor.drafts, vec!["unacknowledged"]);
    host.connection_changed();
    assert!(host.edit(
        Side::Host,
        Edit {
            epoch: host.snapshot.epoch,
            base_revision: host.snapshot.revision,
            seq: 1,
            text: "latest host".into()
        }
    ));
    host.connection_changed();
    editor.connection(true, true);
    editor.receive(host.snapshot.clone(), 2);
    assert_eq!(editor.text, "latest host");
    assert_eq!(editor.drafts, vec!["unacknowledged"]);
    assert!(!editor.can_edit());
    assert!(editor.prepare_edit().is_none());
}

#[test]
fn coalesced_notifications_cannot_hide_reconnection_or_lose_draft() {
    let (mut host, mut editor) = setup();
    editor.set_text("not yet sent".into()).unwrap();
    host.connection_changed();
    host.connection_changed();
    // watch channels deliberately retain only the latest state. The UI may
    // never see the disconnected notification, but must still retain its edit.
    editor.receive(host.snapshot.clone(), 2);
    assert_eq!(editor.text, "host state");
    assert_eq!(editor.drafts, vec!["not yet sent"]);
}

#[test]
fn draft_storage_is_bounded_by_stopping_edits_instead_of_evicting_text() {
    let (mut host, mut editor) = setup();
    for index in 0..MAX_DRAFTS {
        host.take_control(Side::Peer);
        editor.receive(host.snapshot.clone(), 1);
        editor.set_text(format!("draft {index}")).unwrap();
        host.take_control(Side::Host);
        editor.receive(host.snapshot.clone(), 1);
    }
    assert_eq!(editor.drafts.len(), MAX_DRAFTS);
    host.take_control(Side::Peer);
    editor.receive(host.snapshot.clone(), 1);
    assert!(!editor.can_edit());
    assert!(
        editor
            .set_text("would require a ninth slot".into())
            .is_err()
    );
    editor.restore_draft(0).unwrap();
    assert_eq!(editor.drafts.len(), MAX_DRAFTS - 1);
    assert!(editor.can_edit());
}
