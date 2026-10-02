use pair::{
    cli::{self, Control, Invocation, Preferences, Request, Response},
    discovery::DiscoveredDevice,
};
use std::{fs, path::PathBuf, thread, time::Duration};

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pair-cli-test-{}-{}",
            std::process::id(),
            pair::tls::hex(&pair::tls::random_bytes::<8>().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn commands_and_ambiguous_names_require_an_explicit_device() {
    let args = ["connect".into(), "Jetson desk".into()];
    assert!(
        matches!(cli::parse(&args).unwrap(), Invocation::Application(Request::Connect(name)) if name == "Jetson desk")
    );
    assert!(matches!(
        cli::parse(&["pair".into(), "jetson".into()]).unwrap(),
        Invocation::Application(Request::Pair(_))
    ));
    assert!(cli::parse(&["connect".into()]).is_err());
    let devices = vec![
        DiscoveredDevice {
            id: "aa".repeat(16),
            name: "Jetson".into(),
            addresses: vec![],
        },
        DiscoveredDevice {
            id: "bb".repeat(16),
            name: "Jetson".into(),
            addresses: vec![],
        },
    ];
    let mut preferences = Preferences::default();
    let error = cli::resolve_device("Jetson", &preferences, &devices)
        .err()
        .unwrap();
    assert!(error.contains(&devices[0].id) && error.contains(&devices[1].id));
    preferences.set_alias("desk", &devices[1].id).unwrap();
    assert_eq!(
        cli::resolve_device("DESK", &preferences, &devices)
            .unwrap()
            .id,
        devices[1].id
    );
    assert_eq!(
        cli::resolve_device(&devices[0].id, &preferences, &devices)
            .unwrap()
            .id,
        devices[0].id
    );
}

#[test]
fn preferences_persist_without_touching_trusted_storage() {
    let temporary = Temporary::new();
    let state = temporary.0.join("state.json");
    fs::write(&state, b"existing trusted credentials").unwrap();
    let mut preferences = Preferences::load(&temporary.0).unwrap();
    assert!(!preferences.auto_reconnect);
    preferences.set_alias("Jetson", &"aa".repeat(16)).unwrap();
    assert!(preferences.set_alias("JETSON", &"bb".repeat(16)).is_err());
    assert!(
        preferences
            .set_alias("bad alias", &"aa".repeat(16))
            .is_err()
    );
    preferences.auto_reconnect = true;
    preferences.save(&temporary.0).unwrap();
    let loaded = Preferences::load(&temporary.0).unwrap();
    assert!(loaded.auto_reconnect);
    assert_eq!(loaded.aliases["jetson"], "aa".repeat(16));
    assert_eq!(fs::read(state).unwrap(), b"existing trusted credentials");
    assert!(
        !fs::read_to_string(temporary.0.join("preferences.json"))
            .unwrap()
            .contains("credentials")
    );
}

#[test]
fn handoff_authenticates_and_recovers_a_stale_record() {
    let temporary = Temporary::new();
    fs::write(temporary.0.join("control.json"), b"stale endpoint").unwrap();
    let control = Control::claim(&temporary.0, || {}).unwrap();
    assert!(Control::claim(&temporary.0, || {}).is_err());
    let record = fs::read(temporary.0.join("control.json")).unwrap();
    let mut invalid: serde_json::Value = serde_json::from_slice(&record).unwrap();
    invalid["capability"] = "invalid".into();
    fs::write(
        temporary.0.join("control.json"),
        serde_json::to_vec(&invalid).unwrap(),
    )
    .unwrap();
    assert!(!cli::send(&temporary.0, &Request::Status).unwrap().ok);
    assert!(control.incoming.try_recv().is_err());
    fs::write(temporary.0.join("control.json"), &record).unwrap();
    let directory = temporary.0.clone();
    let sender = thread::spawn(move || cli::send(&directory, &Request::Open).unwrap());
    let incoming = control
        .incoming
        .recv_timeout(Duration::from_secs(3))
        .unwrap();
    assert_eq!(incoming.request, Request::Open);
    incoming
        .reply
        .send(Response::from_result(Ok("Request accepted".into())))
        .unwrap();
    assert!(sender.join().unwrap().ok);
    drop(control);
    fs::write(temporary.0.join("control.json"), record).unwrap();
    assert!(cli::send(&temporary.0, &Request::Status).is_err());
    let replacement = Control::claim(&temporary.0, || {}).unwrap();
    drop(replacement);
    assert!(!temporary.0.join("control.json").exists());
}

#[test]
fn active_sessions_require_confirmation_only_when_switching() {
    assert!(!cli::requires_switch(false, None, Some("jetson"), false));
    assert!(!cli::requires_switch(
        true,
        Some("jetson"),
        Some("jetson"),
        false
    ));
    assert!(cli::requires_switch(
        true,
        Some("desktop"),
        Some("jetson"),
        false
    ));
    assert!(cli::requires_switch(true, None, Some("jetson"), true));
    assert!(cli::requires_switch(true, None, None, false));
}

#[test]
fn auto_reconnect_requires_opt_in_and_respects_session_suppression() {
    assert!(cli::should_auto_reconnect(
        true,
        false,
        false,
        Some("jetson"),
        "jetson"
    ));
    assert!(!cli::should_auto_reconnect(
        false,
        false,
        false,
        Some("jetson"),
        "jetson"
    ));
    assert!(!cli::should_auto_reconnect(
        true,
        true,
        false,
        Some("jetson"),
        "jetson"
    ));
    assert!(!cli::should_auto_reconnect(
        true,
        false,
        true,
        Some("jetson"),
        "jetson"
    ));
    assert!(!cli::should_auto_reconnect(
        true,
        false,
        false,
        Some("jetson"),
        "desktop"
    ));
    assert!(!cli::should_auto_reconnect(
        true, false, false, None, "jetson"
    ));
}
