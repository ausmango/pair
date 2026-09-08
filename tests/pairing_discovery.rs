use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use pair::{
    discovery::{DiscoveryCatalog, MAX_DISCOVERED},
    persistence::{DeviceIdentity, Store, valid_name},
    tls::{Identity, safety_phrase},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn location(label: &str) -> (PathBuf, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "pair-test-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    (directory.join("state.json"), directory)
}

#[test]
fn identity_and_trust_survive_reload_without_storing_notes() {
    let (path, directory) = location("persistence");
    let store = Store::load(path.clone()).unwrap();
    let original = store.identity().unwrap();
    store.set_name("Research Jetson").unwrap();
    store
        .trust_peer(
            DeviceIdentity {
                id: "12".repeat(16),
                name: "Laptop".into(),
            },
            [7; 32],
        )
        .unwrap();
    let host_identity = Identity::generate().unwrap();
    let address: SocketAddr = "192.168.1.20:47321".parse().unwrap();
    store
        .trust_host(
            "34".repeat(16),
            "Main PC".into(),
            address,
            host_identity.pairing.clone(),
        )
        .unwrap();

    let reloaded = Store::load(path.clone()).unwrap();
    assert_eq!(reloaded.device().name, "Research Jetson");
    assert_eq!(
        reloaded.identity().unwrap().pairing.fingerprint,
        original.pairing.fingerprint
    );
    assert!(reloaded.has_trusted_peer());
    let trusted = reloaded.trusted_host().unwrap();
    assert_eq!(trusted.address, address);
    assert_eq!(
        trusted.pairing.fingerprint,
        host_identity.pairing.fingerprint
    );
    let persisted = std::fs::read_to_string(path).unwrap();
    assert!(!persisted.contains("note"));
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn forgetting_revokes_tokens_and_corrupt_settings_fail_closed() {
    let (path, directory) = location("forget");
    let store = Store::load(path.clone()).unwrap();
    store
        .trust_peer(
            DeviceIdentity {
                id: "56".repeat(16),
                name: "Peer".into(),
            },
            [9; 32],
        )
        .unwrap();
    let old = store.identity().unwrap().pairing;
    store.forget_peer().unwrap();
    let new = store.identity().unwrap().pairing;
    assert!(!new.authenticates(&old.token()));
    assert!(!store.has_trusted_peer());
    std::fs::write(&path, b"{broken").unwrap();
    assert!(Store::load(path).is_err());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn resetting_host_identity_changes_the_certificate_and_clears_peer_trust() {
    let (path, directory) = location("reset");
    let store = Store::load(path).unwrap();
    store
        .trust_peer(
            DeviceIdentity {
                id: "78".repeat(16),
                name: "Peer".into(),
            },
            [3; 32],
        )
        .unwrap();
    let old = store.identity().unwrap().pairing;
    store.reset_host_identity().unwrap();
    let new = store.identity().unwrap().pairing;
    assert_ne!(old.fingerprint, new.fingerprint);
    assert!(!store.has_trusted_peer());
    let _ = std::fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[test]
fn settings_permissions_are_private_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let (path, directory) = location("permissions");
    Store::load(path.clone()).unwrap();
    assert_eq!(
        std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn discovery_filters_limits_deduplicates_and_expires_entries() {
    let mut catalog = DiscoveryCatalog::default();
    let now = Instant::now();
    for index in 0..MAX_DISCOVERED {
        let id = format!("{:032x}", index + 1);
        let address = format!("192.168.1.{}:47321", index + 1).parse().unwrap();
        assert!(catalog.resolve(
            format!("{id}._pair._tcp.local."),
            &id,
            "Pair host",
            address,
            2,
            now
        ));
    }
    assert_eq!(catalog.devices().len(), MAX_DISCOVERED);
    assert!(!catalog.resolve(
        "extra._pair._tcp.local.".into(),
        &"ff".repeat(16),
        "Extra",
        "192.168.2.2:47321".parse().unwrap(),
        2,
        now
    ));
    assert!(!catalog.resolve(
        "old._pair._tcp.local.".into(),
        &"ee".repeat(16),
        "Old",
        "192.168.2.3:47321".parse().unwrap(),
        1,
        now
    ));
    assert!(catalog.prune(now + Duration::from_secs(121)));
    assert!(catalog.devices().is_empty());
}

#[test]
fn safety_phrase_is_stable_six_words_and_changes_with_fingerprint() {
    let one = [0x12; 32];
    let mut two = one;
    two[5] ^= 1;
    let phrase = safety_phrase(&one);
    assert_eq!(phrase.split_whitespace().count(), 6);
    assert_eq!(phrase, safety_phrase(&one));
    assert_ne!(phrase, safety_phrase(&two));
}

#[test]
fn device_names_reject_controls_and_choice_separators() {
    assert!(valid_name("Jetson Nano"));
    assert!(valid_name("研究电脑"));
    assert!(!valid_name("bad|choice"));
    assert!(!valid_name("bad\nname"));
    assert!(!valid_name(&"x".repeat(33)));
}
