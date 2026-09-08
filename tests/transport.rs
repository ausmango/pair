use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use pair::{
    editor::Editor,
    network::{
        Command, ConnectTarget, Mode, Network, View, accept_authenticated, connect_authenticated,
        connect_authenticated_first, connect_provisional,
    },
    persistence::{DeviceIdentity, Store},
    protocol::{MAX_FRAME_BYTES, Message, read_frame, write_frame},
    state::{Authority, Edit, Side, Snapshot},
    tls::{Identity, Pairing, random_bytes},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_rustls::TlsStream;

const DEADLINE: Duration = Duration::from_secs(10);
static NEXT: AtomicU64 = AtomicU64::new(1);

fn store(label: &str) -> Store {
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "pair-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let path = directory.join("state.json");
    let _ = std::fs::remove_dir_all(&directory);
    Store::load(path).unwrap()
}

async fn wait_view(network: &mut Network, predicate: impl Fn(&View) -> bool) -> View {
    timeout(DEADLINE, async {
        loop {
            let view = network.updates.borrow_and_update().clone();
            if predicate(&view) {
                return view;
            }
            network
                .updates
                .changed()
                .await
                .expect("network worker stopped unexpectedly");
        }
    })
    .await
    .expect("network state deadline")
}

async fn next_state(stream: &mut TlsStream<TcpStream>) -> Snapshot {
    timeout(DEADLINE, async {
        loop {
            match read_frame(stream, MAX_FRAME_BYTES).await.unwrap() {
                Message::State { snapshot } => return snapshot,
                Message::Ping {} => write_frame(stream, &Message::Pong {}).await.unwrap(),
                Message::Pong {} => {}
                _ => panic!("unexpected message"),
            }
        }
    })
    .await
    .expect("state frame deadline")
}

fn edit(snapshot: &Snapshot, seq: u64, text: &str) -> Edit {
    Edit {
        epoch: snapshot.epoch,
        base_revision: snapshot.revision,
        seq,
        text: text.into(),
    }
}

#[tokio::test]
async fn first_pairing_requires_both_confirmations_then_reconnects_with_saved_trust() {
    let host_store = store("host-pair");
    let client_store = store("client-pair");
    let mut host = Network::start(
        Mode::Host {
            address: "127.0.0.1:0".parse().unwrap(),
            text: "secret note".into(),
            store: host_store.clone(),
        },
        || {},
    )
    .unwrap();
    let address = wait_view(&mut host, |view| view.bound_address.is_some())
        .await
        .bound_address
        .unwrap();
    let mut client = Network::start(
        Mode::Connect {
            target: ConnectTarget {
                addresses: vec![address],
                id: None,
                name: None,
                pairing: None,
            },
            store: client_store.clone(),
        },
        || {},
    )
    .unwrap();
    let host_prompt = wait_view(&mut host, |view| view.pairing.is_some()).await;
    let client_prompt = wait_view(&mut client, |view| view.pairing.is_some()).await;
    assert_eq!(
        host_prompt.pairing.as_ref().unwrap().phrase,
        client_prompt.pairing.as_ref().unwrap().phrase
    );
    assert!(
        client_prompt.snapshot.is_none(),
        "unverified client received note state"
    );
    host.commands.send(Command::ConfirmPairing).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !client.updates.borrow().connected,
        "one confirmation authenticated the client"
    );
    client.commands.send(Command::ConfirmPairing).await.unwrap();
    let connected = wait_view(&mut client, |view| view.connected).await;
    assert_eq!(connected.snapshot.unwrap().text, "secret note");
    assert!(host_store.has_trusted_peer());
    assert!(client_store.trusted_host().is_some());
    host.stop();
    client.stop();
    wait_view(&mut host, |v| !v.running).await;
    wait_view(&mut client, |v| !v.running).await;
}

#[tokio::test]
async fn rejected_pairing_saves_no_trust_and_releases_no_note() {
    let host_store = store("host-reject");
    let client_store = store("client-reject");
    let mut host = Network::start(
        Mode::Host {
            address: "127.0.0.1:0".parse().unwrap(),
            text: "never released".into(),
            store: host_store.clone(),
        },
        || {},
    )
    .unwrap();
    let address = wait_view(&mut host, |view| view.bound_address.is_some())
        .await
        .bound_address
        .unwrap();
    let mut client = Network::start(
        Mode::Connect {
            target: ConnectTarget {
                addresses: vec![address],
                id: None,
                name: None,
                pairing: None,
            },
            store: client_store.clone(),
        },
        || {},
    )
    .unwrap();
    let pending = wait_view(&mut client, |view| view.pairing.is_some()).await;
    assert!(pending.snapshot.is_none());
    client.commands.send(Command::RejectPairing).await.unwrap();
    wait_view(&mut client, |view| !view.running).await;
    wait_view(&mut host, |view| view.pairing.is_none()).await;
    assert!(!host_store.has_trusted_peer());
    assert!(client_store.trusted_host().is_none());
    host.stop();
    wait_view(&mut host, |view| !view.running).await;
}

#[tokio::test]
async fn interrupted_pairing_before_client_storage_leaves_no_host_trust() {
    let host_store = store("host-interrupted");
    let mut host = Network::start(
        Mode::Host {
            address: "127.0.0.1:0".parse().unwrap(),
            text: "private".into(),
            store: host_store.clone(),
        },
        || {},
    )
    .unwrap();
    let address = wait_view(&mut host, |view| view.bound_address.is_some())
        .await
        .bound_address
        .unwrap();
    let (mut stream, _) = connect_provisional(address).await.unwrap();
    write_frame(
        &mut stream,
        &Message::PairRequest {
            version: pair::protocol::VERSION,
            device_id: "44".repeat(16),
            device_name: "Interrupted".into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_frame(&mut stream, pair::protocol::MAX_PAIRING_BYTES)
            .await
            .unwrap(),
        Message::PairReady { .. }
    ));
    write_frame(&mut stream, &Message::PairConfirm {})
        .await
        .unwrap();
    wait_view(&mut host, |view| {
        view.pairing.as_ref().is_some_and(|p| p.peer_confirmed)
    })
    .await;
    host.commands.send(Command::ConfirmPairing).await.unwrap();
    assert!(matches!(
        read_frame(&mut stream, pair::protocol::MAX_PAIRING_BYTES)
            .await
            .unwrap(),
        Message::PairGranted { .. }
    ));
    drop(stream);
    wait_view(&mut host, |view| view.pairing.is_none()).await;
    assert!(!host_store.has_trusted_peer());
    host.stop();
    wait_view(&mut host, |view| !view.running).await;
}

#[tokio::test]
async fn authenticated_host_enforces_ownership_and_reconnect_sends_latest_state() {
    let host_store = store("host-auth");
    let token = random_bytes().unwrap();
    host_store
        .trust_peer(
            DeviceIdentity {
                id: "11".repeat(16),
                name: "test-peer".into(),
            },
            token,
        )
        .unwrap();
    let pairing = Pairing::new(host_store.identity().unwrap().pairing.fingerprint, token);
    let mut host = Network::start(
        Mode::Host {
            address: "127.0.0.1:0".parse().unwrap(),
            text: "initial".into(),
            store: host_store,
        },
        || {},
    )
    .unwrap();
    let address = wait_view(&mut host, |v| v.bound_address.is_some())
        .await
        .bound_address
        .unwrap();
    let mut peer = connect_authenticated(address, &pairing).await.unwrap();
    let initial = next_state(&mut peer).await;
    assert_eq!(initial.text, "initial");
    write_frame(&mut peer, &Message::TakeControl {})
        .await
        .unwrap();
    let granted = next_state(&mut peer).await;
    assert_eq!(granted.owner, Side::Peer);
    let text = "\tpython3 - <<'PY'\r\n    print('梨 🍐')\nPY\n";
    write_frame(
        &mut peer,
        &Message::Edit {
            edit: edit(&granted, 1, text),
        },
    )
    .await
    .unwrap();
    let acknowledged = next_state(&mut peer).await;
    assert_eq!(acknowledged.text, text);
    drop(peer);
    let offline = wait_view(&mut host, |v| {
        !v.connected && v.snapshot.as_ref().is_some_and(|s| s.epoch > granted.epoch)
    })
    .await;
    host.commands
        .send(Command::Edit(edit(
            offline.snapshot.as_ref().unwrap(),
            1,
            "latest host",
        )))
        .await
        .unwrap();
    wait_view(&mut host, |v| {
        v.snapshot.as_ref().is_some_and(|s| s.text == "latest host")
    })
    .await;
    let mut peer = connect_authenticated(address, &pairing).await.unwrap();
    assert_eq!(next_state(&mut peer).await.text, "latest host");
    host.stop();
    wait_view(&mut host, |v| !v.running).await;
}

#[tokio::test]
async fn incorrect_fingerprint_and_token_release_no_note() {
    for wrong_pin in [true, false] {
        let identity = Identity::generate().unwrap();
        let code = identity.pairing.code();
        let parts: Vec<_> = code.split(':').collect();
        let wrong = if wrong_pin {
            format!("pair1:{}:{}", "00".repeat(32), parts[2])
        } else {
            format!("pair1:{}:{}", parts[1], "00".repeat(32))
        };
        let pairing = Pairing::parse(&wrong).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(accept_authenticated(socket, &identity).await.is_err());
        });
        let result = connect_authenticated(address, &pairing).await;
        if wrong_pin {
            assert!(result.is_err());
        } else {
            let mut stream = result.unwrap();
            assert!(matches!(
                timeout(DEADLINE, read_frame(&mut stream, MAX_FRAME_BYTES))
                    .await
                    .unwrap()
                    .unwrap(),
                Message::AuthFailed {}
            ));
        }
        timeout(DEADLINE, server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn connection_falls_back_to_the_next_available_address() {
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let working_address = listener.local_addr().unwrap();
    let identity = Identity::generate().unwrap();
    let pairing = identity.pairing.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = accept_authenticated(socket, &identity).await.unwrap();
    });
    let (stream, selected) =
        connect_authenticated_first(&[unavailable_address, working_address], &pairing)
            .await
            .unwrap();
    assert_eq!(selected, working_address);
    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn reconnect_keeps_unsent_editor_text_as_a_draft() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = Identity::generate().unwrap();
    let pairing = identity.pairing.clone();
    let (disconnect, disconnected) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut authority = Authority::new("old host".into()).unwrap();
        authority.take_control(Side::Peer);
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = accept_authenticated(socket, &identity).await.unwrap();
        write_frame(
            &mut stream,
            &Message::State {
                snapshot: authority.snapshot.clone(),
            },
        )
        .await
        .unwrap();
        disconnected.await.unwrap();
        drop(stream);
        authority.connection_changed();
        authority.edit(Side::Host, edit(&authority.snapshot, 1, "new host state"));
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = accept_authenticated(socket, &identity).await.unwrap();
        write_frame(
            &mut stream,
            &Message::State {
                snapshot: authority.snapshot,
            },
        )
        .await
        .unwrap();
        finished.await.unwrap();
    });
    let client_store = store("reconnect");
    let mut client = Network::start(
        Mode::Connect {
            target: ConnectTarget {
                addresses: vec![address],
                id: None,
                name: None,
                pairing: Some(pairing),
            },
            store: client_store,
        },
        || {},
    )
    .unwrap();
    let first = wait_view(&mut client, |v| v.connected).await;
    let mut editor = Editor::default();
    editor.start(Side::Peer);
    editor.connection(true, true);
    editor.receive(first.snapshot.unwrap(), first.sync_serial);
    editor
        .set_text("unsent local script\n\techo '梨'".into())
        .unwrap();
    disconnect.send(()).unwrap();
    let reconnected = wait_view(&mut client, |v| v.connected && v.sync_serial == 2).await;
    editor.receive(reconnected.snapshot.unwrap(), reconnected.sync_serial);
    assert_eq!(editor.text, "new host state");
    assert_eq!(editor.drafts, vec!["unsent local script\n\techo '梨'"]);
    client.stop();
    finish.send(()).unwrap();
    timeout(DEADLINE, server).await.unwrap().unwrap();
    wait_view(&mut client, |v| !v.running).await;
}

#[test]
fn pairing_code_parser_remains_strict() {
    let one = Identity::generate().unwrap();
    let two = Identity::generate().unwrap();
    assert_ne!(one.pairing.code(), two.pairing.code());
    let parsed = Pairing::parse(&one.pairing.code()).unwrap();
    assert!(parsed.authenticates(&one.pairing.token()));
    assert!(!parsed.authenticates(&two.pairing.token()));
    for code in [
        "",
        "pair2:a:b",
        "pair1:a:b",
        "pair1:🍐:secret",
        "pair1:a:b:c",
    ] {
        assert!(Pairing::parse(code).is_err());
    }
}
