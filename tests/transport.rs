use std::{net::SocketAddr, time::Duration};

use pair::{
    editor::Editor,
    network::{Command, Mode, Network, View, accept_authenticated, connect_authenticated},
    protocol::{MAX_FRAME_BYTES, Message, read_frame, write_frame},
    state::{Authority, Edit, Side, Snapshot},
    tls::{Identity, Pairing},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_rustls::TlsStream;

const DEADLINE: Duration = Duration::from_secs(10);

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
async fn real_tls_host_enforces_ownership_and_reconnect_sends_latest_state() {
    let mut host = Network::start(
        Mode::Host {
            address: "127.0.0.1:0".parse().unwrap(),
            text: "initial".into(),
        },
        || {},
    )
    .unwrap();
    let view = wait_view(&mut host, |v| v.pairing_code.is_some()).await;
    let address = view.bound_address.unwrap();
    let pairing = Pairing::parse(view.pairing_code.as_ref().unwrap()).unwrap();
    let mut peer = connect_authenticated(address, &pairing).await.unwrap();
    let initial = next_state(&mut peer).await;
    assert_eq!(initial.text, "initial");
    assert_eq!(initial.owner, Side::Host);
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
    assert!(acknowledged.receipts[1].accepted);
    host.commands.try_send(Command::TakeControl).unwrap();
    let reclaimed = next_state(&mut peer).await;
    assert_eq!(reclaimed.owner, Side::Host);
    write_frame(
        &mut peer,
        &Message::Edit {
            edit: edit(&acknowledged, 2, "stale peer work"),
        },
    )
    .await
    .unwrap();
    let rejected = next_state(&mut peer).await;
    assert_eq!(rejected.text, text);
    assert!(!rejected.receipts[1].accepted);
    drop(peer);
    let offline = wait_view(&mut host, |v| {
        !v.connected
            && v.snapshot
                .as_ref()
                .is_some_and(|s| s.epoch > reclaimed.epoch)
    })
    .await;
    host.commands
        .try_send(Command::Edit(edit(
            offline.snapshot.as_ref().unwrap(),
            1,
            "edited while offline",
        )))
        .unwrap();
    wait_view(&mut host, |v| {
        v.snapshot
            .as_ref()
            .is_some_and(|s| s.text == "edited while offline")
    })
    .await;
    let mut reconnected = connect_authenticated(address, &pairing).await.unwrap();
    let latest = next_state(&mut reconnected).await;
    assert_eq!(latest.text, "edited while offline");
    assert_eq!(latest.owner, Side::Host);
    assert_eq!(latest.receipts[1].seq, 0);
    host.stop();
    wait_view(&mut host, |v| !v.running).await;
}

#[tokio::test]
async fn incorrect_fingerprint_fails_tls_and_incorrect_token_receives_no_note() {
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
async fn client_automatically_reconnects_and_editor_recovers_an_unsent_draft() {
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
    let mut client = Network::start(Mode::Connect { address, pairing }, || {}).unwrap();
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
    assert!(editor.prepare_edit().is_none());
    client.stop();
    finish.send(()).unwrap();
    timeout(DEADLINE, server).await.unwrap().unwrap();
    wait_view(&mut client, |v| !v.running).await;
}

#[tokio::test]
async fn a_second_peer_cannot_displace_the_current_connection() {
    let mut host = Network::start(
        Mode::Host {
            address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            text: String::new(),
        },
        || {},
    )
    .unwrap();
    let view = wait_view(&mut host, |v| v.pairing_code.is_some()).await;
    let pairing = Pairing::parse(view.pairing_code.as_ref().unwrap()).unwrap();
    let address = view.bound_address.unwrap();
    let mut first = connect_authenticated(address, &pairing).await.unwrap();
    next_state(&mut first).await;
    assert!(connect_authenticated(address, &pairing).await.is_err());
    write_frame(&mut first, &Message::TakeControl {})
        .await
        .unwrap();
    assert_eq!(next_state(&mut first).await.owner, Side::Peer);
    host.stop();
    wait_view(&mut host, |v| !v.running).await;
}

#[test]
fn pairing_code_parser_is_strict_and_generated_secrets_are_distinct() {
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
