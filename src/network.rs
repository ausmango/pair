use std::{io, net::SocketAddr, sync::Arc, thread, time::Duration};

use tokio::{
    io::{AsyncWrite, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{self, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    discovery::Advertiser,
    persistence::{DeviceIdentity, Store},
    protocol::{MAX_FRAME_BYTES, MAX_PAIRING_BYTES, Message, VERSION, read_frame, write_frame},
    state::{Authority, Edit, Side, Snapshot},
    tls::{
        Identity, Pairing, certificate_fingerprint, client_config, hex, provisional_client_config,
        random_bytes, safety_phrase,
    },
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const HEARTBEAT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct ConnectTarget {
    pub address: SocketAddr,
    pub id: Option<String>,
    pub name: Option<String>,
    pub pairing: Option<Pairing>,
}

pub enum Mode {
    Host {
        address: SocketAddr,
        text: String,
        store: Store,
    },
    Connect {
        target: ConnectTarget,
        store: Store,
    },
}

pub enum Command {
    Edit(Edit),
    TakeControl,
    ConfirmPairing,
    RejectPairing,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PairingPrompt {
    pub phrase: String,
    pub fingerprint: String,
    pub other_name: String,
    pub local_confirmed: bool,
    pub peer_confirmed: bool,
}

#[derive(Clone)]
pub struct View {
    pub running: bool,
    pub connected: bool,
    pub status: String,
    pub bound_address: Option<SocketAddr>,
    pub snapshot: Option<Snapshot>,
    pub sync_serial: u64,
    pub pairing: Option<PairingPrompt>,
}

impl Default for View {
    fn default() -> Self {
        Self {
            running: true,
            connected: false,
            status: "Starting...".into(),
            bound_address: None,
            snapshot: None,
            sync_serial: 0,
            pairing: None,
        }
    }
}

pub struct Network {
    pub commands: mpsc::Sender<Command>,
    pub updates: watch::Receiver<View>,
    stop: watch::Sender<bool>,
}

impl Network {
    pub fn start(mode: Mode, wake: impl Fn() + Send + Sync + 'static) -> io::Result<Self> {
        let (commands, rx) = mpsc::channel(8);
        let (updates, view_rx) = watch::channel(View::default());
        let (stop, mut stopped) = watch::channel(false);
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(wake);
        thread::Builder::new().name("pair-network".into()).spawn(move || {
            let mut publisher = Publisher { tx: updates, view: View::default(), wake };
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(async {
                    let result = tokio::select! { _ = stopped.changed() => Ok(()), result = run(mode, rx, &mut publisher) => result };
                    publisher.view.running = false;
                    publisher.view.connected = false;
                    publisher.view.pairing = None;
                    publisher.view.status = result.err().unwrap_or_else(|| "Stopped.".into());
                    publisher.publish();
                }),
                Err(_) => { publisher.view.running = false; publisher.view.status = "Could not start the networking runtime.".into(); publisher.publish(); }
            }
        })?;
        Ok(Self {
            commands,
            updates: view_rx,
            stop,
        })
    }
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Publisher {
    tx: watch::Sender<View>,
    view: View,
    wake: Arc<dyn Fn() + Send + Sync>,
}
impl Publisher {
    fn publish(&self) {
        self.tx.send_replace(self.view.clone());
        (self.wake)();
    }
    fn state(&mut self, authority: &Authority) {
        self.view.snapshot = Some(authority.snapshot.clone());
        self.publish();
    }
    fn prompt(&mut self, prompt: Option<PairingPrompt>) {
        self.view.pairing = prompt;
        self.publish();
    }
}

fn io_message(error: io::Error) -> String {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => {
            "Connection refused. Check the host, port, and firewall."
        }
        io::ErrorKind::AddrInUse => {
            "Address/port is already in use. Stop the other host or choose another port."
        }
        io::ErrorKind::AddrNotAvailable => "That address does not belong to this computer.",
        io::ErrorKind::PermissionDenied => {
            "Network access denied. Check firewall permissions and use a port above 1024."
        }
        io::ErrorKind::TimedOut => {
            "Connection timed out. Check the local network and host firewall."
        }
        io::ErrorKind::InvalidData => "Invalid protocol data received. The connection was closed.",
        _ => "Connection lost or closed by the other computer.",
    }
    .into()
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, message: &Message) -> Result<(), String> {
    timeout(IO_TIMEOUT, write_frame(writer, message))
        .await
        .map_err(|_| "The other computer stopped receiving data.".to_string())?
        .map_err(io_message)
}

async fn accept_tls(
    socket: TcpStream,
    identity: &Identity,
) -> Result<TlsStream<TcpStream>, String> {
    socket.set_nodelay(true).map_err(io_message)?;
    timeout(
        IO_TIMEOUT,
        TlsAcceptor::from(identity.config.clone()).accept(socket),
    )
    .await
    .map_err(|_| "TLS handshake timed out.".to_string())?
    .map(TlsStream::from)
    .map_err(|_| "TLS handshake failed.".to_string())
}

pub async fn accept_authenticated(
    socket: TcpStream,
    identity: &Identity,
) -> Result<TlsStream<TcpStream>, String> {
    let mut stream = accept_tls(socket, identity).await?;
    let message = timeout(IO_TIMEOUT, read_frame(&mut stream, MAX_PAIRING_BYTES))
        .await
        .map_err(|_| "Pairing timed out.".to_string())?
        .map_err(io_message)?;
    match message {
        Message::Hello { version, token }
            if version == VERSION && identity.pairing.authenticates(&token) =>
        {
            Ok(stream)
        }
        Message::Hello { version, .. } if version != VERSION => {
            let _ = send(&mut stream, &Message::VersionMismatch { expected: VERSION }).await;
            Err("Application versions do not match.".into())
        }
        _ => {
            let _ = send(&mut stream, &Message::AuthFailed {}).await;
            Err("Pairing rejected. Check the saved device and application version.".into())
        }
    }
}

pub async fn connect_authenticated(
    address: SocketAddr,
    pairing: &Pairing,
) -> Result<TlsStream<TcpStream>, String> {
    timeout(IO_TIMEOUT, async {
        let socket = TcpStream::connect(address).await.map_err(io_message)?;
        socket.set_nodelay(true).map_err(io_message)?;
        let name = rustls::pki_types::ServerName::try_from("pair.local").expect("fixed valid server name");
        let mut stream = TlsConnector::from(client_config(pairing)).connect(name, socket).await
            .map_err(|_| "TLS verification failed. The host identity may have changed; forget it only after checking the host.".to_string())?;
        send(&mut stream, &Message::Hello { version: VERSION, token: pairing.token() }).await?;
        Ok(stream.into())
    }).await.map_err(|_| "Connection timed out. Check the host, port, and firewall.".to_string())?
}

async fn connect_provisional(
    address: SocketAddr,
) -> Result<(TlsStream<TcpStream>, [u8; 32]), String> {
    timeout(IO_TIMEOUT, async {
        let socket = TcpStream::connect(address).await.map_err(io_message)?;
        socket.set_nodelay(true).map_err(io_message)?;
        let name =
            rustls::pki_types::ServerName::try_from("pair.local").expect("fixed valid server name");
        let stream = TlsConnector::from(provisional_client_config())
            .connect(name, socket)
            .await
            .map_err(|_| "Could not establish the provisional TLS pairing session.".to_string())?;
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| "Host did not provide a pairing certificate.".to_string())?;
        let fingerprint = certificate_fingerprint(cert.as_ref());
        Ok((stream.into(), fingerprint))
    })
    .await
    .map_err(|_| "Connection timed out. Check the host, port, and firewall.".to_string())?
}

struct Reader {
    rx: mpsc::Receiver<Result<Message, String>>,
    task: JoinHandle<()>,
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn split(stream: TlsStream<TcpStream>) -> (Reader, WriteHalf<TlsStream<TcpStream>>) {
    let (mut read, write) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        loop {
            let result = match timeout(IDLE_TIMEOUT, read_frame(&mut read, MAX_FRAME_BYTES)).await {
                Ok(result) => result.map_err(io_message),
                Err(_) => Err("No response from the other computer for 20 seconds.".into()),
            };
            let failed = result.is_err();
            if tx.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    (Reader { rx, task }, write)
}

fn local_command(authority: &mut Authority, command: Command) {
    match command {
        Command::Edit(edit) => {
            authority.edit(Side::Host, edit);
        }
        Command::TakeControl => authority.take_control(Side::Host),
        Command::ConfirmPairing | Command::RejectPairing => {}
    }
}

async fn send_state<W: AsyncWrite + Unpin>(
    writer: &mut W,
    authority: &Authority,
) -> Result<(), String> {
    send(
        writer,
        &Message::State {
            snapshot: authority.snapshot.clone(),
        },
    )
    .await
}

enum Incoming {
    Authenticated(TlsStream<TcpStream>),
    Pairing(TlsStream<TcpStream>, DeviceIdentity),
}

async fn accept_incoming(
    socket: TcpStream,
    identity: &Identity,
    paired: bool,
) -> Result<Incoming, String> {
    let mut stream = accept_tls(socket, identity).await?;
    let message = timeout(IO_TIMEOUT, read_frame(&mut stream, MAX_PAIRING_BYTES))
        .await
        .map_err(|_| "The connecting device did not identify itself.".to_string())?
        .map_err(io_message)?;
    match message {
        Message::Hello { version, token }
            if paired && version == VERSION && identity.pairing.authenticates(&token) =>
        {
            Ok(Incoming::Authenticated(stream))
        }
        Message::PairRequest {
            version,
            device_id,
            device_name,
        } if !paired && version == VERSION => Ok(Incoming::Pairing(
            stream,
            DeviceIdentity {
                id: device_id,
                name: device_name,
            },
        )),
        Message::Hello { version, .. } | Message::PairRequest { version, .. }
            if version != VERSION =>
        {
            let _ = send(&mut stream, &Message::VersionMismatch { expected: VERSION }).await;
            Err(format!(
                "Application version mismatch; this host uses protocol {VERSION}."
            ))
        }
        Message::PairRequest { .. } => {
            let _ = send(&mut stream, &Message::PairRejected {}).await;
            Err("Pairing rejected. Forget the saved peer first, or update both devices.".into())
        }
        _ => {
            let _ = send(&mut stream, &Message::AuthFailed {}).await;
            Err(
                "Authentication rejected. The saved token or application version does not match."
                    .into(),
            )
        }
    }
}

async fn run(
    mode: Mode,
    mut commands: mpsc::Receiver<Command>,
    publisher: &mut Publisher,
) -> Result<(), String> {
    match mode {
        Mode::Host {
            address,
            text,
            store,
        } => run_host(address, text, store, &mut commands, publisher).await,
        Mode::Connect { target, store } => {
            run_client(target, store, &mut commands, publisher).await
        }
    }
}

async fn run_host(
    address: SocketAddr,
    text: String,
    store: Store,
    commands: &mut mpsc::Receiver<Command>,
    publisher: &mut Publisher,
) -> Result<(), String> {
    let mut authority = Authority::new(text).map_err(str::to_string)?;
    let mut identity = store.identity()?;
    let listener = TcpListener::bind(address).await.map_err(io_message)?;
    let bound = listener.local_addr().map_err(io_message)?;
    publisher.view.bound_address = Some(bound);
    publisher.view.sync_serial = 1;
    publisher.state(&authority);
    loop {
        let advertiser = Advertiser::start(&store.device(), bound.port());
        publisher.view.status = match &advertiser {
            Ok(_) => format!(
                "Hosting as {}. Waiting for a nearby computer.",
                store.device().name
            ),
            Err(error) => format!("Hosting on {bound}; discovery unavailable: {error}"),
        };
        publisher.publish();
        let accepted = loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { return Ok(()) };
                    local_command(&mut authority, command); publisher.state(&authority);
                }
                accepted = listener.accept() => break accepted.map_err(io_message)?,
            }
        };
        drop(advertiser);
        match accept_incoming(accepted.0, &identity, store.has_trusted_peer()).await {
            Ok(Incoming::Authenticated(stream)) => {
                authority.connection_changed();
                publisher.view.connected = true;
                publisher.view.status = format!("Connected to {} (TLS 1.3, verified).", accepted.1);
                publisher.state(&authority);
                let result =
                    host_session(stream, &listener, commands, &mut authority, publisher).await;
                authority.connection_changed();
                publisher.view.connected = false;
                publisher.view.status = format!(
                    "{} Waiting for reconnection.",
                    result.err().unwrap_or_else(|| "Peer disconnected.".into())
                );
                publisher.state(&authority);
            }
            Ok(Incoming::Pairing(stream, peer)) => {
                let result = timeout(
                    PAIR_TIMEOUT,
                    host_pair_session(
                        stream,
                        peer,
                        &store,
                        &mut identity,
                        commands,
                        &mut authority,
                        publisher,
                    ),
                )
                .await;
                publisher.prompt(None);
                publisher.view.status = match result {
                    Ok(Ok(())) => "Pairing saved. Waiting for the verified reconnect.".into(),
                    Ok(Err(e)) => format!("{e} Still hosting."),
                    Err(_) => "Pairing expired after 60 seconds. Still hosting.".into(),
                };
                publisher.publish();
            }
            Err(error) => {
                publisher.view.status = format!("{error} Still hosting.");
                publisher.publish();
            }
        }
    }
}

async fn host_pair_session(
    stream: TlsStream<TcpStream>,
    peer: DeviceIdentity,
    store: &Store,
    identity: &mut Identity,
    commands: &mut mpsc::Receiver<Command>,
    authority: &mut Authority,
    publisher: &mut Publisher,
) -> Result<(), String> {
    let own = store.device();
    let (mut reader, mut writer) = split(stream);
    send(
        &mut writer,
        &Message::PairReady {
            host_id: own.id,
            host_name: own.name,
        },
    )
    .await?;
    let mut prompt = PairingPrompt {
        phrase: safety_phrase(&identity.pairing.fingerprint),
        fingerprint: hex(&identity.pairing.fingerprint),
        other_name: peer.name.clone(),
        local_confirmed: false,
        peer_confirmed: false,
    };
    publisher.view.status =
        "Unverified pairing: compare the phrase on both screens. No note data has been shared."
            .into();
    publisher.prompt(Some(prompt.clone()));
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::ConfirmPairing) if !prompt.local_confirmed => { prompt.local_confirmed = true; send(&mut writer, &Message::PairConfirm {}).await?; publisher.prompt(Some(prompt.clone())); }
                Some(Command::RejectPairing) => { let _ = send(&mut writer, &Message::PairRejected {}).await; return Err("Pairing rejected locally.".into()); }
                Some(command) => { local_command(authority, command); publisher.state(authority); }
                None => return Ok(()),
            },
            message = reader.rx.recv() => match message.ok_or("Pairing connection closed.")?? {
                Message::PairConfirm {} => { prompt.peer_confirmed = true; publisher.prompt(Some(prompt.clone())); }
                Message::PairRejected {} => return Err("The other computer rejected pairing.".into()),
                _ => return Err("Unexpected message during pairing.".into()),
            }
        }
        if prompt.local_confirmed && prompt.peer_confirmed {
            let token = random_bytes::<32>().map_err(str::to_string)?;
            store.trust_peer(peer.clone(), token)?;
            identity.set_token(token);
            send(&mut writer, &Message::PairGranted { token: hex(&token) }).await?;
            return Ok(());
        }
    }
}

async fn run_client(
    mut target: ConnectTarget,
    store: Store,
    commands: &mut mpsc::Receiver<Command>,
    publisher: &mut Publisher,
) -> Result<(), String> {
    if target.pairing.is_none() {
        publisher.view.status = format!("Starting unverified pairing with {}...", target.address);
        publisher.publish();
        let (pairing, id, name) = timeout(
            PAIR_TIMEOUT,
            client_pair_session(&target, &store, commands, publisher),
        )
        .await
        .map_err(|_| "Pairing expired after 60 seconds.".to_string())??;
        target.pairing = Some(pairing);
        target.id = Some(id);
        target.name = Some(name);
        publisher.prompt(None);
    }
    let pairing = target
        .pairing
        .as_ref()
        .expect("pairing established")
        .clone();
    let mut delay = 1;
    loop {
        publisher.view.status = format!("Connecting securely to {}...", target.address);
        publisher.publish();
        let result = match connect_authenticated(target.address, &pairing).await {
            Ok(stream) => client_session(stream, commands, publisher, &mut delay).await,
            Err(error) => Err(error),
        };
        publisher.view.connected = false;
        publisher.view.status = format!(
            "{} Retrying in {delay}s. Stop to change details.",
            result.err().unwrap_or_else(|| "Disconnected.".into())
        );
        publisher.publish();
        while commands.try_recv().is_ok() {}
        time::sleep(Duration::from_secs(delay)).await;
        while commands.try_recv().is_ok() {}
        delay = (delay * 2).min(5);
    }
}

async fn client_pair_session(
    target: &ConnectTarget,
    store: &Store,
    commands: &mut mpsc::Receiver<Command>,
    publisher: &mut Publisher,
) -> Result<(Pairing, String, String), String> {
    let (mut stream, fingerprint) = connect_provisional(target.address).await?;
    let device = store.device();
    send(
        &mut stream,
        &Message::PairRequest {
            version: VERSION,
            device_id: device.id,
            device_name: device.name,
        },
    )
    .await?;
    let ready = timeout(IO_TIMEOUT, read_frame(&mut stream, MAX_PAIRING_BYTES))
        .await
        .map_err(|_| "Host did not begin pairing.".to_string())?
        .map_err(io_message)?;
    let (host_id, host_name) = match ready {
        Message::PairReady { host_id, host_name } => (host_id, host_name),
        Message::VersionMismatch { expected } => {
            return Err(format!(
                "Application version mismatch; host expects protocol {expected}."
            ));
        }
        _ => return Err("Host rejected pairing or is already paired.".into()),
    };
    if target
        .id
        .as_ref()
        .is_some_and(|expected| expected != &host_id)
    {
        return Err("Discovered host identity changed before pairing.".into());
    }
    let (mut reader, mut writer) = split(stream);
    let mut prompt = PairingPrompt {
        phrase: safety_phrase(&fingerprint),
        fingerprint: hex(&fingerprint),
        other_name: host_name.clone(),
        local_confirmed: false,
        peer_confirmed: false,
    };
    publisher.view.status =
        "Unverified pairing: compare the phrase on both screens. No note data has been shared."
            .into();
    publisher.prompt(Some(prompt.clone()));
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::ConfirmPairing) if !prompt.local_confirmed => { prompt.local_confirmed = true; send(&mut writer, &Message::PairConfirm {}).await?; publisher.prompt(Some(prompt.clone())); }
                Some(Command::RejectPairing) => { let _ = send(&mut writer, &Message::PairRejected {}).await; return Err("Pairing rejected locally.".into()); }
                Some(_) => {}
                None => return Err("Pairing stopped.".into()),
            },
            message = reader.rx.recv() => match message.ok_or("Pairing connection closed.")?? {
                Message::PairConfirm {} => { prompt.peer_confirmed = true; publisher.prompt(Some(prompt.clone())); }
                Message::PairGranted { token } if prompt.local_confirmed && prompt.peer_confirmed => {
                    let pairing = Pairing::parse(&format!("pair1:{}:{token}", hex(&fingerprint))).map_err(str::to_string)?;
                    store.trust_host(host_id.clone(), host_name.clone(), target.address, pairing.clone())?;
                    return Ok((pairing, host_id, host_name));
                }
                Message::PairRejected {} => return Err("The host rejected pairing.".into()),
                _ => return Err("Unexpected message during pairing.".into()),
            }
        }
    }
}

async fn host_session(
    stream: TlsStream<TcpStream>,
    listener: &TcpListener,
    commands: &mut mpsc::Receiver<Command>,
    authority: &mut Authority,
    publisher: &mut Publisher,
) -> Result<(), String> {
    let (mut reader, mut writer) = split(stream);
    send_state(&mut writer, authority).await?;
    let mut heartbeat = time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            command = commands.recv() => { let Some(command) = command else { return Ok(()) }; local_command(authority, command); publisher.state(authority); send_state(&mut writer, authority).await?; }
            message = reader.rx.recv() => {
                match message.ok_or("Connection closed.")?? {
                    Message::Edit { edit } => { authority.edit(Side::Peer, edit); }
                    Message::TakeControl {} => authority.take_control(Side::Peer),
                    Message::Ping {} => { send(&mut writer, &Message::Pong {}).await?; continue; }
                    Message::Pong {} => continue,
                    _ => return Err("Unexpected protocol message. Connection closed.".into()),
                }
                publisher.state(authority); send_state(&mut writer, authority).await?;
            }
            _ = heartbeat.tick() => send(&mut writer, &Message::Ping {}).await?,
            extra = listener.accept() => { drop(extra.map_err(io_message)?.0); }
        }
    }
}

async fn client_session(
    mut stream: TlsStream<TcpStream>,
    commands: &mut mpsc::Receiver<Command>,
    publisher: &mut Publisher,
    delay: &mut u64,
) -> Result<(), String> {
    let first = timeout(IO_TIMEOUT, read_frame(&mut stream, MAX_FRAME_BYTES))
        .await
        .map_err(|_| "Host did not complete authentication.".to_string())?
        .map_err(io_message)?;
    let snapshot = match first {
        Message::State { snapshot } => snapshot,
        Message::VersionMismatch { expected } => {
            return Err(format!(
                "Application version mismatch; host expects protocol {expected}."
            ));
        }
        _ => {
            return Err(
                "Authentication rejected. Forget and re-pair only after checking the host.".into(),
            );
        }
    };
    while commands.try_recv().is_ok() {}
    publisher.view.sync_serial += 1;
    publisher.view.snapshot = Some(snapshot);
    publisher.view.connected = true;
    publisher.view.status = "Connected to host (TLS 1.3, pinned certificate).".into();
    publisher.publish();
    *delay = 1;
    let (mut reader, mut writer) = split(stream);
    let mut heartbeat = time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            command = commands.recv() => {
                let message = match command { Some(Command::Edit(edit)) => Message::Edit { edit }, Some(Command::TakeControl) => Message::TakeControl {}, Some(_) => continue, None => return Ok(()) };
                send(&mut writer, &message).await?;
            }
            message = reader.rx.recv() => match message.ok_or("Connection closed.")?? {
                Message::State { snapshot } => { publisher.view.snapshot = Some(snapshot); publisher.publish(); }
                Message::Ping {} => send(&mut writer, &Message::Pong {}).await?, Message::Pong {} => {},
                _ => return Err("Unexpected protocol message. Connection closed.".into()),
            },
            _ = heartbeat.tick() => send(&mut writer, &Message::Ping {}).await?,
        }
    }
}
