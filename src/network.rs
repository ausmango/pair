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
    protocol::{MAX_FRAME_BYTES, MAX_HELLO_BYTES, Message, VERSION, read_frame, write_frame},
    state::{Authority, Edit, Side, Snapshot},
    tls::{Identity, Pairing, client_config},
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const HEARTBEAT: Duration = Duration::from_secs(5);

pub enum Mode {
    Host {
        address: SocketAddr,
        text: String,
    },
    Connect {
        address: SocketAddr,
        pairing: Pairing,
    },
}

pub enum Command {
    Edit(Edit),
    TakeControl,
}

#[derive(Clone)]
pub struct View {
    pub running: bool,
    pub connected: bool,
    pub status: String,
    pub pairing_code: Option<String>,
    pub bound_address: Option<SocketAddr>,
    pub snapshot: Option<Snapshot>,
    /// Advances on every successful client connection. Old unacknowledged
    /// work must never be submitted against a new connection's snapshot.
    pub sync_serial: u64,
}

impl Default for View {
    fn default() -> Self {
        Self {
            running: true,
            connected: false,
            status: "Starting...".into(),
            pairing_code: None,
            bound_address: None,
            snapshot: None,
            sync_serial: 0,
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
        thread::Builder::new()
            .name("pair-network".into())
            .spawn(move || {
                let mut publisher = Publisher {
                    tx: updates,
                    view: View::default(),
                    wake,
                };
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(async {
                        let result = tokio::select! {
                            _ = stopped.changed() => Ok(()),
                            result = run(mode, rx, &mut publisher) => result,
                        };
                        publisher.view.running = false;
                        publisher.view.connected = false;
                        publisher.view.status = result.err().unwrap_or_else(|| "Stopped.".into());
                        publisher.publish();
                    }),
                    Err(_) => {
                        publisher.view.running = false;
                        publisher.view.status = "Could not start the networking runtime.".into();
                        publisher.publish();
                    }
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
}

fn io_message(error: io::Error) -> String {
    // Never display raw TLS/JSON errors; library errors may include peer input.
    match error.kind() {
        io::ErrorKind::ConnectionRefused => {
            "Connection refused. Check the host IP, port, and that Host is running."
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

/// Authenticate before sending any note state. Only one handshake is in flight.
pub async fn accept_authenticated(
    socket: TcpStream,
    identity: &Identity,
) -> Result<TlsStream<TcpStream>, String> {
    socket.set_nodelay(true).map_err(io_message)?;
    timeout(IO_TIMEOUT, async {
        let mut stream = TlsAcceptor::from(identity.config.clone())
            .accept(socket)
            .await
            .map_err(|_| {
                "TLS handshake failed. The peer must use the current pairing code.".to_string()
            })?;
        let message = read_frame(&mut stream, MAX_HELLO_BYTES)
            .await
            .map_err(io_message)?;
        match message {
            Message::Hello { version, token }
                if version == VERSION && identity.pairing.authenticates(&token) =>
            {
                Ok(stream.into())
            }
            _ => {
                let _ = send(&mut stream, &Message::AuthFailed {}).await;
                Err("Pairing rejected. Check the code and application version.".into())
            }
        }
    })
    .await
    .map_err(|_| "Pairing timed out.".to_string())?
}

pub async fn connect_authenticated(
    address: SocketAddr,
    pairing: &Pairing,
) -> Result<TlsStream<TcpStream>, String> {
    timeout(IO_TIMEOUT, async {
        let socket = TcpStream::connect(address).await.map_err(io_message)?;
        socket.set_nodelay(true).map_err(io_message)?;
        let name = rustls::pki_types::ServerName::try_from("pair.local")
            .expect("fixed valid server name");
        let mut stream = TlsConnector::from(client_config(pairing)).connect(name, socket).await
            .map_err(|_| "TLS verification failed or the handshake was interrupted. Verify the host's pairing code; never accept a changed fingerprint without checking the host.".to_string())?;
        send(&mut stream, &Message::Hello { version: VERSION, token: pairing.token() }).await?;
        Ok(stream.into())
    }).await.map_err(|_| "Connection/pairing timed out. Check the IP, port, and firewall.".to_string())?
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
            // Dedicated reader: a UI action cannot cancel a partially read frame.
            // Timeout closes the entire session, so no partial frame is reused.
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

async fn run(
    mode: Mode,
    mut commands: mpsc::Receiver<Command>,
    publisher: &mut Publisher,
) -> Result<(), String> {
    match mode {
        Mode::Host { address, text } => {
            let mut authority = Authority::new(text).map_err(str::to_string)?;
            let identity = Identity::generate().map_err(str::to_string)?;
            let listener = TcpListener::bind(address).await.map_err(io_message)?;
            publisher.view.bound_address = Some(listener.local_addr().map_err(io_message)?);
            publisher.view.status = format!(
                "Hosting on {}. Waiting for the paired computer.",
                listener.local_addr().map_err(io_message)?
            );
            publisher.view.pairing_code = Some(identity.pairing.code());
            publisher.view.sync_serial = 1;
            publisher.state(&authority);
            loop {
                tokio::select! {
                    command = commands.recv() => {
                        let Some(command) = command else { return Ok(()) };
                        local_command(&mut authority, command);
                        publisher.state(&authority);
                    }
                    accepted = listener.accept() => {
                        let (socket, peer) = accepted.map_err(io_message)?;
                        let pending = accept_authenticated(socket, &identity);
                        tokio::pin!(pending);
                        let result = loop {
                            tokio::select! {
                                result = &mut pending => break result,
                                command = commands.recv() => {
                                    let Some(command) = command else { return Ok(()) };
                                    local_command(&mut authority, command);
                                    publisher.state(&authority);
                                }
                            }
                        };
                        match result {
                            Ok(stream) => {
                                authority.connection_changed();
                                publisher.view.connected = true;
                                publisher.view.status = format!("Connected to {peer} (TLS 1.3, paired).");
                                publisher.state(&authority);
                                let result = host_session(stream, &listener, &mut commands, &mut authority, publisher).await;
                                authority.connection_changed();
                                publisher.view.connected = false;
                                publisher.view.status = format!("{} Host is waiting for reconnection.", result.err().unwrap_or_else(|| "Peer disconnected.".into()));
                                publisher.state(&authority);
                            }
                            Err(error) => {
                                publisher.view.status = format!("{error} Still hosting.");
                                publisher.publish();
                            }
                        }
                    }
                }
            }
        }
        Mode::Connect { address, pairing } => {
            let mut delay = 1;
            loop {
                publisher.view.status = format!("Connecting to {address}...");
                publisher.publish();
                let result = match connect_authenticated(address, &pairing).await {
                    Ok(stream) => {
                        client_session(stream, &mut commands, publisher, &mut delay).await
                    }
                    Err(error) => Err(error),
                };
                publisher.view.connected = false;
                publisher.view.status = format!(
                    "{} Retrying in {delay}s. Stop to change connection details.",
                    result.err().unwrap_or_else(|| "Disconnected.".into())
                );
                publisher.publish();
                // Discard connection-specific queued commands; the UI retains
                // their unacknowledged text and saves it as a recoverable draft.
                while commands.try_recv().is_ok() {}
                time::sleep(Duration::from_secs(delay)).await;
                while commands.try_recv().is_ok() {}
                delay = (delay * 2).min(5);
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
            command = commands.recv() => {
                let Some(command) = command else { return Ok(()) };
                local_command(authority, command);
                publisher.state(authority);
                send_state(&mut writer, authority).await?;
            }
            message = reader.rx.recv() => {
                match message.ok_or("Connection closed.")?? {
                    Message::Edit { edit } => { authority.edit(Side::Peer, edit); }
                    Message::TakeControl {} => authority.take_control(Side::Peer),
                    Message::Ping {} => { send(&mut writer, &Message::Pong {}).await?; continue; }
                    Message::Pong {} => continue,
                    _ => return Err("Unexpected protocol message. Connection closed.".into()),
                }
                publisher.state(authority);
                send_state(&mut writer, authority).await?;
            }
            _ = heartbeat.tick() => send(&mut writer, &Message::Ping {}).await?,
            // A second connection can never replace the active editor.
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
        .map_err(|_| "Host did not complete pairing.".to_string())?
        .map_err(io_message)?;
    let Message::State { snapshot } = first else {
        return Err(
            "Pairing rejected. Check the host's current code and application version.".into(),
        );
    };
    // A fresh connection always starts with the host's full authoritative state.
    while commands.try_recv().is_ok() {}
    publisher.view.sync_serial += 1;
    publisher.view.snapshot = Some(snapshot);
    publisher.view.connected = true;
    publisher.view.status = "Connected to host (TLS 1.3, pinned certificate, paired).".into();
    publisher.publish();
    *delay = 1;
    let (mut reader, mut writer) = split(stream);
    let mut heartbeat = time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            command = commands.recv() => {
                let message = match command {
                    Some(Command::Edit(edit)) => Message::Edit { edit },
                    Some(Command::TakeControl) => Message::TakeControl {},
                    None => return Ok(()),
                };
                send(&mut writer, &message).await?;
            }
            message = reader.rx.recv() => {
                match message.ok_or("Connection closed.")?? {
                    Message::State { snapshot } => {
                        publisher.view.snapshot = Some(snapshot);
                        publisher.publish();
                    }
                    Message::Ping {} => send(&mut writer, &Message::Pong {}).await?,
                    Message::Pong {} => {}
                    _ => return Err("Unexpected protocol message. Connection closed.".into()),
                }
            }
            _ = heartbeat.tick() => send(&mut writer, &Message::Ping {}).await?,
        }
    }
}
