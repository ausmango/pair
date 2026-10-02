//! Local application commands. This endpoint is independent of the LAN protocol.
use crate::{
    discovery::{DiscoveredDevice, DiscoveryBrowser},
    network::{ConnectTarget, ordered_addresses},
    persistence::{Store, default_path},
    tls::{hex, random_bytes},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use subtle::ConstantTimeEq;

pub const DEFAULT_PORT: u16 = 47321;
const LIMIT: u64 = 8192;
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    Open,
    Nearby,
    Connect(String),
    Pair(String),
    Host,
    Status,
    AliasSet { computer: String, alias: String },
    AliasList,
    AliasRemove(String),
}

pub enum Invocation {
    Application(Request),
    Help,
    Install,
}

pub fn parse(args: &[String]) -> Result<Invocation, String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let request = match words.as_slice() {
        [] | ["open"] => Request::Open,
        ["help"] | ["--help"] | ["-h"] => return Ok(Invocation::Help),
        ["install-cli"] => return Ok(Invocation::Install),
        ["nearby"] => Request::Nearby,
        ["host"] => Request::Host,
        ["status"] => Request::Status,
        ["connect", target] => Request::Connect((*target).into()),
        ["pair", target] => Request::Pair((*target).into()),
        ["alias", "list"] => Request::AliasList,
        ["alias", "set", computer, alias] => Request::AliasSet {
            computer: (*computer).into(),
            alias: (*alias).into(),
        },
        ["alias", "remove", alias] => Request::AliasRemove((*alias).into()),
        _ => return Err("Unknown command or incorrect arguments. Run pair help.".into()),
    };
    Ok(Invocation::Application(request))
}

pub const HELP: &str = "Pair — live local notepad\n\n  pair [open]                 Open or activate Pair\n  pair nearby                 Search nearby for three seconds\n  pair connect <computer>     Reconnect, or open verified pairing\n  pair pair <computer>        Open pairing or repair flow\n  pair host                   Host a note\n  pair status                 Show the running app's connection state\n  pair alias set <computer> <alias>\n  pair alias list\n  pair alias remove <alias>\n  pair install-cli            Install the command for this user\n\nComputer: alias, exact name, device ID, IPv4, or IPv6.\nOptional port: IPv4:port or [IPv6]:port. Quote names with spaces.\nPairing always requires comparing the phrase in the application.";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Preferences {
    pub aliases: BTreeMap<String, String>,
    pub auto_reconnect: bool,
}

impl Preferences {
    pub fn load(directory: &Path) -> Result<Self, String> {
        let path = directory.join("preferences.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path).map_err(|_| "Could not read Pair preferences.")?;
        if bytes.len() > 65536 {
            return Err("Pair preferences are too large.".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "Pair preferences are invalid.".into())
    }
    pub fn save(&self, directory: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec(self).map_err(|_| "Could not encode preferences.")?;
        let temporary = directory.join("preferences.tmp");
        write_private(&temporary, &bytes)?;
        crate::persistence::replace_file(&temporary, &directory.join("preferences.json"))
            .map_err(|_| "Could not save Pair preferences.".into())
    }
    pub fn set_alias(&mut self, alias: &str, id: &str) -> Result<(), String> {
        let alias = alias.to_ascii_lowercase();
        if alias.is_empty()
            || alias.len() > 32
            || !alias
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("Aliases need 1–32 letters, digits, hyphens, or underscores.".into());
        }
        if self.aliases.get(&alias).is_some_and(|saved| saved != id) {
            return Err("That alias already belongs to another computer. Remove it first.".into());
        }
        if self.aliases.len() >= 64 && !self.aliases.contains_key(&alias) {
            return Err("Alias list full. Remove an unused alias first.".into());
        }
        self.aliases.insert(alias, id.into());
        Ok(())
    }
}

pub fn saved_devices(store: &Store) -> Vec<DiscoveredDevice> {
    let mut devices: Vec<_> = store
        .trusted_peers()
        .into_iter()
        .map(|peer| DiscoveredDevice {
            id: peer.id,
            name: peer.name,
            addresses: Vec::new(),
        })
        .collect();
    if let Some(host) = store.trusted_host() {
        devices.retain(|device| device.id != host.id);
        devices.push(DiscoveredDevice {
            id: host.id,
            name: host.name,
            addresses: vec![host.address],
        });
    }
    devices
}

pub fn resolve_device<'a>(
    query: &str,
    preferences: &Preferences,
    devices: &'a [DiscoveredDevice],
) -> Result<&'a DiscoveredDevice, String> {
    let alias = preferences.aliases.get(&query.to_ascii_lowercase());
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| {
            if let Some(id) = alias {
                &device.id == id
            } else {
                device.id == query || device.name == query
            }
        })
        .collect();
    match matches.as_slice() {
        [device] => Ok(device),
        [] => Err(format!(
            "Computer '{query}' was not discovered or saved. Run pair nearby."
        )),
        _ => Err(format!(
            "Name '{query}' is ambiguous. Use a device ID:\n{}",
            matches
                .iter()
                .map(|device| format!("{}  {}", device.id, device.name))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

pub fn nearby() -> Result<Vec<DiscoveredDevice>, String> {
    let browser = DiscoveryBrowser::start(|| {})?;
    thread::sleep(Duration::from_secs(3));
    let devices = browser.updates.borrow().clone();
    Ok(devices)
}

pub fn resolve_target(
    query: &str,
    preferences: &Preferences,
    store: &Store,
) -> Result<ConnectTarget, String> {
    if let Ok(address) = query.parse::<SocketAddr>().or_else(|_| {
        query
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
    }) {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || address.ip().is_loopback()
            || address.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
        {
            return Err("Enter a usable computer address and nonzero port.".into());
        }
        // Match the existing manual GUI fallback: retain the saved host's pin
        // even when entering its new address. A changed identity still needs repair.
        let saved = store.trusted_host();
        return Ok(ConnectTarget {
            addresses: vec![address],
            id: saved.as_ref().map(|host| host.id.clone()),
            name: saved.as_ref().map(|host| host.name.clone()),
            pairing: saved.map(|host| host.pairing),
        });
    }
    let mut devices = saved_devices(store);
    // Discovery refreshes even saved targets so adapter/address changes are included.
    for discovered in nearby()? {
        if discovered.id == store.device().id {
            continue;
        }
        if let Some(saved) = devices.iter_mut().find(|device| device.id == discovered.id) {
            saved.addresses =
                ordered_addresses(saved.addresses.first().copied(), discovered.addresses);
            saved.name = discovered.name;
        } else {
            devices.push(discovered);
        }
    }
    let device = resolve_device(query, preferences, &devices)?;
    if device.addresses.is_empty() {
        return Err("Device saved but not discovered. Open Pair on the other computer.".into());
    }
    let host = store.trusted_host().filter(|host| host.id == device.id);
    Ok(ConnectTarget {
        addresses: device.addresses.clone(),
        id: Some(device.id.clone()),
        name: Some(device.name.clone()),
        pairing: host.map(|host| host.pairing),
    })
}

/// Decision shared by CLI session switching and its regression test.
pub fn requires_switch(
    running: bool,
    active: Option<&str>,
    requested: Option<&str>,
    hosting: bool,
) -> bool {
    running && (hosting || active.is_none() || requested.is_none() || active != requested)
}
pub fn should_auto_reconnect(
    enabled: bool,
    suppressed: bool,
    running: bool,
    saved: Option<&str>,
    found: &str,
) -> bool {
    enabled && !suppressed && !running && saved == Some(found)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    port: u16,
    capability: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    capability: String,
    request: Request,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub ok: bool,
    pub message: String,
}
impl Response {
    pub fn from_result(result: Result<String, String>) -> Self {
        match result {
            Ok(message) => Self { ok: true, message },
            Err(message) => Self { ok: false, message },
        }
    }
}
pub struct Incoming {
    pub request: Request,
    pub reply: mpsc::Sender<Response>,
}
pub struct Control {
    pub incoming: mpsc::Receiver<Incoming>,
    stopped: Arc<AtomicBool>,
    directory: PathBuf,
    capability: String,
    worker: Option<thread::JoinHandle<()>>,
}

fn control_address(directory: &Path) -> SocketAddr {
    // A stable port makes bind itself the single-instance lock, before settings load.
    let resolved = directory
        .canonicalize()
        .unwrap_or_else(|_| directory.to_path_buf());
    let text = resolved.to_string_lossy();
    #[cfg(windows)]
    let text = text.to_lowercase();
    let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
    let bytes = digest.as_ref();
    SocketAddr::from((
        [127, 0, 0, 1],
        49152 + (u16::from_be_bytes([bytes[0], bytes[1]]) % 16384),
    ))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Could not write Pair's local control settings.")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Could not save Pair's local control settings.".into())
}

pub fn directory() -> Result<PathBuf, String> {
    Ok(default_path()?
        .parent()
        .ok_or("Invalid Pair configuration directory.")?
        .to_path_buf())
}

impl Control {
    pub fn claim(directory: &Path, wake: fn()) -> Result<Self, String> {
        fs::create_dir_all(directory)
            .map_err(|_| "Could not create Pair's configuration directory.")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "Could not protect Pair's configuration directory.")?;
        }
        let listener = TcpListener::bind(control_address(directory))
            .map_err(|_| "Pair is already starting, or its local control port is unavailable.")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "Could not initialize local control.")?;
        let capability = hex(&random_bytes::<32>().map_err(str::to_string)?);
        let endpoint = Endpoint {
            port: listener.local_addr().map_err(|e| e.to_string())?.port(),
            capability: capability.clone(),
        };
        write_private(
            &directory.join("control.json"),
            &serde_json::to_vec(&endpoint).map_err(|e| e.to_string())?,
        )?;
        let (tx, incoming) = mpsc::sync_channel(8);
        let stopped = Arc::new(AtomicBool::new(false));
        let stopping = stopped.clone();
        let expected = capability.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let tx = tx.clone();
                        let expected = expected.clone();
                        // Bound concurrency by serving each bounded request in this thread.
                        let _ = stream.set_read_timeout(Some(TIMEOUT));
                        let _ = stream.set_write_timeout(Some(TIMEOUT));
                        let result = read_json::<Envelope>(&mut stream).and_then(|envelope| {
                            if !bool::from(
                                expected.as_bytes().ct_eq(envelope.capability.as_bytes()),
                            ) {
                                return Err("Local command authentication failed.".into());
                            }
                            let (reply, rx) = mpsc::channel();
                            tx.try_send(Incoming {
                                request: envelope.request,
                                reply,
                            })
                            .map_err(|_| "Pair is busy. Try again.".to_string())?;
                            wake();
                            rx.recv_timeout(Duration::from_secs(10))
                                .map_err(|_| "Pair did not respond. Check its window.".into())
                        });
                        let response =
                            result.unwrap_or_else(|error| Response::from_result(Err(error)));
                        if let Ok(bytes) = serde_json::to_vec(&response) {
                            if bytes.len() as u64 <= LIMIT {
                                let _ = stream.write_all(&bytes);
                            } else {
                                let _ = stream.write_all(b"{\"ok\":false,\"message\":\"Too many results for the terminal. Use Pair's computer list.\"}");
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            incoming,
            stopped,
            directory: directory.into(),
            capability,
            worker: Some(worker),
        })
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let path = self.directory.join("control.json");
        if fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Endpoint>(&bytes).ok())
            .is_some_and(|record| record.capability == self.capability)
        {
            let _ = fs::remove_file(path);
        }
    }
}
fn read_json<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> Result<T, String> {
    let mut bytes = Vec::new();
    stream
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read local command.")?;
    if bytes.len() as u64 > LIMIT {
        return Err("Local command is too large.".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid local command.".into())
}
pub fn send(directory: &Path, request: &Request) -> Result<Response, String> {
    let bytes = fs::read(directory.join("control.json")).map_err(|_| "Pair is not running.")?;
    if bytes.len() > 1024 {
        return Err("Invalid local control record.".into());
    }
    let endpoint: Endpoint =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid local control record.")?;
    if endpoint.port != control_address(directory).port() {
        return Err("Invalid local control address.".into());
    }
    let mut stream =
        TcpStream::connect_timeout(&control_address(directory), Duration::from_millis(500))
            .map_err(|_| "Pair is not running.")?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&Envelope {
        capability: endpoint.capability,
        request: request.clone(),
    })
    .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("Local command is too large.".into());
    }
    stream
        .write_all(&bytes)
        .map_err(|_| "Could not send local command.")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| e.to_string())?;
    read_json(&mut stream)
}

pub fn install() -> Result<String, String> {
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("Could not locate local application data.")?
        .join("Pair/bin");
    #[cfg(not(windows))]
    let root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("Could not locate your home directory.")?
        .join(".local/bin");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let destination = root.join("app/pair.exe");
    #[cfg(not(windows))]
    let destination = root.join("pair");
    #[cfg(windows)]
    let shim = b"@echo off\r\nif \"%~1\"==\"\" (\r\n  \"%~dp0app\\pair.exe\" open\r\n) else (\r\n  \"%~dp0app\\pair.exe\" %*\r\n)\r\nexit /b %errorlevel%\r\n";
    #[cfg(windows)]
    {
        // Keep the GUI executable off PATH so PowerShell resolves the batch
        // shim, whose command process waits for CLI output and exit status.
        if root.join("pair.exe").exists()
            || root.join("pair.com").exists()
            || root.join("pair.bat").exists()
            || (root.join("pair.cmd").exists()
                && fs::read(root.join("pair.cmd")).map_err(|e| e.to_string())? != shim)
        {
            return Err(
                "Another pair command already exists in the installation directory.".into(),
            );
        }
    }
    let marker = root.join(".pair-cli-owner");
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let bytes = fs::read(&source).map_err(|e| e.to_string())?;
    if destination.exists() {
        let existing = fs::read(&destination).map_err(|e| e.to_string())?;
        let fingerprint = hex(ring::digest::digest(&ring::digest::SHA256, &existing).as_ref());
        if existing != bytes && fs::read_to_string(&marker).ok().as_deref() != Some(&fingerprint) {
            return Err(
                "An unrelated pair executable already exists in the command directory.".into(),
            );
        }
    }
    fs::create_dir_all(destination.parent().ok_or("Invalid command directory.")?)
        .map_err(|e| e.to_string())?;
    if source != destination {
        fs::copy(&source, &destination).map_err(
            |_| "Could not install Pair. Close the installed application before updating it.",
        )?;
    }
    write_private(
        &marker,
        hex(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()).as_bytes(),
    )?;
    #[cfg(windows)]
    {
        write_private(&root.join("pair.cmd"), shim)?;
        let status = std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", "$pairBin=$env:PAIR_CLI_INSTALL_DIRECTORY; $pairPath=[Environment]::GetEnvironmentVariable('Path','User'); $pairParts=@($pairPath -split ';' | Where-Object { $_ }); if (-not ($pairParts | Where-Object { $_.TrimEnd('\\') -ieq $pairBin.TrimEnd('\\') })) { [Environment]::SetEnvironmentVariable('Path', (($pairParts + $pairBin) -join ';'), 'User') }"]).env("PAIR_CLI_INSTALL_DIRECTORY", &root).status().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("Pair was copied, but user PATH could not be updated.".into());
        }
    }
    Ok(format!(
        "Installed {}. Open a new terminal to use pair.{}",
        destination.display(),
        if cfg!(windows) {
            ""
        } else {
            " Ensure ~/.local/bin is on your PATH."
        }
    ))
}
