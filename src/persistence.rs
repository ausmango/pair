use std::{
    env, fs,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::tls::{Identity, Pairing, hex, random_bytes, unhex};

const FORMAT_VERSION: u32 = 2;
const MAX_NAME_BYTES: usize = 32;
pub const MAX_TRUSTED_PEERS: usize = 8;

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: String,
    pub name: String,
}

#[derive(Clone)]
pub struct TrustedHost {
    pub id: String,
    pub name: String,
    pub address: SocketAddr,
    pub pairing: Pairing,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TrustedPeer {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRecord {
    id: String,
    name: String,
    token: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRecord {
    id: String,
    name: String,
    address: String,
    pairing_code: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    version: u32,
    device_id: String,
    device_name: String,
    certificate: String,
    private_key: String,
    trusted_peers: Vec<PeerRecord>,
    trusted_host: Option<HostRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DataV1 {
    version: u32,
    device_id: String,
    device_name: String,
    certificate: String,
    private_key: String,
    host_token: String,
    trusted_peer: Option<PeerV1>,
    trusted_host: Option<HostRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerV1 {
    id: String,
    name: String,
}

#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    data: Arc<Mutex<Data>>,
}

fn valid_id(value: &str) -> bool {
    value.len() == 32 && unhex(value, 16).is_ok()
}

pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && !value.contains('|')
        && !value.chars().any(|c| c.is_control())
}

impl Data {
    fn generate() -> Result<Self, String> {
        let identity = Identity::generate().map_err(str::to_string)?;
        let device_id = hex(&random_bytes::<16>().map_err(str::to_string)?);
        Ok(Self {
            version: FORMAT_VERSION,
            device_name: format!("pair-{}", device_id[..4].to_ascii_uppercase()),
            device_id,
            certificate: hex(identity.cert_der()),
            private_key: hex(identity.key_der()),
            trusted_peers: Vec::new(),
            trusted_host: None,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != FORMAT_VERSION {
            return Err("Unsupported Pair settings version.".into());
        }
        if !valid_id(&self.device_id) || !valid_name(&self.device_name) {
            return Err("Pair settings contain an invalid device identity.".into());
        }
        let cert = unhex(&self.certificate, 16 * 1024).map_err(str::to_string)?;
        let key = unhex(&self.private_key, 16 * 1024).map_err(str::to_string)?;
        Identity::from_der(cert, key, [0; 32]).map_err(str::to_string)?;
        if self.trusted_peers.len() > MAX_TRUSTED_PEERS {
            return Err("Too many stored peers.".into());
        }
        for (index, peer) in self.trusted_peers.iter().enumerate() {
            if !valid_id(&peer.id)
                || !valid_name(&peer.name)
                || unhex(&peer.token, 32).is_err()
                || peer.token.len() != 64
                || self.trusted_peers[..index].iter().any(|p| p.id == peer.id)
            {
                return Err("Stored peer is invalid.".into());
            }
        }
        if let Some(host) = &self.trusted_host
            && (!valid_id(&host.id)
                || !valid_name(&host.name)
                || host.address.parse::<SocketAddr>().is_err()
                || Pairing::parse(&host.pairing_code).is_err())
        {
            return Err("Stored host is invalid.".into());
        }
        Ok(())
    }
}

fn migrate_v1(bytes: &[u8]) -> Result<Data, String> {
    let old: DataV1 =
        serde_json::from_slice(bytes).map_err(|_| "Pair settings file is invalid.".to_string())?;
    if old.version != 1 {
        return Err("Unsupported Pair settings version.".into());
    }
    let trusted_peers = old
        .trusted_peer
        .map(|peer| PeerRecord {
            id: peer.id,
            name: peer.name,
            token: old.host_token,
        })
        .into_iter()
        .collect();
    Ok(Data {
        version: FORMAT_VERSION,
        device_id: old.device_id,
        device_name: old.device_name,
        certificate: old.certificate,
        private_key: old.private_key,
        trusted_peers,
        trusted_host: old.trusted_host,
    })
}

fn version_on_disk(path: &Path) -> Option<u64> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("version")?
        .as_u64()
}

impl Store {
    pub fn load_default() -> Result<Self, String> {
        Self::load(default_path()?)
    }

    pub fn load(path: PathBuf) -> Result<Self, String> {
        let data = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| "Could not read Pair settings.".to_string())?;
            if bytes.len() > 128 * 1024 {
                return Err("Pair settings file is too large.".into());
            }
            let version = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value.get("version")?.as_u64())
                .ok_or_else(|| "Pair settings file is invalid.".to_string())?;
            match version {
                1 => migrate_v1(&bytes)?,
                2 => serde_json::from_slice::<Data>(&bytes)
                    .map_err(|_| "Pair settings file is invalid.".to_string())?,
                _ => return Err("Unsupported Pair settings version.".into()),
            }
        } else {
            Data::generate()?
        };
        data.validate()?;
        let store = Self {
            path,
            data: Arc::new(Mutex::new(data)),
        };
        if !store.path.exists() || version_on_disk(&store.path) == Some(1) {
            store.save()?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn device(&self) -> DeviceIdentity {
        let data = self.data.lock().expect("settings mutex poisoned");
        DeviceIdentity {
            id: data.device_id.clone(),
            name: data.device_name.clone(),
        }
    }

    pub fn set_name(&self, name: &str) -> Result<(), String> {
        let name = name.trim();
        if !valid_name(name) {
            return Err("Device name must be 1–32 bytes without control characters.".into());
        }
        self.update(|data| data.device_name = name.to_string())
    }

    pub fn identity(&self) -> Result<Identity, String> {
        let data = self
            .data
            .lock()
            .map_err(|_| "Pair settings are unavailable.")?;
        let cert = unhex(&data.certificate, 16 * 1024).map_err(str::to_string)?;
        let key = unhex(&data.private_key, 16 * 1024).map_err(str::to_string)?;
        Identity::from_der(cert, key, [0; 32]).map_err(str::to_string)
    }

    pub fn has_trusted_peer(&self) -> bool {
        self.data
            .lock()
            .is_ok_and(|data| !data.trusted_peers.is_empty())
    }

    pub fn trusted_peers(&self) -> Vec<TrustedPeer> {
        self.data.lock().map_or_else(
            |_| Vec::new(),
            |data| {
                data.trusted_peers
                    .iter()
                    .map(|peer| TrustedPeer {
                        id: peer.id.clone(),
                        name: peer.name.clone(),
                    })
                    .collect()
            },
        )
    }

    pub fn token_authenticates(&self, candidate: &str) -> bool {
        let Ok(candidate): Result<[u8; 32], _> =
            unhex(candidate, 32).and_then(|bytes| bytes.try_into().map_err(|_| "bad token"))
        else {
            return false;
        };
        self.data.lock().is_ok_and(|data| {
            let mut matched = 0u8;
            for peer in &data.trusted_peers {
                let token: Result<[u8; 32], _> =
                    unhex(&peer.token, 32).and_then(|v| v.try_into().map_err(|_| "bad token"));
                if let Ok(token) = token {
                    matched |= token.ct_eq(&candidate).unwrap_u8();
                }
            }
            matched == 1
        })
    }

    pub fn trust_peer(&self, peer: DeviceIdentity, token: [u8; 32]) -> Result<(), String> {
        if !valid_id(&peer.id) || !valid_name(&peer.name) {
            return Err("Peer identity is invalid.".into());
        }
        if self.trusted_peers().len() >= MAX_TRUSTED_PEERS
            && !self.trusted_peers().iter().any(|saved| saved.id == peer.id)
        {
            return Err("Host trust list full. Remove a paired device.".into());
        }
        self.update(|data| {
            data.trusted_peers.retain(|saved| saved.id != peer.id);
            data.trusted_peers.push(PeerRecord {
                id: peer.id,
                name: peer.name,
                token: hex(&token),
            });
        })
    }

    pub fn forget_peer(&self, id: &str) -> Result<(), String> {
        self.update(|data| data.trusted_peers.retain(|peer| peer.id != id))
    }

    pub fn forget_all_peers(&self) -> Result<(), String> {
        self.update(|data| data.trusted_peers.clear())
    }

    pub fn reset_host_identity(&self) -> Result<(), String> {
        let identity = Identity::generate().map_err(str::to_string)?;
        self.update(|data| {
            data.certificate = hex(identity.cert_der());
            data.private_key = hex(identity.key_der());
            data.trusted_peers.clear();
        })
    }

    pub fn trusted_host(&self) -> Option<TrustedHost> {
        let data = self.data.lock().ok()?;
        let host = data.trusted_host.as_ref()?;
        Some(TrustedHost {
            id: host.id.clone(),
            name: host.name.clone(),
            address: host.address.parse().ok()?,
            pairing: Pairing::parse(&host.pairing_code).ok()?,
        })
    }

    pub fn trust_host(
        &self,
        id: String,
        name: String,
        address: SocketAddr,
        pairing: Pairing,
    ) -> Result<(), String> {
        if !valid_id(&id) || !valid_name(&name) {
            return Err("Host identity is invalid.".into());
        }
        self.update(|data| {
            data.trusted_host = Some(HostRecord {
                id,
                name,
                address: address.to_string(),
                pairing_code: pairing.code(),
            })
        })
    }

    pub fn forget_host(&self) -> Result<(), String> {
        self.update(|data| data.trusted_host = None)
    }

    pub fn update_host_address(&self, address: SocketAddr) -> Result<(), String> {
        self.update(|data| {
            if let Some(host) = &mut data.trusted_host {
                host.address = address.to_string();
            }
        })
    }

    fn update(&self, change: impl FnOnce(&mut Data)) -> Result<(), String> {
        let original = {
            let mut data = self
                .data
                .lock()
                .map_err(|_| "Pair settings are unavailable.")?;
            let original = data.clone();
            change(&mut data);
            data.validate()?;
            original
        };
        if let Err(error) = self.save() {
            if let Ok(mut data) = self.data.lock() {
                *data = original;
            }
            return Err(error);
        }
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or("Pair settings path has no parent directory.")?;
        fs::create_dir_all(parent)
            .map_err(|_| "Could not create the Pair settings directory.".to_string())?;
        set_dir_permissions(parent)?;
        let bytes = {
            let data = self
                .data
                .lock()
                .map_err(|_| "Pair settings are unavailable.")?;
            serde_json::to_vec(&*data).map_err(|_| "Could not encode Pair settings.".to_string())?
        };
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        write_private(&temporary, &bytes)?;
        replace_file(&temporary, &self.path)
            .map_err(|_| "Could not save Pair settings atomically.".to_string())
    }
}

fn default_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("PAIR_CONFIG_DIR") {
        return Ok(PathBuf::from(path).join("state.json"));
    }
    #[cfg(target_os = "windows")]
    let base = env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base =
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    base.map(|path| path.join("pair/state.json"))
        .ok_or_else(|| "Could not locate the per-user settings directory.".into())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Could not create a private settings file.".to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Could not write Pair settings.".to_string())
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "Could not secure the Pair settings directory.".into())
}
#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}
#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    if !to.exists() {
        return fs::rename(from, to);
    }
    let replaced: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    let replacement: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    // Both paths are inside Pair's per-user settings directory and therefore
    // on the same volume, which lets ReplaceFileW exchange them atomically.
    let result = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
