use std::{
    env, fs,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::tls::{Identity, Pairing, hex, random_bytes, unhex};

const FORMAT_VERSION: u32 = 1;
const MAX_NAME_BYTES: usize = 32;

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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRecord {
    id: String,
    name: String,
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
    host_token: String,
    trusted_peer: Option<PeerRecord>,
    trusted_host: Option<HostRecord>,
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
            host_token: identity.pairing.token(),
            trusted_peer: None,
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
        let token: [u8; 32] = unhex(&self.host_token, 32)
            .map_err(str::to_string)?
            .try_into()
            .map_err(|_| "Stored host token has the wrong length.")?;
        Identity::from_der(cert, key, token).map_err(str::to_string)?;
        if let Some(peer) = &self.trusted_peer
            && (!valid_id(&peer.id) || !valid_name(&peer.name))
        {
            return Err("Stored peer is invalid.".into());
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
            serde_json::from_slice::<Data>(&bytes)
                .map_err(|_| "Pair settings file is invalid.".to_string())?
        } else {
            Data::generate()?
        };
        data.validate()?;
        let store = Self {
            path,
            data: Arc::new(Mutex::new(data)),
        };
        if !store.path.exists() {
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
        let token: [u8; 32] = unhex(&data.host_token, 32)
            .map_err(str::to_string)?
            .try_into()
            .map_err(|_| "Stored host token has the wrong length.")?;
        Identity::from_der(cert, key, token).map_err(str::to_string)
    }

    pub fn has_trusted_peer(&self) -> bool {
        self.data
            .lock()
            .is_ok_and(|data| data.trusted_peer.is_some())
    }

    pub fn trust_peer(&self, peer: DeviceIdentity, token: [u8; 32]) -> Result<(), String> {
        if !valid_id(&peer.id) || !valid_name(&peer.name) {
            return Err("Peer identity is invalid.".into());
        }
        self.update(|data| {
            data.host_token = hex(&token);
            data.trusted_peer = Some(PeerRecord {
                id: peer.id,
                name: peer.name,
            });
        })
    }

    pub fn forget_peer(&self) -> Result<(), String> {
        let token = random_bytes::<32>().map_err(str::to_string)?;
        self.update(|data| {
            data.host_token = hex(&token);
            data.trusted_peer = None;
        })
    }

    pub fn reset_host_identity(&self) -> Result<(), String> {
        let identity = Identity::generate().map_err(str::to_string)?;
        self.update(|data| {
            data.certificate = hex(identity.cert_der());
            data.private_key = hex(identity.key_der());
            data.host_token = identity.pairing.token();
            data.trusted_peer = None;
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
