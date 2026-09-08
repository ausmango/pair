use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use mdns_sd::{IfKind, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::watch;

use crate::{
    persistence::{DeviceIdentity, valid_name},
    protocol::VERSION,
};

pub const SERVICE_TYPE: &str = "_pair._tcp.local.";
pub const MAX_DISCOVERED: usize = 32;
const STALE_AFTER: Duration = Duration::from_secs(120);

#[derive(Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub id: String,
    pub name: String,
    pub address: SocketAddr,
}

struct Entry {
    device: DiscoveredDevice,
    seen: Instant,
}

#[derive(Default)]
pub struct DiscoveryCatalog {
    entries: BTreeMap<String, Entry>,
}

impl DiscoveryCatalog {
    pub fn resolve(
        &mut self,
        fullname: String,
        id: &str,
        name: &str,
        address: SocketAddr,
        version: u32,
        now: Instant,
    ) -> bool {
        if version != VERSION
            || !valid_id(id)
            || !valid_name(name)
            || !address.ip().is_ipv4()
            || address.port() == 0
        {
            return false;
        }
        if !self.entries.contains_key(&fullname) && self.entries.len() >= MAX_DISCOVERED {
            return false;
        }
        self.entries.insert(
            fullname,
            Entry {
                device: DiscoveredDevice {
                    id: id.into(),
                    name: name.into(),
                    address,
                },
                seen: now,
            },
        );
        true
    }

    pub fn remove(&mut self, fullname: &str) -> bool {
        self.entries.remove(fullname).is_some()
    }

    pub fn prune(&mut self, now: Instant) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.seen) < STALE_AFTER);
        before != self.entries.len()
    }

    pub fn devices(&self) -> Vec<DiscoveredDevice> {
        let mut by_id = BTreeMap::new();
        for entry in self.entries.values() {
            by_id.insert(entry.device.id.clone(), entry.device.clone());
        }
        by_id.into_values().collect()
    }
}

fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolved_fields(service: &ResolvedService) -> Option<(&str, &str, SocketAddr, u32)> {
    let id = service.get_property_val_str("id")?;
    let name = service.get_property_val_str("name")?;
    let version = service.get_property_val_str("ver")?.parse().ok()?;
    let ip = service
        .get_addresses_v4()
        .into_iter()
        .find(|ip| !ip.is_loopback())?;
    Some((
        id,
        name,
        SocketAddr::new(IpAddr::V4(ip), service.get_port()),
        version,
    ))
}

pub struct DiscoveryBrowser {
    pub updates: watch::Receiver<Vec<DiscoveredDevice>>,
    daemon: ServiceDaemon,
}

impl DiscoveryBrowser {
    pub fn start(wake: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        let daemon = ServiceDaemon::new()
            .map_err(|_| "Could not start local-network discovery.".to_string())?;
        daemon
            .disable_interface(IfKind::IPv6)
            .map_err(|_| "Could not configure IPv4 discovery.".to_string())?;
        let events = daemon
            .browse(SERVICE_TYPE)
            .map_err(|_| "Could not browse for Pair hosts.".to_string())?;
        let (tx, updates) = watch::channel(Vec::new());
        let wake = Arc::new(wake);
        thread::Builder::new()
            .name("pair-discovery".into())
            .spawn(move || {
                let mut catalog = DiscoveryCatalog::default();
                loop {
                    let changed = match events.recv_timeout(Duration::from_secs(2)) {
                        Ok(ServiceEvent::ServiceResolved(service)) => resolved_fields(&service)
                            .is_some_and(|(id, name, address, version)| {
                                catalog.resolve(
                                    service.fullname.clone(),
                                    id,
                                    name,
                                    address,
                                    version,
                                    Instant::now(),
                                )
                            }),
                        Ok(ServiceEvent::ServiceRemoved(_, fullname)) => catalog.remove(&fullname),
                        Ok(ServiceEvent::SearchStopped(_)) => break,
                        Err(flume::RecvTimeoutError::Timeout) => catalog.prune(Instant::now()),
                        Err(flume::RecvTimeoutError::Disconnected) => break,
                        _ => catalog.prune(Instant::now()),
                    };
                    if changed {
                        tx.send_replace(catalog.devices());
                        wake();
                    }
                }
            })
            .map_err(|_| "Could not start the discovery worker.".to_string())?;
        Ok(Self { updates, daemon })
    }
}

impl Drop for DiscoveryBrowser {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

pub struct Advertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertiser {
    pub fn start(device: &DeviceIdentity, port: u16) -> Result<Self, String> {
        if !valid_id(&device.id) || !valid_name(&device.name) || port == 0 {
            return Err("Invalid discovery advertisement.".into());
        }
        let daemon =
            ServiceDaemon::new().map_err(|_| "Could not start host discovery.".to_string())?;
        daemon
            .disable_interface(IfKind::IPv6)
            .map_err(|_| "Could not configure IPv4 discovery.".to_string())?;
        let hostname = format!("pair-{}.local.", &device.id[..8]);
        let properties = [
            ("ver", VERSION.to_string()),
            ("id", device.id.clone()),
            ("name", device.name.clone()),
        ];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &device.id,
            &hostname,
            "",
            port,
            &properties[..],
        )
        .map_err(|_| "Could not create discovery advertisement.".to_string())?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|_| "Could not advertise Pair on the local network.".to_string())?;
        Ok(Self { daemon, fullname })
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        if let Ok(receiver) = self.daemon.unregister(&self.fullname) {
            let _ = receiver.recv_timeout(Duration::from_millis(500));
        }
        let _ = self.daemon.shutdown();
    }
}
