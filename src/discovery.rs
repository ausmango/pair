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
pub const MAX_ADDRESSES_PER_DEVICE: usize = 8;
const STALE_AFTER: Duration = Duration::from_secs(120);

#[derive(Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub id: String,
    pub name: String,
    pub addresses: Vec<SocketAddr>,
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
        _version: u32,
        now: Instant,
    ) -> bool {
        if !valid_id(id) || !valid_name(name) || !valid_address(address) || address.port() == 0 {
            return false;
        }
        if !self.entries.contains_key(&fullname) && self.entries.len() >= MAX_DISCOVERED {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(&fullname) {
            if entry.device.id != id {
                return false;
            }
            let mut changed = entry.device.name != name;
            entry.device.name = name.into();
            entry.seen = now;
            if !entry.device.addresses.contains(&address) {
                if entry.device.addresses.len() == MAX_ADDRESSES_PER_DEVICE {
                    entry.device.addresses.remove(0);
                }
                entry.device.addresses.push(address);
                changed = true;
            }
            changed
        } else {
            self.entries.insert(
                fullname,
                Entry {
                    device: DiscoveredDevice {
                        id: id.into(),
                        name: name.into(),
                        addresses: vec![address],
                    },
                    seen: now,
                },
            );
            true
        }
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
        let mut by_id: BTreeMap<String, DiscoveredDevice> = BTreeMap::new();
        for entry in self.entries.values() {
            let merged = by_id
                .entry(entry.device.id.clone())
                .or_insert_with(|| DiscoveredDevice {
                    id: entry.device.id.clone(),
                    name: entry.device.name.clone(),
                    addresses: Vec::new(),
                });
            merged.name = entry.device.name.clone();
            for address in &entry.device.addresses {
                if !merged.addresses.contains(address)
                    && merged.addresses.len() < MAX_ADDRESSES_PER_DEVICE
                {
                    merged.addresses.push(*address);
                }
            }
        }
        by_id.into_values().collect()
    }
}

fn valid_address(address: SocketAddr) -> bool {
    address.port() != 0
        && address.ip().is_ipv4()
        && !address.ip().is_loopback()
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}

fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolved_fields(service: &ResolvedService) -> Option<(&str, &str, Vec<SocketAddr>, u32)> {
    let id = service.get_property_val_str("id")?;
    let name = service.get_property_val_str("name")?;
    let version = service.get_property_val_str("ver")?.parse().ok()?;
    let addresses = service
        .get_addresses_v4()
        .into_iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), service.get_port()))
        .filter(|address| valid_address(*address))
        .take(MAX_ADDRESSES_PER_DEVICE)
        .collect::<Vec<_>>();
    (!addresses.is_empty()).then_some((id, name, addresses, version))
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
                            .is_some_and(|(id, name, addresses, version)| {
                                let mut changed = false;
                                for address in addresses {
                                    changed |= catalog.resolve(
                                        service.fullname.clone(),
                                        id,
                                        name,
                                        address,
                                        version,
                                        Instant::now(),
                                    );
                                }
                                changed
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
