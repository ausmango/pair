# Pair connection help

## A host does not appear

Both computers must be on the same local network and multicast DNS must be
allowed. Guest Wi-Fi, client isolation, VPNs, and some corporate networks block
device-to-device traffic or multicast.

Use manual connection when discovery is unavailable:

1. Start the host on `0.0.0.0` and port `47321`.
2. Find its LAN address with `ipconfig` on Windows or `ip -brief address` on
   Linux.
3. Enter that address and port on the connecting computer.

Do not connect to `0.0.0.0`; it is a bind address. `127.0.0.1` connects only to
the same computer.

## Firewall

Allow Pair on private networks when Windows asks. Pair needs inbound TCP on its
selected port and IPv4 multicast DNS on UDP 5353. Avoid opening the port to the
public internet.

On Linux, firewall commands depend on the distribution. If UFW is active, an
administrator can allow the default Pair port from the local subnet, for
example:

```sh
sudo ufw allow from 192.168.1.0/24 to any port 47321 proto tcp
```

Change the subnet to match the network. Discovery can still fail while a manual
TCP connection succeeds.

## Saved identity changed

Pair fails closed when the host certificate differs from the saved pin. Confirm
that the host intentionally reset its Pair identity. Then stop Pair, use
**Forget Device** on both computers, and repeat phrase verification.

## Jetson Nano

The ARM64 release is built inside an Ubuntu 18.04 container for the original
Jetson Nano / JetPack 4 userspace generation. A user has confirmed Pair works on
physical Jetson Nano hardware, but the exact JetPack version was not recorded.

No administrator password, Rust installation, or compiler is needed for the
release archive:

```sh
cd ~/Downloads
mkdir -p pair-release
tar -xzf pair-linux-arm64-jetpack4.tar.gz -C pair-release
cd pair-release
sh install-desktop.sh
```

Open **Pair** from the Jetson Applications menu after installation. The
installer copies the executable to `~/.local/bin/pair` and creates
`~/.local/share/applications/pair.desktop`; it changes only files owned by your
user and does not use `sudo`. Run the installer from a newer extracted release
to update the installed application.

Run it inside the graphical desktop with a valid `DISPLAY`. A bare SSH session
cannot show the X11 interface. Check missing runtime libraries with:

```sh
ldd ./pair
```

Third-party Jetson images, Orin devices, and JetPack 5/6 require separate
runtime validation.
