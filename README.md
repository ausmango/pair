<p align="center">
  <img src="assets/pair-horizontal.svg" alt="pair" width="520">
</p>

Pair is a tiny native notepad shared between two computers on the same local
network. Paste a command, script, or any plain text on one computer and it
starts syncing after about 20 ms of idle typing, plus normal LAN latency.

Pair never executes received text. It has no browser, cloud service, account,
database, clipboard monitoring, telemetry, or note logging.

## Download

Download the archive for your computer from the
[latest release](https://github.com/ausmango/pair/releases/latest):

| System | File |
| --- | --- |
| Windows 10/11 x64 | `pair-windows-x64.zip` |
| Linux x64 | `pair-linux-x64.tar.gz` |
| NVIDIA Jetson Nano / JetPack 4 ARM64 | `pair-linux-arm64-jetpack4.tar.gz` |
| macOS 12+ Intel | `pair-macos-x64.zip` |
| macOS 12+ Apple Silicon | `pair-macos-arm64.zip` |

Verify a download against `SHA256SUMS` when possible. Windows and macOS builds
are currently unsigned. macOS builds are produced in CI but have not yet been
tested on physical Macs.

On Linux or Jetson, extract the archive and run `sh install-desktop.sh` once.
This installs Pair for your current user with no administrator password, then
you can open it from the Applications menu.

## Use Pair

1. Open Pair on both computers. Give each one a useful device name.
2. On one computer, leave **Host** selected and click **Start Host**. On the
   other, select **Connect**, choose the nearby host, and click **Connect**.
3. Compare the six-word phrase on both screens. If it matches exactly, click
   **Phrase Matches — Pair** on both computers.

Pair remembers the verified device. Later connections need one click and use
the saved certificate pin and random reconnect token.

The host starts with editing control. Click **Take Control** on the other
computer before editing there. **Copy All** copies the complete note. Tabs,
indentation, Unicode, and line breaks are preserved.

If the host does not appear, enter its LAN IP and port manually. The default
port is `47321`. Discovery uses IPv4 multicast DNS; manual IPv4 and IPv6
connections remain available.

## Privacy and security

Pair uses TLS 1.3. The first connection is visibly marked unverified and cannot
receive note data. The matching phrase verifies the host certificate before
Pair stores a 256-bit reconnect token. Later connections pin that exact
certificate and authenticate with the token.

Only device identity and pairing credentials are saved in the current user's
application-data directory. Notes and recovery drafts stay in memory. Use
**Forget Device** to revoke or remove saved trust.

Read [the security design](docs/SECURITY.md) for the full pairing flow and
threat model.

## Platform status

| Platform | Status |
| --- | --- |
| Windows x64 | Built and tested during development |
| Original Jetson Nano ARM64 | User-confirmed on physical hardware; exact JetPack version was not recorded |
| Linux x64 | Built in CI; desktop runtime depends on common X11/Pango libraries |
| macOS Intel / Apple Silicon | CI build target; physical runtime validation pending |

Linux uses X11 and works under Wayland through XWayland. Pair does not require
OpenGL, Vulkan, CUDA, GTK, Qt, or an embedded web engine.

## More information

- [Build from source](docs/BUILDING.md)
- [Connection, firewall, and Jetson help](docs/TROUBLESHOOTING.md)
- [Security and stored data](docs/SECURITY.md)
- [Development validation](VALIDATION.md)

Pair is written in Rust with a statically linked FLTK interface. Source builds
require Rust 1.88+, a C++ compiler, CMake 3.28+, and the platform prerequisites
listed in the build guide. Downloaded release binaries do not require Rust or a
compiler.
