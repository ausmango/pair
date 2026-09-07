# Validation record

Performed on **2026-09-07** in this repository on Windows x64, OS build
`10.0.26200`. No Linux machine or Jetson was attached.

## Build environment

- Rust `1.98.1 (48a229cea 2026-09-01)`, `x86_64-pc-windows-gnu`.
- GCC-MinGW `16.2.0`, x86_64 UCRT/POSIX/SEH (WinLibs distribution).
- CMake `4.4.3`.
- FLTK Rust crate `1.5.23`, compiled from its included C++ sources.
- Dependency versions are recorded in `Cargo.lock`.

Rust and portable build tools were installed locally in the ignored `.tools`
directory because Rust and C++ build tools were not initially available on
`PATH`. In this workspace, `. .\.tools\env.ps1` sets up that temporary build
environment. The README also gives normal system-toolchain build instructions.
The declared Rust 1.88 minimum was not separately tested with a 1.88 compiler.

## Checks completed

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed |
| `cargo test --locked --all-targets` | 19 tests passed |
| `cargo test --locked --no-default-features` | 18 tests passed, no GUI needed |
| `cargo build --locked --release` | Passed; Windows executable produced |
| `git diff --check` | Passed |
| `sh -n scripts/build-linux-user.sh` | Passed with Git's POSIX shell on Windows |

The no-sudo helper was syntax-checked and its official CMake download names
were verified against Kitware's Linux ARM64 release listing. It could not be
executed end to end because no Linux/Jetson environment was available. A source
transfer archive was created locally and its contents and SHA-256 checksum were
checked after creation.

The final native-widget test was also run individually after extending its
connection-error coverage. The other 18 tests were unchanged by that extension.

Coverage:

- **5 framing tests:** byte-at-a-time partial reads, consecutive frames,
  UTF-8/Unicode, tabs and CR/LF preservation, truncated headers/bodies, invalid
  UTF-8/JSON, unknown message fields/types, oversized/zero length prefixes,
  pre-authentication limits, maximum JSON escaping, note-size and NUL rejection,
  and errors that do not echo note fragments.
- **8 authority/editor tests:** ownership grants, stale epochs (including
  handing control away and back), stale revisions/replays, edits during an
  outstanding acknowledgement, lost control before debounce, rejected edits,
  unacknowledged work across reconnect, coalesced state notifications, draft
  restoration, and filling draft storage without evicting older text.
- **5 transport tests:** real TCP/TLS loopback connections using generated
  identities; wrong certificate pin and wrong secret rejection; code parsing;
  text synchronization and control enforcement; host edits while disconnected;
  latest-state reconnect; actual client automatic retry and draft recovery;
  and refusal of a second peer while the first stays usable.
- **1 native-widget test:** constructs the real FLTK window, preserves mixed
  line breaks/Unicode/tabs, recovers from an oversized local paste, switches
  between editable and read-only widgets on control changes, and surfaces a
  port-in-use error even when the network worker has already closed its
  notification channel.

The release executable was launched successfully and its initial native window
was inspected visually. The runtime imports were inspected with `objdump -p`:
they are Windows system DLLs/UCRT API sets, with no FLTK, MinGW runtime, or
application-specific DLL dependency.

## Measurements

One short sample of the **corrected release build**, with an empty note and no
active Host/Connect session. The desktop helper could foreground/background the
window; this is a local smoke measurement, not a benchmark or an upper bound.
Measurements came from Windows process counters after launch, not estimates.

| Quantity | Observed |
| --- | --- |
| Executable size | 2,844,160 bytes (about 2.71 MiB) |
| Sample duration | 10.010734 seconds |
| Working set at start / end | 23,662,592 / 23,678,976 bytes (about 22.6 MiB) |
| Private bytes at start / end | 3,293,184 / 3,293,184 bytes (about 3.14 MiB) |
| Process CPU consumed during sample | 0.0625 seconds |

The sampling caught a redraw loop in an earlier build. The event loop was fixed
to update widgets only for user/network changes, and the measurements above
were taken afterward. They do not describe the earlier faulty build.

End-to-end GUI/LAN latency, connected idle memory, maximum-note memory, build
memory, and Jetson performance were **not measured**. The 75 ms debounce is a
configured interval, not a measured delivery-latency claim.

## Unverified

- Linux x64 and ARM64 builds/runtime, including native library availability on
  JetPack 4 / Ubuntu 18.04. Compatibility notes are based on upstream platform
  documentation and inspected dependency build scripts, not a tested Nano.
- The Windows MSVC route and Windows versions other than this machine.
- A physical two-computer LAN session, Wi-Fi loss timing, and firewall rules.
- Manual editing/copy/paste between two GUI processes, OS clipboard newline
  conversion, IME behavior, screen readers, and font coverage across languages.
  Programmatic widget text tests and real TLS loopback tests are separate from
  those manual acceptance checks.
- Independent security review or fuzzing. Authentication failure tests and
  bounds checks are not a security audit.

Useful next hardware check: build natively on the intended Nano image, pair it
with Windows using the trusted-code flow, paste an indented Unicode script,
take control in both directions, interrupt the network with a pending edit,
edit on the host, reconnect, and check the host note plus the recoverable draft.
