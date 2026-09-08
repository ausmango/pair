# Validation record

Validation below was performed on 2026-09-07 on Windows x64 with the repository's
portable GNU toolchain. Dependency versions are locked in `Cargo.lock`.

## Completed for v0.2

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed |
| `cargo +1.88.0 check --all-targets --locked` | Passed with the documented minimum Rust version |
| `cargo test --all-targets --locked` | 26 tests passed |
| `cargo build --release --locked` | Passed |
| Release executable launch | Passed |

The tests cover bounded and partial framing, exact Unicode/indentation/newline
preservation, host-authoritative ownership, recovery drafts, discovery input
limits and expiry, persistent identities, token revocation, strict certificate
pins, rejection of bad tokens, two-sided phrase confirmation, denial of note
state before verification, authenticated reconnect, and latest-host-state sync.

## Windows release measurement

One short launch sample with an empty note and no active Host/Connect session:

| Quantity | v0.2 observation | Previous v0.1 observation |
| --- | ---: | ---: |
| Executable size | 2,828,800 bytes | 2,844,160 bytes |
| Working set after 3 seconds | 15,986,688 bytes | 23,678,976 bytes |
| Private bytes after 3 seconds | 2,457,600 bytes | 3,293,184 bytes |

The samples used different durations and are smoke measurements, not benchmarks.
Connected-state and active-discovery memory have not been measured on physical
two-computer hardware.

## Platform limits

- The earlier release was user-confirmed on a physical Jetson Nano. The exact
  JetPack version was not recorded, and v0.2 discovery/pairing has not yet been
  manually exercised there.
- Linux x64 and both macOS variants are release targets but were not built or
  run in this Windows environment. CI provides the platform builds.
- macOS Intel and Apple Silicon runtime behavior remains unverified on physical
  Macs. The archives are ad-hoc signed and not notarized.
- Real multicast discovery, firewall prompts, certificate-phrase comparison
  between two visible machines, and end-to-end LAN latency need hardware checks.
- No independent security audit or fuzzing was performed.
