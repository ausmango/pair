# Building Pair

Release archives are the easiest way to run Pair. Building from source requires
Rust 1.88 or newer, Git, a C++ compiler, CMake 3.28 or newer, and Ninja. Keep
`Cargo.lock` and use `--locked`.

## Windows x64

Install Rust through rustup and Visual Studio Build Tools with **Desktop
development with C++**, the Windows SDK, CMake, and Ninja. In an x64 Native
Tools Command Prompt:

```bat
rustup toolchain install stable-x86_64-pc-windows-msvc --profile minimal --component rustfmt,clippy
cargo build --release --locked
target\release\pair.exe
```

The release executable statically links FLTK and the MSVC runtime.

## Linux x64 or ARM64

On a recent Debian or Ubuntu system:

```sh
sudo apt-get update
sudo apt-get install build-essential git cmake ninja-build pkg-config curl ca-certificates \
  libx11-dev libxext-dev libxft-dev libxinerama-dev libxcursor-dev \
  libxrender-dev libxfixes-dev libfontconfig1-dev libpango1.0-dev libcairo2-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
cargo build --release --locked
./target/release/pair
```

Linux release binaries still use glibc, libstdc++, X11, Pango, Cairo, and
fontconfig supplied by the system. Build on the oldest distribution generation
you intend to support.

The repository also contains a no-sudo helper for a machine that already has
the required development libraries:

```sh
sh scripts/build-linux-user.sh
./target/release/pair
```

## macOS Intel or Apple Silicon

Install the Xcode command-line tools, Rust, CMake, and Ninja:

```sh
xcode-select --install
rustup toolchain install stable --profile minimal --component rustfmt,clippy
MACOSX_DEPLOYMENT_TARGET=12.0 cargo build --release --locked
./target/release/pair
```

GitHub releases package Pair as a minimal `.app` bundle. The current builds are
ad-hoc signed and not notarized.

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

The GUI uses FLTK built from its included C++ source. Image decoding, OpenGL,
and embedded browser support remain disabled.
