#!/bin/sh
set -eu

# Installs Rust and CMake under the current user's home directory, then builds
# pair. It deliberately does not attempt to install system GUI headers.

cmake_version=3.31.12
machine=$(uname -m)

case "$machine" in
    aarch64|arm64)
        cmake_arch=aarch64
        ;;
    x86_64|amd64)
        cmake_arch=x86_64
        ;;
    *)
        printf '%s\n' "Unsupported Linux architecture: $machine" >&2
        exit 1
        ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname "$script_dir")
cache_dir=${XDG_CACHE_HOME:-"$HOME/.cache"}/pair-build
cmake_dir="$HOME/.local/cmake-$cmake_version-linux-$cmake_arch"

need_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf '%s\n' "Missing required command: $1" >&2
        printf '%s\n' "This must already be installed by the system administrator." >&2
        exit 1
    fi
}

need_command curl
need_command tar
need_command sha256sum
need_command c++
need_command make
need_command pkg-config

missing_packages=
for package in x11 xext xft xinerama xcursor xrender xfixes fontconfig pango pangoxft cairo pangocairo; do
    if ! pkg-config --exists "$package"; then
        missing_packages="$missing_packages $package"
    fi
done

if [ -n "$missing_packages" ]; then
    printf '%s\n' "Missing native GUI development packages:$missing_packages" >&2
    printf '%s\n' "On Ubuntu/JetPack these normally require the corresponding -dev packages." >&2
    printf '%s\n' "Ask an administrator to install the command shown in README.md, then rerun this script." >&2
    exit 1
fi

mkdir -p "$cache_dir" "$HOME/.local"

if [ ! -x "$cmake_dir/bin/cmake" ]; then
    archive="cmake-$cmake_version-linux-$cmake_arch.tar.gz"
    release="https://github.com/Kitware/CMake/releases/download/v$cmake_version"
    curl --proto '=https' --tlsv1.2 -fL "$release/$archive" -o "$cache_dir/$archive"
    curl --proto '=https' --tlsv1.2 -fL "$release/cmake-$cmake_version-SHA-256.txt" \
        -o "$cache_dir/cmake-$cmake_version-SHA-256.txt"
    (
        cd "$cache_dir"
        grep " $archive\$" "cmake-$cmake_version-SHA-256.txt" | sha256sum -c -
    )
    mkdir -p "$cmake_dir"
    tar -xzf "$cache_dir/$archive" --strip-components=1 -C "$cmake_dir"
fi

PATH="$cmake_dir/bin:$PATH"
export PATH

if ! command -v cargo >/dev/null 2>&1; then
    rustup_script="$cache_dir/rustup-init.sh"
    curl --proto '=https' --tlsv1.2 -fL https://sh.rustup.rs -o "$rustup_script"
    sh "$rustup_script" -y --profile minimal
fi

if [ -f "$HOME/.cargo/env" ]; then
    # rustup's generated file adds the user-local Cargo bin directory to PATH.
    . "$HOME/.cargo/env"
fi

need_command cargo

printf '%s\n' "Building with:"
rustc --version
cargo --version
cmake --version | sed -n '1p'
c++ --version | sed -n '1p'

cd "$project_dir"
CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1}
export CARGO_BUILD_JOBS
cargo build --release --locked

printf '\n%s\n' "Built: $project_dir/target/release/pair"
printf '%s\n' "Run it from the Jetson desktop with:"
printf '  %s\n' "$project_dir/target/release/pair"
