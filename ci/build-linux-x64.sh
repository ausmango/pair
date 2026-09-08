#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates curl git pkg-config \
  libx11-dev libxext-dev libxft-dev libxinerama-dev libxcursor-dev \
  libxrender-dev libxfixes-dev libfontconfig1-dev libpango1.0-dev libcairo2-dev

cmake_version=3.31.12
archive="cmake-${cmake_version}-linux-x86_64.tar.gz"
release="https://github.com/Kitware/CMake/releases/download/v${cmake_version}"
curl --proto '=https' --tlsv1.2 -fL "$release/$archive" -o "/tmp/$archive"
curl --proto '=https' --tlsv1.2 -fL "$release/cmake-${cmake_version}-SHA-256.txt" -o "/tmp/cmake-sha256.txt"
(cd /tmp && grep " $archive\$" cmake-sha256.txt | sha256sum -c -)
mkdir -p /opt/cmake
tar -xzf "/tmp/$archive" --strip-components=1 -C /opt/cmake
export PATH="/opt/cmake/bin:$PATH"

curl --proto '=https' --tlsv1.2 -fL https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.88.0
. /root/.cargo/env
cargo build --release --locked

mkdir -p dist/linux-x64/package
cp target/release/pair README.md LICENSE dist/linux-x64/package/
cp assets/pair-logo-512.png dist/linux-x64/package/pair-logo.png
cp scripts/install-linux-desktop.sh dist/linux-x64/package/install-desktop.sh
chmod 0755 dist/linux-x64/package/install-desktop.sh
tar -czf dist/pair-linux-x64.tar.gz -C dist/linux-x64/package .
chmod -R a+rwX dist
