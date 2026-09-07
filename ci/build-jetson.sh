#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates curl git pkg-config \
  libx11-dev libxext-dev libxft-dev libxinerama-dev libxcursor-dev \
  libxrender-dev libxfixes-dev libfontconfig1-dev libpango1.0-dev libcairo2-dev

cmake_version=3.31.12
cmake_archive="cmake-${cmake_version}-linux-aarch64.tar.gz"
cmake_release="https://github.com/Kitware/CMake/releases/download/v${cmake_version}"
curl --proto '=https' --tlsv1.2 -fL "$cmake_release/$cmake_archive" -o "/tmp/$cmake_archive"
curl --proto '=https' --tlsv1.2 -fL "$cmake_release/cmake-${cmake_version}-SHA-256.txt" \
  -o "/tmp/cmake-${cmake_version}-SHA-256.txt"
(
  cd /tmp
  grep " $cmake_archive\$" "cmake-${cmake_version}-SHA-256.txt" | sha256sum -c -
)
mkdir -p /opt/cmake
tar -xzf "/tmp/$cmake_archive" --strip-components=1 -C /opt/cmake
export PATH="/opt/cmake/bin:$PATH"

curl --proto '=https' --tlsv1.2 -fL https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.98.1
. /root/.cargo/env

rustc --version
cmake --version
CARGO_BUILD_JOBS=2 cargo build --release --locked

mkdir -p dist/jetson
cp target/release/pair dist/jetson/pair
cp JETSON.md dist/jetson/JETSON.md
ldd dist/jetson/pair | tee dist/jetson/LINKED-LIBRARIES.txt
chmod -R a+rwX dist
