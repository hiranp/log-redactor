#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Install cross if not already installed
if ! command -v cross &>/dev/null; then
  echo "cross could not be found, installing..."
  cargo install cross
fi

# install zig if not already installed
if ! command -v zigbuild &>/dev/null; then
  echo "zig could not be found, installing..."
  cargo install --locked cargo-zigbuild
fi

# Build for Darwin
echo "Building for macOS..."
# docker run --rm -it -v $(pwd):/io -w /io ghcr.io/rust-cross/cargo-zigbuild \
#   cargo zigbuild --release --target x86_64-apple-darwin
# rustup target add x86_64-apple-darwin
cargo zigbuild --target aarch64-unknown-linux-gnu.2.17

# Build for Linux
echo "Building for Linux..."
cargo zigbuild --target aarch64-unknown-linux-gnu.2.17

# Build for Windows
echo "Building for Windows..."
cargo zigbuild --target aarch64-
