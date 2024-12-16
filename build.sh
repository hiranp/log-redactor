#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Install cross if not already installed
if ! command -v cross &>/dev/null; then
  echo "cross could not be found, installing..."
  cargo install cross
fi

# Build for Linux
echo "Building for Linux..."
cross build --target x86_64-unknown-linux-gnu --release

# Build for Windows
echo "Building for Windows..."
cross build --target x86_64-pc-windows-gnu --release

echo "Build completed successfully."

# show compiled binaries
echo "Compiled binaries:"
ls -lh target/x86_64-unknown-linux-gnu/release/
ls -lh target/x86_64-pc-windows-gnu/release/
