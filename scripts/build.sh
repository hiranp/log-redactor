#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Install cross if not already installed
if ! command -v cross &>/dev/null; then
  echo "cross could not be found, installing..."
  cargo install cross
fi

# Build for macOS
echo "Building for macOS..."
cross build --target x86_64-apple-darwin --release

# Build for Linux
echo "Building for Linux..."
cross build --target x86_64-unknown-linux-gnu --release

# Build for Windows
echo "Building for Windows..."
cross build --target x86_64-pc-windows-gnu --release

echo "Build completed successfully."

# show compiled binaries
echo "Compiled binaries located in:"
echo "target/x86_64-unknown-linux-gnu/release/ and target/x86_64-pc-windows-gnu/release/ and target/x86_64-apple-darwin/release/"
ls -lRh target/x86_64-unknown-linux-gnu/release/log_redactor* target/x86_64-pc-windows-gnu/release/log_redactor* target/x86_64-apple-darwin/release/log_redactor*

# Copy the compiled binaries to the bin directory
mkdir -p bin/macos-x86_64
mkdir -p bin/linux-x86_64
mkdir -p bin/windows-x86_64
cp -f target/x86_64-apple-darwin/release/log_redactor bin/macos-x86_64/log_redactor
cp -f target/x86_64-unknown-linux-gnu/release/log_redactor bin/linux-x86_64/log_redactor
cp -f target/x86_64-pc-windows-gnu/release/log_redactor.exe bin/windows-x86_64/log_redactor.exe
