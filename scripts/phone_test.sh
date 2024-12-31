#!/bin/bash

# Test selection from arguments
# Example: ./scripts/phone_test.sh test_phone_formats
if [ $# -eq 0 ]; then
  echo "No arguments supplied - running all tests"
  cargo test --package log_redactor --test test_phone -- tests --show-output
else
  echo "Running test: $1"
  export RUST_BACKTRACE=full
  export RUST_LOG=debug
  cargo test --package log_redactor --test test_phone -- tests::"$1" --exact --show-output
fi
