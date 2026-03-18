#!/bin/bash
cd /home/test/development/rust/netstack
echo "=== cargo build ==="
cargo build 2>&1
echo ""
echo "=== cargo test ==="
cargo test 2>&1
echo ""
echo "=== cargo run ==="
cargo run 2>&1
