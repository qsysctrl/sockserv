#!/bin/bash
#
# SOCKS5 Fuzzing Script (cargo-fuzz)
# 
# NOTE: cargo-fuzz requires nightly Rust!
#
# Usage:
#   ./scripts/fuzz.sh setup       - Install cargo-fuzz
#   ./scripts/fuzz.sh build       - Build all fuzzing targets
#   ./scripts/fuzz.sh run <target> - Run a specific fuzzing target
#   ./scripts/fuzz.sh list        - List available fuzzing targets
#   ./scripts/fuzz.sh clean       - Clean fuzzing artifacts
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FUZZ_DIR="$PROJECT_DIR/fuzz"
OUTPUT_DIR="$FUZZ_DIR/artifacts"
SEEDS_DIR="$FUZZ_DIR/seeds"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
SOCKS5 Fuzzing Script (cargo-fuzz)

NOTE: This script requires nightly Rust!

Usage:
  ./scripts/fuzz.sh <command> [options]

Commands:
  setup           Install cargo-fuzz (requires nightly Rust)
  build           Build all fuzzing targets
  build <target>  Build a specific fuzzing target
  run <target>    Run a fuzzing target (default: 60 seconds)
  run <target> <time>  Run a fuzzing target for specified time (e.g., 30s, 1m, 1h)
  list            List available fuzzing targets
  clean           Clean fuzzing artifacts
  help            Show this help message

Examples:
  ./scripts/fuzz.sh setup
  ./scripts/fuzz.sh build
  ./scripts/fuzz.sh run fuzz_client_hello
  ./scripts/fuzz.sh run fuzz_request 5m
  ./scripts/fuzz.sh list

Available Targets:
  - fuzz_client_hello  - Fuzz ClientHello parsing
  - fuzz_request       - Fuzz SOCKS request parsing
  - fuzz_response      - Fuzz SOCKS response parsing
  - fuzz_address       - Fuzz SOCKS address parsing

EOF
}

setup_fuzz() {
    print_info "Installing cargo-fuzz (requires nightly Rust)..."
    cargo +nightly install cargo-fuzz
    
    print_info "Setup complete!"
    print_warn "Remember: cargo-fuzz requires nightly Rust for all commands"
}

build_target() {
    local target=$1
    
    if [ -z "$target" ]; then
        print_info "Building all fuzzing targets (nightly)..."
        cd "$FUZZ_DIR"
        cargo +nightly fuzz build
    else
        print_info "Building fuzzing target: $target (nightly)..."
        cd "$FUZZ_DIR"
        cargo +nightly fuzz build "$target"
    fi
    
    print_info "Build complete!"
}

run_fuzz() {
    local target=$1
    local time=${2:-60}
    
    if [ -z "$target" ]; then
        print_error "Please specify a fuzzing target"
        echo "Available targets:"
        list_targets
        exit 1
    fi
    
    print_info "Starting fuzzing target: $target"
    print_info "Max time: $time seconds"
    
    cd "$FUZZ_DIR"
    
    # Run cargo-fuzz
    cargo +nightly fuzz run "$target" -- -max_total_time="$time"
}

list_targets() {
    print_info "Available fuzzing targets:"
    echo ""
    echo "  fuzz_client_hello  - Fuzz ClientHello parsing"
    echo "  fuzz_request       - Fuzz SOCKS request parsing"
    echo "  fuzz_response      - Fuzz SOCKS response parsing"
    echo "  fuzz_address       - Fuzz SOCKS address parsing"
    echo ""
}

clean_fuzz() {
    print_info "Cleaning fuzzing artifacts..."
    
    if [ -d "$OUTPUT_DIR" ]; then
        rm -rf "$OUTPUT_DIR"
        print_info "Removed output directory"
    fi
    
    cd "$FUZZ_DIR"
    cargo clean
    print_info "Cleaned cargo artifacts"
    
    print_info "Clean complete!"
}

# Main command handler
case "${1:-help}" in
    setup)
        setup_fuzz
        ;;
    build)
        build_target "$2"
        ;;
    run)
        run_fuzz "$2" "$3"
        ;;
    list)
        list_targets
        ;;
    clean)
        clean_fuzz
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
