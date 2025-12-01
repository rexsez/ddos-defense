#!/bin/bash
# =============================================================================
# DDoS Defense System - Enhanced Start Script (CO-RE/libbpf)
# =============================================================================
# Features:
# - Automated NIC discovery
# - XDP program build verification
# - Container-safe operations
# - Clean restarts with data cleanup
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"
DATA_DIR="$SCRIPT_DIR/data"
LOGS_DIR="$SCRIPT_DIR/logs"

# XDP files should be in root directory alongside start.sh
XDP_SOURCE="$SCRIPT_DIR/xdp_ip_blacklist_bcc.c"
XDP_OUTPUT="$SCRIPT_DIR/xdp_ip_blacklist.o"
VMLINUX_H="$SCRIPT_DIR/vmlinux.h"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONTAINERS="ddos-app ddos-redis ddos-elasticsearch ddos-kibana"

# =============================================================================
# Helper Functions
# =============================================================================

print_banner() {
    echo -e "${GREEN}"
    echo "=============================================="
    echo "    🛡️  DDoS Defense System (CO-RE/libbpf)"
    echo "=============================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

# =============================================================================
# Prerequisites Check
# =============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Docker
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker not installed"
        echo "Install: https://docs.docker.com/engine/install/"
        exit 1
    fi

    # Docker Compose
    if ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose plugin missing"
        echo "Install: sudo apt-get install docker-compose-plugin"
        exit 1
    fi

    # Root check
    if [ "$EUID" -ne 0 ]; then
        log_warning "Not running as root - XDP and permissions may fail"
        echo "         Run with: sudo $0 $*"
        echo ""
    fi

    log_success "Prerequisites OK"
    echo ""
}

# =============================================================================
# XDP Build Check
# =============================================================================

check_xdp_build() {
    log_info "Checking XDP program build status..."

    if [ ! -f "$XDP_OUTPUT" ]; then
        log_warning "XDP object file not found: $XDP_OUTPUT"
        echo ""
        log_info "Attempting to build XDP program..."
        build_xdp_program
    else
        # Check if source is newer than object
        if [ "$XDP_SOURCE" -nt "$XDP_OUTPUT" ]; then
            log_warning "XDP source modified since last build"
            log_info "Rebuilding XDP program..."
            build_xdp_program
        else
            log_success "XDP object file up to date"
        fi
    fi
    echo ""
}

build_xdp_program() {
    log_info "Building XDP program with CO-RE/libbpf..."

    # Check build dependencies
    local missing_deps=()
    for cmd in clang llvm-strip bpftool; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing build dependencies: ${missing_deps[*]}"
        echo ""
        echo "Install with:"
        echo "  Ubuntu/Debian: sudo apt-get install clang llvm bpftool libbpf-dev"
        echo "  Fedora/RHEL:   sudo dnf install clang llvm bpftool libbpf-devel"
        echo ""
        echo "Or run the provided build script: ./build_xdp.sh"
        exit 1
    fi

    # Generate vmlinux.h if needed
    if [ ! -f "$VMLINUX_H" ]; then
        log_info "Generating vmlinux.h from kernel BTF..."
        
        if [ ! -f /sys/kernel/btf/vmlinux ]; then
            log_error "/sys/kernel/btf/vmlinux not found"
            echo ""
            echo "Your kernel doesn't have BTF support enabled."
            echo "Solutions:"
            echo "  1. Use kernel with CONFIG_DEBUG_INFO_BTF=y"
            echo "  2. Download vmlinux.h from: https://github.com/aquasecurity/btfhub"
            exit 1
        fi
        
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_H"
        log_success "Generated $VMLINUX_H"
    fi

    # Compile XDP program
    log_info "Compiling: $XDP_SOURCE -> $XDP_OUTPUT"
    
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include/bpf \
        -I"$(dirname "$VMLINUX_H")" \
        -c "$XDP_SOURCE" \
        -o "$XDP_OUTPUT"
    
    # Strip debug symbols (optional, reduces size)
    llvm-strip -g "$XDP_OUTPUT" 2>/dev/null || true

    log_success "XDP program compiled successfully"
    ls -lh "$XDP_OUTPUT"
    echo ""
}

# =============================================================================
# Network Interface Detection
# =============================================================================

detect_network_interface() {
    log_info "Detecting network interface..."

    # Try multiple methods to find the default interface
    DETECTED_INTERFACE=""

    # Method 1: ip route (most reliable)
    DETECTED_INTERFACE=$(ip route | awk '/default/ {print $5}' | head -n1)

    # Method 2: Check for common interface names if method 1 fails
    if [ -z "$DETECTED_INTERFACE" ]; then
        for iface in eth0 ens33 ens160 enp0s3 wlan0; do
            if ip link show "$iface" >/dev/null 2>&1; then
                DETECTED_INTERFACE="$iface"
                break
            fi
        done
    fi

    # Fallback
    if [ -z "$DETECTED_INTERFACE" ]; then
        log_warning "Could not auto-detect interface, using default: ens33"
        DETECTED_INTERFACE="ens33"
    fi

    export NETWORK_INTERFACE="$DETECTED_INTERFACE"
    export CAPTURE_INTERFACE="$DETECTED_INTERFACE"

    log_success "Using interface: $NETWORK_INTERFACE"
    
    # Show interface details
    log_info "Interface details:"
    ip addr show "$NETWORK_INTERFACE" | grep -E "inet |link/ether" | sed 's/^/         /'
    echo ""
}

# =============================================================================
# Container Management
# =============================================================================

is_cluster_running() {
    for container in $CONTAINERS; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            return 0
        fi
    done
    return 1
}

stop_services() {
    log_info "Stopping DDoS containers..."

    for container in $CONTAINERS; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            docker stop "$container" >/dev/null 2>&1 || true
            docker rm "$container" >/dev/null 2>&1 || true
            echo "  ✓ Removed $container"
        fi
    done

    cd "$DOCKER_DIR"
    docker compose down >/dev/null 2>&1 || true

    log_success "DDoS services stopped"
    echo ""
}

# =============================================================================
# Data Directory Management
# =============================================================================

fix_permissions() {
    log_info "Fixing data directory permissions..."

    mkdir -p "$DATA_DIR/elasticsearch" "$DATA_DIR/kibana" "$DATA_DIR/redis" "$LOGS_DIR"

    # Elasticsearch requires uid 1000
    chown -R 1000:0 "$DATA_DIR/elasticsearch"
    chmod -R 775 "$DATA_DIR/elasticsearch"

    # Other services
    chown -R 1000:0 "$DATA_DIR/kibana" "$DATA_DIR/redis"
    chmod -R 775 "$DATA_DIR/kibana" "$DATA_DIR/redis"

    log_success "Permissions fixed"
    echo ""
}

clean_data() {
    log_info "Cleaning data directories..."

    rm -rf "$DATA_DIR/elasticsearch/"* 2>/dev/null || true
    rm -rf "$DATA_DIR/kibana/"* 2>/dev/null || true
    rm -rf "$DATA_DIR/redis/"* 2>/dev/null || true
    rm -rf "$LOGS_DIR/"* 2>/dev/null || true

    fix_permissions

    log_success "Data cleaned"
    echo ""
}

# =============================================================================
# Service Startup
# =============================================================================

start_services() {
    print_banner
    check_prerequisites
    detect_network_interface
    check_xdp_build

    if is_cluster_running; then
        log_warning "Existing DDoS containers detected"
        log_info "Performing clean restart..."
        stop_services
        clean_data
    else
        clean_data
    fi

    log_info "Starting DDoS Defense System..."
    echo ""

    cd "$DOCKER_DIR"
    
    # Export variables for docker-compose
    export NETWORK_INTERFACE
    export CAPTURE_INTERFACE
    
    # Build and start
    docker compose build --no-cache
    docker compose up -d

    echo ""
    log_success "Services started!"
    echo ""
    echo -e "${CYAN}=============================================="
    echo "  Service Endpoints"
    echo "==============================================${NC}"
    echo "  Kibana        → http://localhost:5601"
    echo "  Elasticsearch → http://localhost:9200"
    echo "  Redis         → localhost:6379"
    echo ""
    echo -e "${CYAN}Network Configuration:${NC}"
    echo "  Interface: $NETWORK_INTERFACE"
    echo ""
    echo -e "${YELLOW}⏳ Wait 2-3 minutes for Elasticsearch to be ready${NC}"
    echo ""
    echo "Monitor logs with: sudo $0 logs"
}

# =============================================================================
# Status & Monitoring
# =============================================================================

show_logs() {
    cd "$DOCKER_DIR"
    if [ $# -gt 1 ]; then
        docker compose logs -f "${@:2}"
    else
        docker compose logs -f
    fi
}

show_status() {
    echo -e "${CYAN}Container Status:${NC}"
    cd "$DOCKER_DIR"
    docker compose ps
    echo ""

    log_info "Health Checks:"
    
    # Check Elasticsearch
    if docker inspect --format='{{.State.Health.Status}}' ddos-elasticsearch 2>/dev/null | grep -q "healthy"; then
        log_success "Elasticsearch: healthy"
    else
        log_warning "Elasticsearch: not ready"
    fi
    
    # Check Redis
    if docker inspect --format='{{.State.Health.Status}}' ddos-redis 2>/dev/null | grep -q "healthy"; then
        log_success "Redis: healthy"
    else
        log_warning "Redis: not ready"
    fi
    
    # Check XDP in app container
    if docker ps --format '{{.Names}}' | grep -q "^ddos-app$"; then
        if docker exec ddos-app bpftool prog show 2>/dev/null | grep -q "xdp"; then
            log_success "XDP program: loaded"
        else
            log_warning "XDP program: not loaded"
        fi
    fi
    
    echo ""
}

# =============================================================================
# Additional Commands
# =============================================================================

restart_services() {
    stop_services
    start_services
}

clean_restart() {
    stop_services
    clean_data
    start_services
}

rebuild_xdp() {
    log_info "Force rebuilding XDP program..."
    rm -f "$XDP_OUTPUT" "$VMLINUX_H"
    build_xdp_program
    log_success "XDP rebuilt - restart services to apply"
}

# =============================================================================
# Help
# =============================================================================

show_help() {
    cat << EOF
Usage: sudo $0 [COMMAND]

Commands:
  up, start       Start all services (default)
  down, stop      Stop all services
  restart         Restart services without cleaning data
  clean           Clean restart (wipes all data)
  logs [service]  Show logs (optional: specific service)
  status, ps      Show container status
  rebuild-xdp     Force rebuild XDP program
  help            Show this help

Examples:
  sudo $0 up              # Start everything
  sudo $0 logs ddos-app   # Watch app logs
  sudo $0 clean           # Fresh start
  sudo $0 rebuild-xdp     # Rebuild XDP after code changes

EOF
}

# =============================================================================
# Entry Point
# =============================================================================

case "${1:-up}" in
    up|start)       start_services ;;
    down|stop)      stop_services ;;
    logs)           show_logs "$@" ;;
    status|ps)      show_status ;;
    restart)        restart_services ;;
    clean)          clean_restart ;;
    rebuild-xdp)    rebuild_xdp ;;
    help|-h|--help) show_help ;;
    *)
        log_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac