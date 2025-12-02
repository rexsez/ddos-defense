#!/bin/bash
# =============================================================================
# XDP Dependency Auto-Detection Script
# =============================================================================
# Detects and validates all XDP/BPF dependencies needed for the system
# Generates docker-compose.override.yml with correct volume mounts
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"
OVERRIDE_FILE="$DOCKER_DIR/docker-compose.override.yml"
ENV_FILE="$DOCKER_DIR/.env"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "=============================================="
echo "  XDP Dependency Detection"
echo "=============================================="
echo ""

# =============================================================================
# 1. Detect bpftool
# =============================================================================
log_info "Detecting bpftool..."

BPFTOOL_PATH=""
BPFTOOL_LOCATIONS=(
    "/usr/sbin/bpftool"
    "/usr/bin/bpftool"
    "/sbin/bpftool"
    "/usr/lib/linux-tools/$(uname -r)/bpftool"
    "/usr/lib/linux-tools-$(uname -r)/bpftool"
)

# Also check in linux-tools directories
for dir in /usr/lib/linux-tools-*; do
    if [ -d "$dir" ] && [ -f "$dir/bpftool" ]; then
        BPFTOOL_LOCATIONS+=("$dir/bpftool")
    fi
done

# Find first available bpftool
for path in "${BPFTOOL_LOCATIONS[@]}"; do
    if [ -f "$path" ] && [ -x "$path" ]; then
        BPFTOOL_PATH="$path"
        break
    fi
done

if [ -z "$BPFTOOL_PATH" ]; then
    log_error "bpftool not found!"
    echo ""
    echo "Install bpftool:"
    echo "  Ubuntu/Debian: sudo apt-get install linux-tools-common linux-tools-\$(uname -r)"
    echo "  Fedora/RHEL:   sudo dnf install bpftool"
    echo ""
    exit 1
fi

log_success "Found bpftool: $BPFTOOL_PATH"

# =============================================================================
# 2. Detect Kernel BTF
# =============================================================================
log_info "Checking kernel BTF support..."

BTF_PATH="/sys/kernel/btf/vmlinux"
if [ ! -f "$BTF_PATH" ]; then
    log_error "Kernel BTF not found at $BTF_PATH"
    echo ""
    echo "Your kernel doesn't have BTF (BPF Type Format) support."
    echo ""
    echo "Solutions:"
    echo "  1. Use a kernel with CONFIG_DEBUG_INFO_BTF=y (5.2+)"
    echo "  2. Upgrade your kernel to a BTF-enabled version"
    echo "  3. Check: zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF"
    echo ""
    exit 1
fi

log_success "Kernel BTF available: $BTF_PATH"

# =============================================================================
# 3. Check BPF filesystem
# =============================================================================
log_info "Checking BPF filesystem..."

BPF_FS="/sys/fs/bpf"
if [ ! -d "$BPF_FS" ]; then
    log_warning "BPF filesystem directory not found, will be created"
fi

# Check if mounted
if mount | grep -q "bpf on $BPF_FS"; then
    log_success "BPF filesystem already mounted"
else
    log_warning "BPF filesystem not mounted (will be mounted by container)"
fi

# =============================================================================
# 4. Check for XDP object file
# =============================================================================
log_info "Checking XDP object file..."

XDP_OBJECT="$SCRIPT_DIR/app/xdp_ip_blacklist.o"
if [ ! -f "$XDP_OBJECT" ]; then
    log_warning "XDP object file not found: $XDP_OBJECT"
    echo ""
    echo "You need to compile the XDP program first:"
    echo "  ./build_xdp.sh"
    echo ""
    echo "Proceeding anyway (will fail at runtime)..."
else
    log_success "XDP object file exists: $XDP_OBJECT"
    
    # Check file size
    SIZE=$(stat -c%s "$XDP_OBJECT" 2>/dev/null || stat -f%z "$XDP_OBJECT" 2>/dev/null)
    if [ "$SIZE" -lt 100 ]; then
        log_error "XDP object file too small ($SIZE bytes) - may be corrupted"
        exit 1
    fi
    log_success "XDP object file size: $SIZE bytes"
fi

# =============================================================================
# 5. Check vmlinux.h
# =============================================================================
log_info "Checking vmlinux.h..."

VMLINUX_H="$SCRIPT_DIR/app/vmlinux.h"
if [ ! -f "$VMLINUX_H" ]; then
    log_warning "vmlinux.h not found"
    echo ""
    echo "To rebuild XDP program, you need vmlinux.h:"
    echo "  ./build_xdp.sh"
    echo ""
else
    log_success "vmlinux.h exists"
fi

# =============================================================================
# 6. Detect debugfs
# =============================================================================
log_info "Checking kernel debugfs..."

DEBUGFS_PATH="/sys/kernel/debug"
if [ ! -d "$DEBUGFS_PATH" ]; then
    log_warning "Debugfs not available (optional for advanced debugging)"
else
    log_success "Debugfs available: $DEBUGFS_PATH"
fi

# =============================================================================
# 7. Detect kernel headers
# =============================================================================
log_info "Checking kernel headers..."

KERNEL_VERSION=$(uname -r)
KERNEL_HEADERS="/lib/modules/$KERNEL_VERSION/build"

if [ ! -d "$KERNEL_HEADERS" ]; then
    log_warning "Kernel headers not found (optional, only needed for rebuilding)"
else
    log_success "Kernel headers available"
fi

# =============================================================================
# 8. Generate docker-compose.override.yml
# =============================================================================
echo ""
log_info "Generating docker-compose.override.yml..."

cat > "$OVERRIDE_FILE" << EOF
# =============================================================================
# Auto-generated Docker Compose Override
# =============================================================================
# Generated by: detect_xdp_deps.sh
# Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Kernel: $(uname -r)
# =============================================================================
# DO NOT EDIT MANUALLY - This file is auto-generated
# Re-run ./detect_xdp_deps.sh to regenerate
# =============================================================================

services:
  ddos-app:
    volumes:
      # Auto-detected bpftool
      - ${BPFTOOL_PATH}:/usr/sbin/bpftool:ro
      
      # Kernel BTF (required for CO-RE)
      - ${BTF_PATH}:${BTF_PATH}:ro
      
      # BPF filesystem (required for map pinning)
      - ${BPF_FS}:${BPF_FS}:rw
EOF

# Add debugfs if available
if [ -d "$DEBUGFS_PATH" ]; then
    cat >> "$OVERRIDE_FILE" << EOF
      
      # Kernel debugfs (optional, for advanced debugging)
      - ${DEBUGFS_PATH}:${DEBUGFS_PATH}:ro
EOF
fi

cat >> "$OVERRIDE_FILE" << EOF

    environment:
      # Auto-detected paths
      - BPFTOOL_PATH=/usr/sbin/bpftool
      - BTF_PATH=${BTF_PATH}
      - BPF_FS=${BPF_FS}
      - KERNEL_VERSION=${KERNEL_VERSION}
EOF

log_success "Generated: $OVERRIDE_FILE"

# =============================================================================
# 9. Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  Detection Complete!"
echo "=============================================="
echo ""
echo "Summary:"
echo "  ✓ bpftool:      $BPFTOOL_PATH"
echo "  ✓ Kernel BTF:   $BTF_PATH"
echo "  ✓ BPF FS:       $BPF_FS"
echo "  ✓ Kernel:       $KERNEL_VERSION"
if [ -f "$XDP_OBJECT" ]; then
    echo "  ✓ XDP Object:   $XDP_OBJECT"
else
    echo "  ⚠ XDP Object:   NOT FOUND (run ./build_xdp.sh)"
fi
echo ""
echo "Files generated:"
echo "  • $OVERRIDE_FILE"
echo ""
echo "Next steps:"
if [ ! -f "$XDP_OBJECT" ]; then
    echo "  1. Build XDP program: ./build_xdp.sh"
    echo "  2. Start system:      sudo ./start.sh"
else
    echo "  1. Start system:      sudo ./start.sh"
fi
echo ""