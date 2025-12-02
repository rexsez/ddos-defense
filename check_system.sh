#!/bin/bash
# =============================================================================
# System Compatibility Checker for DDoS Defense System
# =============================================================================
# Validates that your system meets all requirements before installation
# Run this before attempting to build or deploy the system
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
WARN=0
FAIL=0

log_info() { echo -e "${BLUE}[CHECK]${NC} $1"; }
log_pass() { echo -e "${GREEN}[✓ PASS]${NC} $1"; PASS=$((PASS+1)); }
log_warn() { echo -e "${YELLOW}[⚠ WARN]${NC} $1"; WARN=$((WARN+1)); }
log_fail() { echo -e "${RED}[✗ FAIL]${NC} $1"; FAIL=$((FAIL+1)); }

echo "=============================================="
echo "  DDoS Defense System Compatibility Check"
echo "=============================================="
echo ""
echo "Kernel: $(uname -r)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Architecture: $(uname -m)"
echo ""
echo "=============================================="
echo ""

# =============================================================================
# 1. Operating System
# =============================================================================
log_info "Checking operating system..."

if [ "$(uname -s)" != "Linux" ]; then
    log_fail "Must be running on Linux (found: $(uname -s))"
else
    log_pass "Linux OS detected"
fi

if [ "$(uname -m)" != "x86_64" ]; then
    log_warn "Non-x86_64 architecture may have limited support (found: $(uname -m))"
else
    log_pass "x86_64 architecture"
fi

echo ""

# =============================================================================
# 2. Kernel Version
# =============================================================================
log_info "Checking kernel version..."

KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
MAJOR=$(echo $KERNEL_VERSION | cut -d'.' -f1)
MINOR=$(echo $KERNEL_VERSION | cut -d'.' -f2)

if [ "$MAJOR" -lt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 2 ]); then
    log_fail "Kernel 5.2+ required for BTF support (found: $KERNEL_VERSION)"
else
    log_pass "Kernel version $KERNEL_VERSION meets minimum requirement (5.2+)"
fi

echo ""

# =============================================================================
# 3. Docker
# =============================================================================
log_info "Checking Docker..."

if ! command -v docker &> /dev/null; then
    log_fail "Docker not installed"
    echo ""
    echo "  Install Docker:"
    echo "    curl -fsSL https://get.docker.com | sh"
    echo "    sudo usermod -aG docker \$USER"
else
    DOCKER_VERSION=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    log_pass "Docker installed: $DOCKER_VERSION"
    
    # Check if Docker daemon is running
    if docker ps &> /dev/null; then
        log_pass "Docker daemon is running"
    else
        log_fail "Docker daemon is not running or permission denied"
        echo ""
        echo "  Start Docker:"
        echo "    sudo systemctl start docker"
        echo "    sudo systemctl enable docker"
    fi
fi

echo ""

# =============================================================================
# 4. Docker Compose
# =============================================================================
log_info "Checking Docker Compose..."

if docker compose version &> /dev/null; then
    COMPOSE_VERSION=$(docker compose version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    log_pass "Docker Compose installed: $COMPOSE_VERSION"
elif command -v docker-compose &> /dev/null; then
    log_warn "Old docker-compose detected, please upgrade to Docker Compose V2"
    COMPOSE_VERSION=$(docker-compose version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "  Current: $COMPOSE_VERSION"
else
    log_fail "Docker Compose not installed"
    echo ""
    echo "  Install Docker Compose V2:"
    echo "    sudo apt-get update"
    echo "    sudo apt-get install docker-compose-plugin"
fi

echo ""

# =============================================================================
# 5. Root/Sudo Access
# =============================================================================
log_info "Checking privileges..."

if [ "$EUID" -eq 0 ]; then
    log_pass "Running as root"
elif sudo -n true 2>/dev/null; then
    log_pass "Sudo access available (passwordless)"
elif sudo -v &> /dev/null; then
    log_pass "Sudo access available"
else
    log_fail "No root or sudo access"
    echo ""
    echo "  XDP/eBPF requires root privileges"
    echo "  Add your user to sudoers or run as root"
fi

echo ""

# =============================================================================
# 6. bpftool
# =============================================================================
log_info "Checking bpftool..."

BPFTOOL_FOUND=false
BPFTOOL_LOCATIONS=(
    "/usr/sbin/bpftool"
    "/usr/bin/bpftool"
    "/sbin/bpftool"
    "/usr/lib/linux-tools/$(uname -r)/bpftool"
    "/usr/lib/linux-tools-$(uname -r)/bpftool"
)

for dir in /usr/lib/linux-tools-*; do
    if [ -d "$dir" ] && [ -f "$dir/bpftool" ]; then
        BPFTOOL_LOCATIONS+=("$dir/bpftool")
    fi
done

for path in "${BPFTOOL_LOCATIONS[@]}"; do
    if [ -f "$path" ] && [ -x "$path" ]; then
        log_pass "bpftool found: $path"
        BPFTOOL_FOUND=true
        break
    fi
done

if [ "$BPFTOOL_FOUND" = false ]; then
    log_fail "bpftool not found"
    echo ""
    echo "  Install bpftool:"
    echo "    Ubuntu/Debian: sudo apt-get install linux-tools-\$(uname -r)"
    echo "    Fedora/RHEL:   sudo dnf install bpftool"
    echo "    Arch:          sudo pacman -S bpf"
fi

echo ""

# =============================================================================
# 7. Kernel BTF Support
# =============================================================================
log_info "Checking kernel BTF support..."

if [ -f "/sys/kernel/btf/vmlinux" ]; then
    SIZE=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || stat -f%z /sys/kernel/btf/vmlinux 2>/dev/null)
    log_pass "Kernel BTF available: /sys/kernel/btf/vmlinux ($SIZE bytes)"
else
    log_fail "Kernel BTF not available"
    echo ""
    echo "  Your kernel was not compiled with CONFIG_DEBUG_INFO_BTF=y"
    echo ""
    echo "  Solutions:"
    echo "    1. Upgrade to a kernel with BTF support"
    echo "    2. Ubuntu: sudo apt-get install linux-generic-hwe-22.04"
    echo "    3. Check: zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF"
fi

# Check kernel config if available
if [ -f "/proc/config.gz" ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_DEBUG_INFO_BTF=y"; then
        log_pass "CONFIG_DEBUG_INFO_BTF=y in kernel config"
    fi
elif [ -f "/boot/config-$(uname -r)" ]; then
    if grep -q "CONFIG_DEBUG_INFO_BTF=y" "/boot/config-$(uname -r)"; then
        log_pass "CONFIG_DEBUG_INFO_BTF=y in kernel config"
    fi
fi

echo ""

# =============================================================================
# 8. BPF Filesystem
# =============================================================================
log_info "Checking BPF filesystem..."

if [ -d "/sys/fs/bpf" ]; then
    log_pass "/sys/fs/bpf directory exists"
    
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_pass "BPF filesystem already mounted"
    else
        log_warn "BPF filesystem not mounted (will be mounted automatically)"
    fi
else
    log_warn "/sys/fs/bpf does not exist (will be created automatically)"
fi

echo ""

# =============================================================================
# 9. Required Build Tools
# =============================================================================
log_info "Checking build tools for XDP compilation..."

TOOLS=("clang" "llvm-strip")
for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        VERSION=$($tool --version | head -1)
        log_pass "$tool found: $VERSION"
    else
        log_fail "$tool not found"
        echo ""
        echo "  Install build tools:"
        echo "    Ubuntu/Debian: sudo apt-get install clang llvm"
        echo "    Fedora/RHEL:   sudo dnf install clang llvm"
    fi
done

echo ""

# =============================================================================
# 10. Network Interface
# =============================================================================
log_info "Checking network interfaces..."

INTERFACES=$(ip link show | grep -E "^[0-9]+" | awk -F: '{print $2}' | tr -d ' ' | grep -v "^lo$")

if [ -z "$INTERFACES" ]; then
    log_fail "No network interfaces found (other than loopback)"
else
    log_pass "Network interfaces available:"
    echo "$INTERFACES" | while read -r iface; do
        STATE=$(ip link show $iface | grep -oE "state [A-Z]+" | awk '{print $2}')
        if [ "$STATE" = "UP" ]; then
            echo "    ✓ $iface (UP)"
        else
            echo "    • $iface ($STATE)"
        fi
    done
fi

echo ""

# =============================================================================
# 11. Python Dependencies (in container)
# =============================================================================
log_info "Checking Python (will be installed in container)..."

if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | grep -oE '[0-9]+\.[0-9]+')
    log_pass "Python 3 available on host: $PYTHON_VERSION (note: not required, only for testing)"
else
    log_warn "Python 3 not found on host (not critical - Docker will provide it)"
fi

echo ""

# =============================================================================
# 12. Memory and CPU
# =============================================================================
log_info "Checking system resources..."

TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))

if [ $TOTAL_MEM_GB -lt 4 ]; then
    log_warn "Only ${TOTAL_MEM_GB}GB RAM available (4GB minimum, 8GB recommended)"
else
    log_pass "${TOTAL_MEM_GB}GB RAM available"
fi

CPU_CORES=$(nproc)
if [ $CPU_CORES -lt 2 ]; then
    log_warn "Only $CPU_CORES CPU core(s) available (2 minimum, 4 recommended)"
else
    log_pass "$CPU_CORES CPU cores available"
fi

echo ""

# =============================================================================
# 13. Disk Space
# =============================================================================
log_info "Checking disk space..."

DISK_AVAIL_KB=$(df "$SCRIPT_DIR" | tail -1 | awk '{print $4}')
DISK_AVAIL_GB=$((DISK_AVAIL_KB / 1024 / 1024))

if [ $DISK_AVAIL_GB -lt 10 ]; then
    log_warn "Only ${DISK_AVAIL_GB}GB disk space available (20GB recommended)"
else
    log_pass "${DISK_AVAIL_GB}GB disk space available"
fi

echo ""

# =============================================================================
# 14. Required Files
# =============================================================================
log_info "Checking project files..."

REQUIRED_FILES=(
    "build_xdp.sh"
    "start.sh"
    "detect_xdp_deps.sh"
    "manage_blacklist.sh"
    "app/xdp_ip_blacklist.c"
    "app/xdp_controller.py"
    "app/nfstream_agent.py"
    "app/ml_infer_service.py"
    "docker/Dockerfile"
    "docker/docker-compose.yml"
    "docker/entrypoint.sh"
    "docker/.env"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$file" ]; then
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -eq 0 ]; then
    log_pass "All required files present"
else
    log_fail "Missing required files:"
    for file in "${MISSING_FILES[@]}"; do
        echo "    ✗ $file"
    done
fi

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================="
echo "  Compatibility Check Summary"
echo "=============================================="
echo ""
echo -e "${GREEN}Passed:  $PASS${NC}"
echo -e "${YELLOW}Warnings: $WARN${NC}"
echo -e "${RED}Failed:   $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ Your system is compatible!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. ./build_xdp.sh          # Compile XDP program"
    echo "  2. sudo ./start.sh         # Start the system"
    echo ""
elif [ $FAIL -le 2 ]; then
    echo -e "${YELLOW}⚠ Your system has minor issues${NC}"
    echo ""
    echo "You can proceed, but fix the issues above for best results."
    echo ""
else
    echo -e "${RED}✗ Your system has compatibility issues${NC}"
    echo ""
    echo "Please fix the failed checks above before proceeding."
    echo ""
fi

exit $FAIL