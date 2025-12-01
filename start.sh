#!/bin/bash
# =============================================================================
# DDoS Defense System - Quick Start Script (FIXED & SAFE)
# =============================================================================
# Stops only THIS pipeline’s containers
# Cleans Elasticsearch / Redis / Kibana data
# Fixes ES permissions
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"
DATA_DIR="$SCRIPT_DIR/data"
LOGS_DIR="$SCRIPT_DIR/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CONTAINERS="ddos-app ddos-redis ddos-elasticsearch ddos-kibana"

print_banner() {
    echo -e "${GREEN}"
    echo "=============================================="
    echo "    🛡️  DDoS Defense System"
    echo "=============================================="
    echo -e "${NC}"
}

check_prerequisites() {
    echo "Checking prerequisites..."

    command -v docker >/dev/null || { echo -e "${RED}Docker not installed${NC}"; exit 1; }
    docker compose version >/dev/null || { echo -e "${RED}Docker Compose plugin missing${NC}"; exit 1; }

    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Run with sudo for XDP & permissions${NC}"
        echo "Example: sudo ./start.sh"
    fi

    echo -e "${GREEN}✓ Prerequisites OK${NC}"
    echo ""
}

detect_network_interface() {
    echo "Detecting network interface..."
    DETECTED_INTERFACE=$(ip route | awk '/default/ {print $5}' | head -n1)
    [ -z "$DETECTED_INTERFACE" ] && DETECTED_INTERFACE="ens33"

    export NETWORK_INTERFACE="$DETECTED_INTERFACE"
    export CAPTURE_INTERFACE="$DETECTED_INTERFACE"

    echo -e "${GREEN}✓ Using interface: $NETWORK_INTERFACE${NC}"
    echo ""
}

is_cluster_running() {
    for container in $CONTAINERS; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            return 0
        fi
    done
    return 1
}

stop_services() {
    echo -e "${BLUE}Stopping DDoS containers only...${NC}"

    for container in $CONTAINERS; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            docker stop "$container" >/dev/null 2>&1 || true
            docker rm   "$container" >/dev/null 2>&1 || true
            echo "  ✓ Removed $container"
        fi
    done

    cd "$DOCKER_DIR"
    docker compose down >/dev/null 2>&1 || true

    echo -e "${GREEN}✓ DDoS services stopped${NC}"
}

fix_permissions() {
    echo -e "${BLUE}Fixing data directory permissions...${NC}"

    mkdir -p "$DATA_DIR/elasticsearch" "$DATA_DIR/kibana" "$DATA_DIR/redis" "$LOGS_DIR"

    # Elasticsearch user: 1000:0
    chown -R 1000:0 "$DATA_DIR/elasticsearch"
    chmod -R 775 "$DATA_DIR/elasticsearch"

    # Other services
    chown -R 1000:0 "$DATA_DIR/kibana" "$DATA_DIR/redis"
    chmod -R 775 "$DATA_DIR/kibana" "$DATA_DIR/redis"

    echo -e "${GREEN}✓ Permissions fixed${NC}"
}

clean_data() {
    echo -e "${BLUE}Cleaning data directories...${NC}"

    rm -rf "$DATA_DIR/elasticsearch/"* || true
    rm -rf "$DATA_DIR/kibana/"* || true
    rm -rf "$DATA_DIR/redis/"* || true
    rm -rf "$LOGS_DIR/"* || true

    fix_permissions

    echo -e "${GREEN}✓ Data cleaned${NC}"
}

start_services() {
    print_banner
    check_prerequisites
    detect_network_interface

    if is_cluster_running; then
        echo -e "${YELLOW}Existing DDoS containers detected. Restarting cleanly...${NC}"
        stop_services
        clean_data
    else
        clean_data
    fi

    echo -e "${BLUE}Starting DDoS Defense System...${NC}"
    echo ""

    cd "$DOCKER_DIR"
    NETWORK_INTERFACE="$NETWORK_INTERFACE" CAPTURE_INTERFACE="$CAPTURE_INTERFACE" \
        docker compose up -d --build

    echo ""
    echo -e "${GREEN}=============================================="
    echo "  Services Started!"
    echo "==============================================${NC}"
    echo ""
    echo "Kibana        → http://localhost:5601"
    echo "Elasticsearch → http://localhost:9200"
    echo "Redis         → localhost:6379"
    echo ""
    echo -e "${YELLOW}Wait 2–3 minutes for Elasticsearch healthcheck${NC}"
}

show_logs() {
    cd "$DOCKER_DIR"
    docker compose logs -f "${@:2}"
}

show_status() {
    echo -e "${BLUE}Container Status:${NC}"
    cd "$DOCKER_DIR"
    docker compose ps
    echo ""

    docker inspect --format='Elasticsearch health: {{.State.Health.Status}}' ddos-elasticsearch 2>/dev/null || true
}

restart_services() {
    stop_services
    start_services
}

clean_restart() {
    stop_services
    clean_data
    start_services
}

# =========================
# Entry Point
# =========================
case "${1:-up}" in
    up|start) start_services ;;
    down|stop) stop_services ;;
    logs) show_logs "$@" ;;
    status|ps) show_status ;;
    restart) restart_services ;;
    clean) clean_restart ;;
    *)
        echo "Usage: $0 [up|down|logs|status|restart|clean]"
        exit 1
        ;;
esac