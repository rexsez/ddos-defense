#!/bin/bash
# =============================================================================
# DDoS Defense System - Quick Start Script (FIXED)
# =============================================================================
# Usage: ./start.sh [up|down|logs|status|restart|clean]
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"
DATA_DIR="$SCRIPT_DIR/data"
LOGS_DIR="$SCRIPT_DIR/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
        echo -e "${YELLOW}WARNING: Not running as root. XDP may fail.${NC}"
        echo "Run with: sudo $0 $@"
    fi

    echo -e "${GREEN}✓ Prerequisites OK${NC}"
    echo ""
}

detect_network_interface() {
    echo "Detecting network interface..."
    DETECTED_INTERFACE=$(ip route | awk '/default/ {print $5}' | head -n1)

    if [ -z "$DETECTED_INTERFACE" ]; then
        echo -e "${YELLOW}WARNING: No interface detected, fallback: ens33${NC}"
        DETECTED_INTERFACE="ens33"
    fi

    export NETWORK_INTERFACE="$DETECTED_INTERFACE"
    export CAPTURE_INTERFACE="$DETECTED_INTERFACE"

    echo -e "${GREEN}✓ Using interface: $NETWORK_INTERFACE${NC}"
    echo ""
}

is_cluster_running() {
    cd "$DOCKER_DIR"
    docker compose ps --services --filter "status=running" | grep -q ddos && return 0 || return 1
}

clean_data() {
    echo -e "${BLUE}Cleaning data directories...${NC}"

    # Ensure directories exist
    mkdir -p "$DATA_DIR/elasticsearch" "$DATA_DIR/kibana" "$DATA_DIR/redis" "$LOGS_DIR"

    # Remove data
    rm -rf "$DATA_DIR/elasticsearch/"* "$DATA_DIR/kibana/"* "$DATA_DIR/redis/"* "$LOGS_DIR/"* || true

    # FIXED PERMISSIONS (Elasticsearch runs as 1000:0)
    chown -R 1000:0 "$DATA_DIR/elasticsearch"
    chown -R 1000:0 "$DATA_DIR/kibana"
    chown -R 1000:0 "$DATA_DIR/redis"

    chmod -R 775 "$DATA_DIR/elasticsearch" "$DATA_DIR/kibana" "$DATA_DIR/redis"

    echo -e "${GREEN}✓ Data cleaned and permissions fixed${NC}"
}

stop_services() {
    echo -e "${BLUE}Stopping services...${NC}"
    cd "$DOCKER_DIR"
    docker compose down || true
    echo -e "${GREEN}✓ Stopped${NC}"
}

start_services() {
    print_banner
    check_prerequisites
    detect_network_interface

    if is_cluster_running; then
        echo -e "${YELLOW}Cluster already running → clean restart${NC}"
        stop_services
        clean_data
    fi

    echo -e "${BLUE}Starting services...${NC}"
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
    echo "User: elastic"
    echo "Pass: jgYsL5-kztDUSd8HyiNd"
    echo ""
    echo -e "${YELLOW}Wait 2–3 minutes for ES and dashboards${NC}"
    echo ""
}

show_logs() {
    cd "$DOCKER_DIR"
    docker compose logs -f "${@:2}"
}

show_status() {
    cd "$DOCKER_DIR"
    docker compose ps
    echo ""

    if docker ps | grep -q ddos-app; then
        docker exec ddos-app supervisorctl status || true
        COUNT=$(docker exec ddos-app bpftool map dump name ip_blacklist 2>/dev/null | grep -c "key:" || true)
        echo -e "${GREEN}Blocked IPs: $COUNT${NC}"
    else
        echo -e "${YELLOW}ddos-app not running${NC}"
    fi
}

restart_services() {
    echo -e "${BLUE}Restarting services...${NC}"
    cd "$DOCKER_DIR"
    docker compose restart
    echo -e "${GREEN}✓ Restarted${NC}"
}

clean_restart() {
    print_banner
    check_prerequisites
    detect_network_interface
    stop_services
    clean_data
    start_services
}

# ================== ENTRY ==================
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
