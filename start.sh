#!/bin/bash
# =============================================================================
# DDoS Defense System - Quick Start Script
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
NC='\033[0m' # No Color

print_banner() {
    echo -e "${GREEN}"
    echo "=============================================="
    echo "    🛡️  DDoS Defense System"
    echo "=============================================="
    echo -e "${NC}"
}

check_prerequisites() {
    echo "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}ERROR: Docker is not installed${NC}"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${RED}ERROR: Docker Compose is not installed${NC}"
        exit 1
    fi
    
    # Check if running as root (needed for XDP)
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Not running as root. XDP operations may fail.${NC}"
        echo "Consider running: sudo $0 $@"
    fi
    
    echo -e "${GREEN}✓ Prerequisites OK${NC}"
    echo ""
}

detect_network_interface() {
    echo "Detecting network interface..."
    
    # Auto-detect the default network interface
    DETECTED_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [ -z "$DETECTED_INTERFACE" ]; then
        echo -e "${YELLOW}WARNING: Could not auto-detect network interface${NC}"
        echo "Available interfaces:"
        ip link show | grep -E "^[0-9]+" | awk -F: '{print "  " $2}'
        echo ""
        echo "Using default: ens33"
        DETECTED_INTERFACE="ens33"
    fi
    
    export NETWORK_INTERFACE="$DETECTED_INTERFACE"
    export CAPTURE_INTERFACE="$DETECTED_INTERFACE"
    
    echo -e "${GREEN}✓ Using interface: $NETWORK_INTERFACE${NC}"
    echo ""
}

is_cluster_running() {
    cd "$DOCKER_DIR"
    # Check if any of our containers are running
    if docker ps --format '{{.Names}}' | grep -qE "^ddos-(app|redis|elasticsearch|kibana)$"; then
        return 0  # true, cluster is running
    else
        return 1  # false, cluster is not running
    fi
}

clean_data() {
    echo -e "${BLUE}Cleaning data directories...${NC}"
    
    # Remove data
    sudo rm -rf "$DATA_DIR/elasticsearch/"* 2>/dev/null || true
    sudo rm -rf "$DATA_DIR/kibana/"* 2>/dev/null || true
    sudo rm -rf "$DATA_DIR/redis/"* 2>/dev/null || true
    sudo rm -rf "$LOGS_DIR/"* 2>/dev/null || true
    
    # Fix permissions
    sudo chown -R 1000:1000 "$DATA_DIR/elasticsearch" 2>/dev/null || true
    sudo chown -R 1000:1000 "$DATA_DIR/kibana" 2>/dev/null || true
    sudo chown -R 1000:1000 "$DATA_DIR/redis" 2>/dev/null || true
    
    echo -e "${GREEN}✓ Data directories cleaned${NC}"
}

stop_services() {
    echo -e "${BLUE}Stopping DDoS Defense System...${NC}"
    cd "$DOCKER_DIR"
    docker compose down 2>/dev/null || true
    echo -e "${GREEN}✓ Services stopped${NC}"
}

start_services() {
    print_banner
    check_prerequisites
    detect_network_interface
    
    # Check if cluster is already running
    if is_cluster_running; then
        echo -e "${YELLOW}Cluster is already running. Performing fresh restart...${NC}"
        echo ""
        stop_services
        echo ""
        clean_data
        echo ""
    fi
    
    echo -e "${BLUE}Starting DDoS Defense System...${NC}"
    echo ""
    
    cd "$DOCKER_DIR"
    
    # Build and start with detected interface
    NETWORK_INTERFACE="$NETWORK_INTERFACE" CAPTURE_INTERFACE="$CAPTURE_INTERFACE" docker compose up -d --build
    
    echo ""
    echo -e "${GREEN}=============================================="
    echo "  Services Started!"
    echo "==============================================${NC}"
    echo ""
    echo "Network Interface: $NETWORK_INTERFACE"
    echo ""
    echo "Access points:"
    echo "  • Kibana:        http://localhost:5601"
    echo "  • Elasticsearch: http://localhost:9200"
    echo "  • Redis:         localhost:6379"
    echo ""
    echo "Credentials:"
    echo "  • User: elastic"
    echo "  • Pass: jgYsL5-kztDUSd8HyiNd"
    echo ""
    echo "Commands:"
    echo "  • View logs:    $0 logs"
    echo "  • View app logs: $0 logs ddos-app"
    echo "  • Check status: $0 status"
    echo "  • Stop:         $0 down"
    echo "  • Clean restart: $0 clean"
    echo ""
    echo -e "${YELLOW}Tip: Wait 2-3 minutes for Kibana dashboards to be imported${NC}"
    echo ""
}

show_logs() {
    cd "$DOCKER_DIR"
    if [ -z "$2" ]; then
        docker compose logs -f
    else
        docker compose logs -f "${@:2}"
    fi
}

show_status() {
    cd "$DOCKER_DIR"
    echo -e "${BLUE}Container Status:${NC}"
    echo ""
    docker compose ps
    echo ""
    
    # Check if main app is healthy
    if docker exec ddos-app supervisorctl status 2>/dev/null; then
        echo ""
        echo -e "${BLUE}Application processes:${NC}"
    fi
    
    # Show blacklist count
    echo ""
    BLACKLIST_COUNT=$(docker exec ddos-app bpftool map dump name ip_blacklist 2>/dev/null | grep -c "key:" || echo "0")
    echo -e "${BLUE}Blacklisted IPs: ${GREEN}$BLACKLIST_COUNT${NC}"
}

restart_services() {
    echo -e "${BLUE}Restarting DDoS Defense System...${NC}"
    cd "$DOCKER_DIR"
    docker compose restart
    echo -e "${GREEN}✓ Services restarted${NC}"
}

clean_restart() {
    print_banner
    check_prerequisites
    detect_network_interface
    
    echo -e "${YELLOW}Performing clean restart (stop, clean data, start fresh)...${NC}"
    echo ""
    
    stop_services
    echo ""
    clean_data
    echo ""
    
    echo -e "${BLUE}Starting DDoS Defense System...${NC}"
    echo ""
    
    cd "$DOCKER_DIR"
    
    # Build and start with detected interface
    NETWORK_INTERFACE="$NETWORK_INTERFACE" CAPTURE_INTERFACE="$CAPTURE_INTERFACE" docker compose up -d --build
    
    echo ""
    echo -e "${GREEN}=============================================="
    echo "  Fresh Start Complete!"
    echo "==============================================${NC}"
    echo ""
    echo "Network Interface: $NETWORK_INTERFACE"
    echo ""
    echo "Access points:"
    echo "  • Kibana:        http://localhost:5601"
    echo "  • Elasticsearch: http://localhost:9200"
    echo "  • Redis:         localhost:6379"
    echo ""
    echo "Credentials:"
    echo "  • User: elastic"
    echo "  • Pass: jgYsL5-kztDUSd8HyiNd"
    echo ""
    echo -e "${YELLOW}Tip: Wait 2-3 minutes for Kibana dashboards to be imported${NC}"
    echo ""
}

# Main
case "${1:-up}" in
    up|start)
        start_services
        ;;
    down|stop)
        stop_services
        ;;
    logs)
        show_logs "$@"
        ;;
    status|ps)
        show_status
        ;;
    restart)
        restart_services
        ;;
    clean)
        clean_restart
        ;;
    *)
        echo "Usage: $0 [up|down|logs|status|restart|clean]"
        echo ""
        echo "Commands:"
        echo "  up, start   - Start all services (fresh restart if already running)"
        echo "  down, stop  - Stop all services"
        echo "  logs        - Show logs (add service name for specific logs)"
        echo "  status, ps  - Show container status and blacklist count"
        echo "  restart     - Restart all services (keeps data)"
        echo "  clean       - Stop, clean all data, and start fresh"
        exit 1
        ;;
esac
