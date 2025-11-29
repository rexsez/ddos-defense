#!/bin/bash
# =============================================================================
# Blacklist Management Script
# =============================================================================
# Usage:
#   ./manage_blacklist.sh list              - List all blocked IPs
#   ./manage_blacklist.sh remove-ip <IP>    - Remove IP from blacklist
#   ./manage_blacklist.sh block-ip <IP>     - Add IP to blacklist
# =============================================================================

# Function to convert integer to IP address
int_to_ip() {
    local int=$1
    printf "%d.%d.%d.%d" \
        $((int & 255)) \
        $((int >> 8 & 255)) \
        $((int >> 16 & 255)) \
        $((int >> 24 & 255))
}

# Function to convert two 64-bit integers to UUID
int_to_uuid() {
    local high=$1
    local low=$2
    printf "%016x%016x" "$high" "$low" | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/'
}

case "$1" in
    list)
        echo "=== Currently Blacklisted IPs ==="
        echo ""
        
        # Get raw output from bpftool
        RAW_OUTPUT=$(docker exec ddos-app bpftool map dump name ip_blacklist 2>/dev/null)
        
        if [ -z "$RAW_OUTPUT" ] || [ "$RAW_OUTPUT" = "[]" ]; then
            echo "  (no IPs blacklisted)"
            exit 0
        fi
        
        # Parse and display each entry
        echo "$RAW_OUTPUT" | grep -E '"key"|"detection_event_id_high"|"detection_event_id_low"|"drop_count"' | \
        while read -r line; do
            if echo "$line" | grep -q '"key"'; then
                KEY=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
                IP=$(int_to_ip $KEY)
            elif echo "$line" | grep -q '"detection_event_id_high"'; then
                HIGH=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
            elif echo "$line" | grep -q '"detection_event_id_low"'; then
                LOW=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
            elif echo "$line" | grep -q '"drop_count"'; then
                DROP_COUNT=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
                UUID=$(int_to_uuid $HIGH $LOW)
                printf "  %-15s | Detection ID: %s | Drops: %s\n" "$IP" "$UUID" "$DROP_COUNT"
            fi
        done
        
        echo ""
        COUNT=$(echo "$RAW_OUTPUT" | grep -c '"key"' || echo "0")
        echo "  Total: $COUNT IP(s) blacklisted"
        ;;
    
    remove-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 remove-ip <IP_ADDRESS>"
            exit 1
        fi
        IP="$2"
        # Convert IP to hex bytes (little-endian)
        HEX=$(echo "$IP" | awk -F. '{printf "%02x %02x %02x %02x", $1, $2, $3, $4}')
        echo "Removing $IP from blacklist..."
        docker exec ddos-app bpftool map delete name ip_blacklist key hex $HEX 2>/dev/null \
            && echo "✅ Removed $IP" \
            || echo "❌ Failed to remove $IP (may not exist)"
        ;;
    
    block-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 block-ip <IP_ADDRESS>"
            exit 1
        fi
        IP="$2"
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo "Blocking $IP with detection ID: $UUID"
        docker exec ddos-redis redis-cli PUBLISH attack_detected \
            "{\"src_ip\": \"$IP\", \"detection_event_id\": \"$UUID\", \"enforcement_mode\": \"BLOCK_MANUAL\", \"confidence\": 1.0}"
        echo "✅ Block command sent"
        ;;
    
    *)
        echo "Usage: $0 {list|remove-ip|block-ip} [IP_ADDRESS]"
        echo ""
        echo "Commands:"
        echo "  list              - List all blocked IPs"
        echo "  remove-ip <IP>    - Remove IP from blacklist"
        echo "  block-ip <IP>     - Add IP to blacklist"
        exit 1
        ;;
esac
