#!/bin/bash
# =============================================================================
# DDoS Defense Application Entrypoint
# =============================================================================

set -e

echo "=============================================="
echo "  DDoS Defense System - Starting"
echo "=============================================="
echo ""
echo "Configuration:"
echo "  Network Interface: ${NETWORK_INTERFACE}"
echo "  Capture Interface: ${CAPTURE_INTERFACE}"
echo "  Redis: ${REDIS_HOST}:${REDIS_PORT}"
echo "  Elasticsearch: ${ES_HOST}"
echo "  Confidence Threshold: ${CONFIDENCE_THRESHOLD}"
echo "  Enforcement Mode: ${ENFORCEMENT_MODE:-SIMULATE}"
echo ""

# =============================================================================
# Validate XDP/BPF Dependencies
# =============================================================================
echo "=============================================="
echo " Validating XDP/BPF Dependencies"
echo "=============================================="
echo ""

# Check bpftool
if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool not found in container"
    echo "This means the auto-detection failed or docker-compose.override.yml is missing"
    echo ""
    echo "Solution: Run ./detect_xdp_deps.sh on the host before starting"
    exit 1
fi
echo "✓ bpftool available: $(which bpftool)"

# Check BTF
if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
    echo "ERROR: Kernel BTF not mounted at /sys/kernel/btf/vmlinux"
    echo "This is required for CO-RE XDP programs"
    exit 1
fi
echo "✓ Kernel BTF mounted"

# Check BPF filesystem
if [ ! -d "/sys/fs/bpf" ]; then
    echo "WARNING: /sys/fs/bpf not mounted, creating..."
    mkdir -p /sys/fs/bpf || true
fi

# Mount bpffs if not already mounted
if ! mount | grep -q "bpf on /sys/fs/bpf"; then
    echo "Mounting BPF filesystem..."
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || echo "  (may already be mounted from host)"
fi
echo "✓ BPF filesystem ready"

# Check XDP object file
if [ ! -f "${XDP_OBJECT_PATH}" ]; then
    echo "ERROR: XDP object file not found: ${XDP_OBJECT_PATH}"
    echo ""
    echo "Solution: Run ./build_xdp.sh on the host before starting"
    exit 1
fi

# Validate object file
SIZE=$(stat -c%s "${XDP_OBJECT_PATH}")
if [ "$SIZE" -lt 100 ]; then
    echo "ERROR: XDP object file too small ($SIZE bytes) - may be corrupted"
    exit 1
fi
echo "✓ XDP object file valid: ${XDP_OBJECT_PATH} ($SIZE bytes)"

echo ""
echo "✓ All XDP/BPF dependencies validated"
echo ""

# =============================================================================
# Wait for Redis
# =============================================================================
echo "=============================================="
echo " Waiting for Dependencies"
echo "=============================================="
echo ""
echo "Waiting for Redis..."
MAX_ATTEMPTS=60
ATTEMPT=0

until redis-cli -h ${REDIS_HOST} -p ${REDIS_PORT} ping > /dev/null 2>&1; do
    ATTEMPT=$((ATTEMPT+1))
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
        echo "ERROR: Redis did not become available in time"
        exit 1
    fi
    echo "  Attempt $ATTEMPT/$MAX_ATTEMPTS - Redis not ready, waiting..."
    sleep 2
done
echo "✓ Redis is ready!"
echo ""

# =============================================================================
# Wait for Elasticsearch
# =============================================================================
echo "Waiting for Elasticsearch..."
ATTEMPT=0

until curl -s -u "${ES_USER}:${ES_PASS}" "${ES_HOST}/_cluster/health" > /dev/null 2>&1; do
    ATTEMPT=$((ATTEMPT+1))
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
        echo "ERROR: Elasticsearch did not become available in time"
        exit 1
    fi
    echo "  Attempt $ATTEMPT/$MAX_ATTEMPTS - Elasticsearch not ready, waiting..."
    sleep 5
done
echo "✓ Elasticsearch is ready!"
echo ""

# =============================================================================
# Setup Kibana System User Password
# =============================================================================
echo "Setting up kibana_system user password..."
curl -s -X POST "${ES_HOST}/_security/user/kibana_system/_password" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d '{"password": "'"${KIBANA_SYSTEM_PASS}"'"}' > /dev/null 2>&1 \
    && echo "  ✓ kibana_system password configured" \
    || echo "  (password may already be set)"
echo ""

# =============================================================================
# Verify Network Interface Exists
# =============================================================================
echo "=============================================="
echo " Network Interface Validation"
echo "=============================================="
echo ""
echo "Checking network interface: ${NETWORK_INTERFACE}"

if ! ip link show ${NETWORK_INTERFACE} > /dev/null 2>&1; then
    echo "ERROR: Interface ${NETWORK_INTERFACE} not found!"
    echo ""
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+" | awk -F: '{print "  " $2}'
    echo ""
    echo "This is a critical error. The system cannot start without a valid interface."
    echo ""
    echo "Solution:"
    echo "  1. Check your .env file in docker/ directory"
    echo "  2. Update NETWORK_INTERFACE to match an available interface"
    echo "  3. Restart with: sudo ./start.sh"
    echo ""
    exit 1
fi

echo "✓ Interface ${NETWORK_INTERFACE} is available"

# Show interface details
echo ""
echo "Interface details:"
ip addr show ${NETWORK_INTERFACE} | grep -E "inet |link/" | sed 's/^/  /'
echo ""

# =============================================================================
# Create Index Templates in Elasticsearch
# =============================================================================
echo "=============================================="
echo " Elasticsearch Setup"
echo "=============================================="
echo ""
echo "Creating index templates..."

curl -s -X PUT "${ES_HOST}/_index_template/enforcement-blocks-template" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d '{
        "index_patterns": ["enforcement-blocks-*"],
        "template": {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "detection_event_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "confidence": {"type": "float"},
                    "source": {"type": "keyword"},
                    "enforcement_mode": {"type": "keyword"}
                }
            }
        }
    }' > /dev/null 2>&1 && echo "  ✓ Created enforcement-blocks template" || echo "  (template may already exist)"

curl -s -X PUT "${ES_HOST}/_index_template/xdp-drops-template" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d '{
        "index_patterns": ["xdp-drops-*"],
        "template": {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event_type": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "drop_reason": {"type": "keyword"},
                    "detection_event_id": {"type": "keyword"},
                    "drop_id": {"type": "keyword"}
                }
            }
        }
    }' > /dev/null 2>&1 && echo "  ✓ Created xdp-drops template" || echo "  (template may already exist)"

curl -s -X PUT "${ES_HOST}/_index_template/netflows-template" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d '{
        "index_patterns": ["netflows-*"],
        "template": {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "protocol": {"type": "integer"},
                    "prediction": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "detection_event_id": {"type": "keyword"}
                }
            }
        }
    }' > /dev/null 2>&1 && echo "  ✓ Created netflows template" || echo "  (template may already exist)"

echo ""

# =============================================================================
# Wait for Kibana and Import Dashboards
# =============================================================================

echo "=============================================="
echo " Kibana Setup"
echo "=============================================="
echo ""
echo "Waiting for Kibana..."
echo "NOTE: On low-resource systems (< 2GB RAM), Kibana may take 5-10 minutes to start"
echo ""

KIBANA_URL="http://localhost:5601"
ATTEMPT=0
MAX_KIBANA_ATTEMPTS=180  # Increased from 90 to 180 (6 minutes total)

while [ $ATTEMPT -lt $MAX_KIBANA_ATTEMPTS ]; do
    # Try to get status
    STATUS=$(curl -s -u "elastic:${ES_PASS}" "$KIBANA_URL/api/status" 2>/dev/null || echo "")
    
    if echo "$STATUS" | grep -q '"available"'; then
        echo "✓ Kibana is ready!"
        break
    fi
    
    ATTEMPT=$((ATTEMPT+1))
    sleep 2
    
    # Show progress every 15 attempts (30 seconds)
    if [ $((ATTEMPT % 15)) -eq 0 ]; then
        ELAPSED=$((ATTEMPT * 2))
        echo "  ⏳ Waiting ${ELAPSED}s / $((MAX_KIBANA_ATTEMPTS * 2))s..."
        
        # Show helpful status from logs every minute
        if [ $((ATTEMPT % 30)) -eq 0 ]; then
            KIBANA_STATUS=$(docker logs ddos-kibana 2>&1 | tail -5 | grep -E "(Starting|Optimizing|available)" | tail -1 || echo "Kibana is starting...")
            echo "     Status: $KIBANA_STATUS"
        fi
    fi
done

if [ $ATTEMPT -ge $MAX_KIBANA_ATTEMPTS ]; then
    echo ""
    echo "⚠️  WARNING: Kibana did not become available in time"
    echo ""
    echo "This is likely due to low system resources (you have 1GB RAM / 1 CPU)"
    echo "Kibana may still be starting in the background."
    echo ""
    echo "To check status:"
    echo "  docker logs -f ddos-kibana"
    echo ""
    echo "To manually import dashboards once Kibana is ready:"
    echo "  curl -X POST \"http://localhost:5601/api/saved_objects/_import?overwrite=true\" \\"
    echo "    -u \"elastic:${ES_PASS}\" \\"
    echo "    -H \"kbn-xsrf: true\" \\"
    echo "    -F \"file=@/app/config/kibana/dashboards/kibana_dashboards.ndjson\""
    echo ""
    echo "Continuing with system startup..."
    echo ""
else
    # =============================================================================
    # Validate and Import Dashboard
    # =============================================================================
    
    DASHBOARD_FILE="/app/config/kibana/dashboards/kibana_dashboards.ndjson"
    
    echo ""
    echo "Importing dashboards..."
    
    if [ ! -f "$DASHBOARD_FILE" ]; then
        echo "WARNING: Dashboard file not found, skipping import"
    elif [ ! -r "$DASHBOARD_FILE" ]; then
        echo "WARNING: Dashboard file is not readable, skipping import"
    else
        SIZE=$(stat -c%s "$DASHBOARD_FILE")
        if [ "$SIZE" -lt 100 ]; then
            echo "WARNING: Dashboard file too small ($SIZE bytes), skipping import"
        else
            HTTP_CODE=$(curl -s -o /tmp/import_response.json -w "%{http_code}" \
                -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
                -u "elastic:${ES_PASS}" \
                -H "kbn-xsrf: true" \
                -H "Accept: application/json" \
                -F "file=@${DASHBOARD_FILE};type=application/ndjson"
            )
            
            if [ "$HTTP_CODE" = "200" ]; then
                echo "✓ Dashboards imported successfully!"
            else
                echo "WARNING: Dashboard import returned HTTP $HTTP_CODE"
                cat /tmp/import_response.json 2>/dev/null || true
            fi
        fi
    fi
fi

echo ""

# =============================================================================
# Insert Demo Data Directly to Elasticsearch
# =============================================================================

echo "=============================================="
echo " Demo Data Insertion"
echo "=============================================="
echo ""

CURRENT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
DATE_INDEX=$(date -u +%Y.%m.%d)

# Generate UUIDs
DEMO_DETECTION_UUID=$(cat /proc/sys/kernel/random/uuid)
DROP_ID_1=$(cat /proc/sys/kernel/random/uuid)
DROP_ID_2=$(cat /proc/sys/kernel/random/uuid)

echo "Inserting demo data..."
echo "  Timestamp: $CURRENT_TIMESTAMP"
echo "  Detection ID: $DEMO_DETECTION_UUID"
echo ""

# 1. Insert enforcement block record
curl -s -X POST "${ES_HOST}/enforcement-blocks-${DATE_INDEX}/_doc" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d "{
        \"@timestamp\": \"${CURRENT_TIMESTAMP}\",
        \"detection_event_id\": \"${DEMO_DETECTION_UUID}\",
        \"event_type\": \"MANUAL_ENFORCEMENT\",
        \"src_ip\": \"1.2.3.4\",
        \"confidence\": 0.88,
        \"source\": \"DEMO_STARTUP\",
        \"enforcement_mode\": \"BLOCK_MANUAL\"
    }" > /dev/null 2>&1 \
    && echo "  ✓ Enforcement block record" \
    || echo "  ✗ Failed to insert enforcement block"

# 2. Insert XDP drop record - CONTENT_FILTER
curl -s -X POST "${ES_HOST}/xdp-drops-${DATE_INDEX}/_doc" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d "{
        \"@timestamp\": \"${CURRENT_TIMESTAMP}\",
        \"event_type\": \"PACKET_DROPPED\",
        \"src_ip\": \"5.6.7.8\",
        \"drop_reason\": \"CONTENT_FILTER\",
        \"detection_event_id\": null,
        \"drop_id\": \"${DROP_ID_1}\"
    }" > /dev/null 2>&1 \
    && echo "  ✓ XDP drop (Content Filter)" \
    || echo "  ✗ Failed to insert XDP drop"

# 3. Insert XDP drop record - IP_BLACKLIST
curl -s -X POST "${ES_HOST}/xdp-drops-${DATE_INDEX}/_doc" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d "{
        \"@timestamp\": \"${CURRENT_TIMESTAMP}\",
        \"event_type\": \"PACKET_DROPPED\",
        \"src_ip\": \"1.2.3.4\",
        \"drop_reason\": \"IP_BLACKLIST\",
        \"detection_event_id\": \"${DEMO_DETECTION_UUID}\",
        \"drop_id\": \"${DROP_ID_2}\"
    }" > /dev/null 2>&1 \
    && echo "  ✓ XDP drop (IP Blacklist)" \
    || echo "  ✗ Failed to insert XDP drop"

echo ""
echo "✓ Demo data insertion complete"
echo ""

# =============================================================================
# Final Summary
# =============================================================================

echo "=============================================="
echo "  Startup Complete - Starting Services"
echo "=============================================="
echo ""
echo "Configuration Summary:"
echo "  • Network Interface: ${NETWORK_INTERFACE}"
echo "  • XDP Program:       ${XDP_OBJECT_PATH}"
echo "  • Enforcement Mode:  ${ENFORCEMENT_MODE}"
echo "  • ML Threshold:      ${CONFIDENCE_THRESHOLD}"
echo ""
echo "Services starting:"
echo "  1. XDP Controller - Kernel packet filtering"
echo "  2. ML Pipeline    - NFStream → ML Inference"
echo ""
echo "Logs: /app/logs/"
echo "=============================================="
echo ""

# =============================================================================
# Start Services via Supervisor
# =============================================================================

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/ddos-defense.conf