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
# Wait for Redis
# =============================================================================
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
echo "SUCCESS: Redis is ready!"
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
echo "SUCCESS: Elasticsearch is ready!"
echo ""

# =============================================================================
# Setup Kibana System User Password
# =============================================================================
echo "Setting up kibana_system user password..."
curl -s -X POST "${ES_HOST}/_security/user/kibana_system/_password" \
    -u "${ES_USER}:${ES_PASS}" \
    -H "Content-Type: application/json" \
    -d '{"password": "'"${KIBANA_SYSTEM_PASS}"'"}' > /dev/null 2>&1 \
    && echo "  kibana_system password configured" \
    || echo "  kibana_system password may already be set"
echo ""

# =============================================================================
# Verify Network Interface Exists
# =============================================================================
echo "Checking network interface: ${NETWORK_INTERFACE}"
if ! ip link show ${NETWORK_INTERFACE} > /dev/null 2>&1; then
    echo "WARNING: Interface ${NETWORK_INTERFACE} not found!"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+" | awk -F: '{print "  " $2}'
    echo ""
fi
echo ""

# =============================================================================
# Create Index Templates in Elasticsearch
# =============================================================================
echo "Setting up Elasticsearch index templates..."

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
    }' > /dev/null 2>&1 && echo "  Created enforcement-blocks template" || echo "  Template may already exist"

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
    }' > /dev/null 2>&1 && echo "  Created xdp-drops template" || echo "  Template may already exist"

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
    }' > /dev/null 2>&1 && echo "  Created netflows template" || echo "  Template may already exist"

echo ""

# =============================================================================
# Wait for Kibana and Import Dashboards
# =============================================================================

echo "Waiting for Kibana..."
KIBANA_URL="http://localhost:5601"
ATTEMPT=0
MAX_KIBANA_ATTEMPTS=90

while [ $ATTEMPT -lt $MAX_KIBANA_ATTEMPTS ]; do
    if curl -s -u "elastic:${ES_PASS}" "$KIBANA_URL/api/status" | grep -q '"available"'; then
        echo "SUCCESS: Kibana is ready!"
        break
    fi
    ATTEMPT=$((ATTEMPT+1))
    sleep 2
    if [ $((ATTEMPT % 10)) -eq 0 ]; then
        echo "  Attempt $ATTEMPT/$MAX_KIBANA_ATTEMPTS..."
    fi
done

# =============================================================================
# Validate dashboard file
# =============================================================================

DASHBOARD_FILE="/app/dashboards/kibana_dashboards.ndjson"

echo ""
echo "=============================================="
echo " Validating Dashboard File"
echo "=============================================="

if [ ! -f "$DASHBOARD_FILE" ]; then
    echo "WARNING: Dashboard file not found, skipping import"
else
    if [ ! -r "$DASHBOARD_FILE" ]; then
        echo "WARNING: Dashboard file is not readable, skipping import"
    else
        SIZE=$(stat -c%s "$DASHBOARD_FILE")
        if [ "$SIZE" -lt 100 ]; then
            echo "WARNING: Dashboard file too small ($SIZE bytes), skipping import"
        else
            echo "✅ File validation passed"
            
            # Import dashboards
            echo ""
            echo "Importing dashboards to Kibana..."

            HTTP_CODE=$(curl -s -o /tmp/import_response.json -w "%{http_code}" \
                -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
                -u "elastic:${ES_PASS}" \
                -H "kbn-xsrf: true" \
                -H "Accept: application/json" \
                -F "file=@${DASHBOARD_FILE};type=application/ndjson"
            )

            if [ "$HTTP_CODE" = "200" ]; then
                echo "✅ Dashboards imported successfully!"
            else
                echo "WARNING: Dashboard import returned HTTP $HTTP_CODE"
            fi
        fi
    fi
fi

# =============================================================================
# Insert Demo Data Directly to Elasticsearch
# =============================================================================

echo ""
echo "=============================================="
echo " Inserting Demo Data"
echo "=============================================="

CURRENT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
DATE_INDEX=$(date -u +%Y.%m.%d)

# Generate UUIDs
DEMO_DETECTION_UUID=$(cat /proc/sys/kernel/random/uuid)
DROP_ID_1=$(cat /proc/sys/kernel/random/uuid)
DROP_ID_2=$(cat /proc/sys/kernel/random/uuid)

echo "  Timestamp: $CURRENT_TIMESTAMP"
echo "  Detection ID: $DEMO_DETECTION_UUID"
echo "  Drop ID 1 (Content Filter): $DROP_ID_1"
echo "  Drop ID 2 (IP Blacklist): $DROP_ID_2"
echo ""

# 1. Insert enforcement block record
echo "Inserting enforcement block record..."
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
    && echo "  ✅ Enforcement block record inserted" \
    || echo "  WARNING: Failed to insert enforcement block record"

# 2. Insert XDP drop record - CONTENT_FILTER (no detection_event_id)
echo "Inserting XDP drop record (Content Filter)..."
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
    && echo "  ✅ XDP drop record (Content Filter) inserted" \
    || echo "  WARNING: Failed to insert XDP drop record (Content Filter)"

# 3. Insert XDP drop record - IP_BLACKLIST (with detection_event_id)
echo "Inserting XDP drop record (IP Blacklist)..."
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
    && echo "  ✅ XDP drop record (IP Blacklist) inserted" \
    || echo "  WARNING: Failed to insert XDP drop record (IP Blacklist)"

echo ""
echo "✅ All demo data inserted successfully"
echo ""

# =============================================================================
# Start Services via Supervisor
# =============================================================================

echo "=============================================="
echo "  Starting Services via Supervisor"
echo "=============================================="
echo ""
echo "Services:"
echo "  1. XDP Controller - Kernel-level packet filtering"
echo "  2. ML Pipeline    - NFStream -> ML Inference"
echo ""
echo "Logs available at: /app/logs/"
echo "=============================================="

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/ddos-defense.conf

