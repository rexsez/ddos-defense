# 🛡️ DDoS Defense System - Dockerized

A high-performance, kernel-level DDoS defense system using XDP (eXpress Data Path) for packet filtering and machine learning for attack detection.

## 📋 Prerequisites

- **Docker** and **Docker Compose** installed
- **Linux host** with kernel 5.x+ (for XDP/BPF support)
- **Root/sudo access** (required for XDP operations)
- Minimum **4GB RAM** (Elasticsearch alone needs 2GB)

## 🚀 Quick Start

```bash
# 1. Clone/copy this directory to your machine

# 2. Edit the .env file to set your network interface
nano .env
# Change NETWORK_INTERFACE and CAPTURE_INTERFACE to match your system
# Run 'ip link show' to see available interfaces

# 3. Start everything with one command
cd docker
docker-compose up -d

# 4. Check status
docker-compose ps

# 5. View logs
docker-compose logs -f ddos-app
```

## 🌐 Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| **Kibana** | http://localhost:5601 | elastic / jgYsL5-kztDUSd8HyiNd |
| **Elasticsearch** | http://localhost:9200 | elastic / jgYsL5-kztDUSd8HyiNd |
| **Redis** | localhost:6379 | No auth |

## 📁 Directory Structure

```
ddos-defense/
├── .env                          # Environment configuration
├── docker/
│   ├── docker-compose.yml        # Container orchestration
│   ├── Dockerfile                # Main app container
│   ├── entrypoint.sh             # Startup script
│   └── supervisord.conf          # Process manager config
├── app/
│   ├── xdp_controller.py         # XDP/BPF controller
│   ├── ml_infer_service.py       # ML inference
│   ├── nfstream_agent.py         # Packet capture
│   └── xdp_ip_blacklist_bcc.c    # XDP kernel program
├── models/
│   ├── trained_models.pkl        # AdaBoost model
│   └── preprocessing_objects.pkl # Scaler + features
├── config/
│   ├── elasticsearch/
│   │   └── elasticsearch.yml
│   └── kibana/
│       ├── kibana.yml
│       └── dashboards/
│           └── kibana_dashboards.ndjson
├── data/                         # Persistent data (auto-created)
│   ├── elasticsearch/
│   ├── redis/
│   └── kibana/
└── logs/                         # Application logs
```

## 🔧 Configuration

### Network Interface

Edit `.env` and set your network interface:

```bash
# Find your interface
ip link show

# Edit .env
NETWORK_INTERFACE=eth0      # Change to your interface
CAPTURE_INTERFACE=eth0      # Usually the same
```

### Enforcement Mode

```bash
# In .env
ENFORCEMENT_MODE=SIMULATE   # Log only, don't block (default)
ENFORCEMENT_MODE=BLOCK_MANUAL  # Actually block IPs
```

### ML Confidence Threshold

```bash
# In .env
CONFIDENCE_THRESHOLD=0.65   # Lower = more sensitive, more false positives
```

## 📊 Monitoring

### View Application Logs

```bash
# All services
docker-compose logs -f

# Just the main app
docker-compose logs -f ddos-app

# Inside the container (supervisor logs)
docker exec -it ddos-app tail -f /app/logs/xdp_controller.log
docker exec -it ddos-app tail -f /app/logs/ml_pipeline.log
```

### Check XDP Status

```bash
# Check if XDP is attached
docker exec -it ddos-app ip link show | grep xdp

# Check drop counter
docker exec -it ddos-app bpftool map dump name drop_cnt

# List blacklisted IPs
docker exec -it ddos-app bpftool map dump name ip_blacklist
```

### Kibana Dashboards

1. Open http://localhost:5601
2. Login with elastic / jgYsL5-kztDUSd8HyiNd
3. Go to **Dashboard** in the left menu
4. Your imported dashboards should be there

## 🧪 Testing

### Manual IP Block Test

```bash
# Publish a manual block command to Redis
docker exec -it ddos-redis redis-cli PUBLISH attack_detected '{
  "src_ip": "192.168.1.100",
  "detection_event_id": "test-001",
  "enforcement_mode": "BLOCK_MANUAL"
}'

# Verify in Elasticsearch
curl -u elastic:jgYsL5-kztDUSd8HyiNd \
  "http://localhost:9200/enforcement-blocks-*/_search?size=5&pretty"
```

### Content Filter Test

```bash
# Send packet with "Test Data" payload (will be dropped)
echo "Test Data" | nc localhost 8080

# Check drops
curl -u elastic:jgYsL5-kztDUSd8HyiNd \
  "http://localhost:9200/xdp-drops-*/_search?size=5&pretty"
```

## 🛑 Stopping

```bash
cd docker
docker-compose down

# To also remove volumes (persistent data)
docker-compose down -v
```

## 🐛 Troubleshooting

### "Interface not found"

```bash
# Check available interfaces on host
ip link show

# Update .env with correct interface name
```

### "BPF permission denied"

The container needs to run privileged. This is already configured, but ensure Docker has proper permissions:

```bash
# Check if running as root or in docker group
groups
```

### "Elasticsearch unhealthy"

```bash
# Check ES logs
docker-compose logs elasticsearch

# ES needs time to start (60+ seconds)
# Check health
curl -u elastic:jgYsL5-kztDUSd8HyiNd http://localhost:9200/_cluster/health
```

### "Dashboards not imported"

```bash
# Check importer logs
docker-compose logs dashboard-importer

# Manual import
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -u elastic:jgYsL5-kztDUSd8HyiNd \
  -H "kbn-xsrf: true" \
  --form file=@config/kibana/dashboards/kibana_dashboards.ndjson
```

## 📈 Elasticsearch Indices

| Index Pattern | Description |
|---------------|-------------|
| `enforcement-blocks-*` | IP block decisions |
| `xdp-drops-*` | Per-packet drop events |
| `netflows-*` | All classified network flows |

## 🔒 Security Notes

- This setup uses **hardcoded passwords** for simplicity
- For production, use Docker secrets or environment injection
- The ddos-app container runs **privileged** (required for XDP)
- XDP operates at kernel level - use with caution

## 📚 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Host Network (privileged)                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    ddos-app container                    │    │
│  │  ┌──────────┐    ┌──────────┐    ┌──────────────────┐   │    │
│  │  │ NFStream │───▶│ ML Model │───▶│  XDP Controller  │   │    │
│  │  │ (capture)│    │(AdaBoost)│    │  (BPF maps)      │   │    │
│  │  └──────────┘    └──────────┘    └──────────────────┘   │    │
│  │       │               │                   │             │    │
│  └───────┼───────────────┼───────────────────┼─────────────┘    │
│          │               │                   │                   │
│          │               ▼                   ▼                   │
│          │         ┌──────────┐        ┌──────────┐             │
│          │         │  Redis   │        │   XDP    │             │
│          │         │ (pubsub) │        │ (kernel) │             │
│          │         └──────────┘        └──────────┘             │
│          │               │                                       │
│          ▼               ▼                                       │
│    ┌───────────────────────────┐                                │
│    │      Elasticsearch        │                                │
│    │  (logs, metrics, drops)   │                                │
│    └───────────────────────────┘                                │
│                  │                                               │
│                  ▼                                               │
│           ┌──────────┐                                          │
│           │  Kibana  │                                          │
│           │(dashboard)│                                          │
│           └──────────┘                                          │
└─────────────────────────────────────────────────────────────────┘
```
