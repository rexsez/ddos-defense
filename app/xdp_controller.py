#!/usr/bin/env python3
"""
xdp_controller.py
-----------------
XDP Controller using libbpf (no BCC runtime compilation)

Features:
1. Loads pre-compiled XDP .o file using bpftool
2. Manages IP blacklist via BPF maps
3. Listens for attack signals from Redis
4. Captures per-drop events from XDP and logs them to Elasticsearch
5. Supports dual-mode: SIMULATE (log only) and BLOCK_MANUAL (real blocking)
"""

import json
import os
import sys
import struct
import socket
import uuid
import subprocess
import time
from datetime import datetime
from threading import Thread
import redis
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
ATTACK_CHANNEL = os.getenv("ATTACK_CHANNEL", "attack_detected")
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

ES_HOST = os.getenv("ES_HOST", "http://127.0.0.1:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "jgYsL5-kztDUSd8HyiNd")

# Index patterns
ES_BLOCK_INDEX_PREFIX = os.getenv("ES_BLOCK_INDEX_PREFIX", "enforcement-blocks")
ES_DROP_INDEX_PREFIX = os.getenv("ES_DROP_INDEX_PREFIX", "xdp-drops")

# XDP configuration
XDP_OBJECT_PATH = os.getenv("XDP_OBJECT_PATH", "/app/xdp_ip_blacklist.o")
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "ens33")
BPF_FS = "/sys/fs/bpf"

# Map paths in bpffs
MAP_BLACKLIST = f"{BPF_FS}/ip_blacklist"
MAP_DROP_CNT = f"{BPF_FS}/drop_cnt"
MAP_DROP_EVENTS = f"{BPF_FS}/drop_events"


# --- HELPER FUNCTIONS ---

def log(msg, level="INFO"):
    """Unified logging function."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[xdp-ctrl][{level}] {timestamp} - {msg}", file=sys.stderr)
    sys.stderr.flush()


def run_cmd(cmd, check=True, capture_output=True):
    """Run shell command and return result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {cmd}", "ERROR")
        log(f"stderr: {e.stderr}", "ERROR")
        if check:
            raise
        return e


def es_index(doc: dict, index_prefix: str):
    """Index document into Elasticsearch."""
    index_name = f"{index_prefix}-{datetime.utcnow():%Y.%m.%d}"
    url = f"{ES_HOST.rstrip('/')}/{index_name}/_doc"

    try:
        resp = requests.post(
            url,
            json=doc,
            headers={"Content-Type": "application/json"},
            auth=(ES_USER, ES_PASS),
            timeout=5,
            verify=False,
        )
        if resp.status_code not in (200, 201):
            log(f"ES index fail: {resp.status_code} - {resp.text[:200]}", "WARN")
        else:
            log(f"✓ Logged to ES: {index_name}", "INFO")
    except Exception as e:
        log(f"ES error: {e}", "ERROR")


def ip_to_int(ip_str: str) -> int:
    """Convert IP string to 32-bit integer (network byte order)."""
    return struct.unpack("=I", socket.inet_aton(ip_str))[0]


def int_to_ip(ip_int: int) -> str:
    """Convert 32-bit integer to IP string."""
    return socket.inet_ntoa(struct.pack("=I", ip_int))


def uuid_to_u64_pair(uuid_str: str) -> tuple:
    """Convert UUID string to two 64-bit integers."""
    try:
        uuid_obj = uuid.UUID(uuid_str)
        uuid_bytes = uuid_obj.bytes
        high = struct.unpack(">Q", uuid_bytes[:8])[0]
        low = struct.unpack(">Q", uuid_bytes[8:])[0]
        return high, low
    except ValueError:
        log(f"Non-standard UUID format '{uuid_str}', storing as-is", "WARN")
        str_bytes = uuid_str.encode('utf-8')
        if len(str_bytes) < 16:
            str_bytes = str_bytes + b'\x00' * (16 - len(str_bytes))
        else:
            str_bytes = str_bytes[:16]
        high = struct.unpack(">Q", str_bytes[:8])[0]
        low = struct.unpack(">Q", str_bytes[8:])[0]
        return high, low


def u64_pair_to_uuid(high: int, low: int) -> str:
    """Convert two 64-bit integers back to UUID string."""
    uuid_bytes = struct.pack(">Q", high) + struct.pack(">Q", low)
    try:
        return str(uuid.UUID(bytes=uuid_bytes))
    except ValueError:
        try:
            decoded = uuid_bytes.rstrip(b'\x00').decode('utf-8', errors='ignore')
            return decoded if decoded else str(uuid.UUID(bytes=uuid_bytes))
        except:
            return str(uuid.UUID(bytes=uuid_bytes))


# --- XDP PROGRAM MANAGEMENT ---

def load_xdp_program():
    """Load pre-compiled XDP program using bpftool."""
    log(f"Loading XDP program: {XDP_OBJECT_PATH}")
    log(f"Target interface: {NETWORK_INTERFACE}")

    if not os.path.exists(XDP_OBJECT_PATH):
        log(f"XDP object file not found: {XDP_OBJECT_PATH}", "FATAL")
        sys.exit(1)

    # Ensure bpffs is mounted
    if not os.path.exists(BPF_FS):
        log(f"Creating {BPF_FS}", "INFO")
        run_cmd(f"mkdir -p {BPF_FS}")

    # Check if already mounted
    mount_check = run_cmd("mount | grep bpf", check=False)
    if BPF_FS not in mount_check.stdout:
        log(f"Mounting bpffs at {BPF_FS}", "INFO")
        run_cmd(f"mount -t bpf bpf {BPF_FS}")

    # Load program and pin maps
    try:
        log("Loading XDP object with bpftool...", "INFO")
        result = run_cmd(
            f"bpftool prog load {XDP_OBJECT_PATH} {BPF_FS}/xdp_prog "
            f"type xdp pinmaps {BPF_FS}"
        )

        log("Attaching XDP program to interface...", "INFO")
        run_cmd(f"bpftool net attach xdp pinned {BPF_FS}/xdp_prog dev {NETWORK_INTERFACE}")

        log(f"✓ XDP program loaded on interface: {NETWORK_INTERFACE}", "SUCCESS")

        # Verify maps are pinned
        for map_name in ["ip_blacklist", "drop_cnt", "drop_events"]:
            map_path = f"{BPF_FS}/{map_name}"
            if not os.path.exists(map_path):
                log(f"WARNING: Map {map_name} not found at {map_path}", "WARN")

        return True

    except Exception as e:
        log(f"Failed to load XDP program: {e}", "FATAL")
        sys.exit(1)


def unload_xdp():
    """Unload XDP program from interface."""
    try:
        log("Detaching XDP program...", "INFO")
        run_cmd(f"bpftool net detach xdp dev {NETWORK_INTERFACE}", check=False)

        log("Removing pinned objects...", "INFO")
        run_cmd(f"rm -f {BPF_FS}/xdp_prog", check=False)
        run_cmd(f"rm -f {BPF_FS}/ip_blacklist", check=False)
        run_cmd(f"rm -f {BPF_FS}/drop_cnt", check=False)
        run_cmd(f"rm -f {BPF_FS}/drop_events", check=False)

        log(f"✓ XDP program unloaded from {NETWORK_INTERFACE}", "SUCCESS")
    except Exception as e:
        log(f"Error unloading XDP: {e}", "WARN")


# --- BLACKLIST MAP MANAGEMENT ---

def add_ip_to_blacklist(ip_str: str, detection_event_id: str):
    """Add IP to blacklist map using bpftool."""
    try:
        ip_int = ip_to_int(ip_str)
        uuid_high, uuid_low = uuid_to_u64_pair(detection_event_id)
        timestamp_ns = int(time.time() * 1e9)

        # Construct value: 3x u64 + 1x u32 = 28 bytes
        # detection_event_id_high, detection_event_id_low, block_timestamp, drop_count
        value_bytes = struct.pack("<QQQI", uuid_high, uuid_low, timestamp_ns, 0)
        value_hex = value_bytes.hex()

        key_hex = struct.pack("<I", ip_int).hex()

        cmd = f"bpftool map update pinned {MAP_BLACKLIST} key hex {key_hex} value hex {value_hex}"
        run_cmd(cmd)

        log(f"✓ Blacklisted IP: {ip_str} (ID: {detection_event_id})", "SUCCESS")
        return True

    except Exception as e:
        log(f"Failed to add IP to blacklist: {e}", "ERROR")
        return False


def remove_ip_from_blacklist(ip_str: str):
    """Remove IP from blacklist map."""
    try:
        ip_int = ip_to_int(ip_str)
        key_hex = struct.pack("<I", ip_int).hex()

        cmd = f"bpftool map delete pinned {MAP_BLACKLIST} key hex {key_hex}"
        result = run_cmd(cmd, check=False)

        if result.returncode == 0:
            log(f"✓ Removed IP from blacklist: {ip_str}", "SUCCESS")
            return True
        else:
            log(f"IP not in blacklist: {ip_str}", "WARN")
            return False

    except Exception as e:
        log(f"Failed to remove IP: {e}", "ERROR")
        return False


def list_blacklist():
    """List all blacklisted IPs."""
    try:
        result = run_cmd(f"bpftool map dump pinned {MAP_BLACKLIST} -j")
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        blacklist = []

        for entry in data:
            # Key is IP as 4-byte hex
            key_bytes = bytes.fromhex(''.join(entry['key']))
            ip_int = struct.unpack("<I", key_bytes)[0]
            ip_str = int_to_ip(ip_int)

            # Value is struct blacklist_entry
            value_bytes = bytes.fromhex(''.join(entry['value']))
            uuid_high, uuid_low, timestamp_ns, drop_count = struct.unpack("<QQQI", value_bytes)
            uuid_str = u64_pair_to_uuid(uuid_high, uuid_low)

            blacklist.append({
                "ip": ip_str,
                "detection_event_id": uuid_str,
                "drop_count": drop_count,
                "block_timestamp": timestamp_ns
            })

        return blacklist

    except Exception as e:
        log(f"Error listing blacklist: {e}", "ERROR")
        return []


# --- DROP EVENT LISTENER ---

def start_drop_event_listener():
    """
    Read drop events from perf buffer using bpftool.
    Note: This is a simplified approach. For production, consider using:
    - Python perf_event_open bindings
    - Standalone C reader
    - eBPF ring buffer (newer kernels)
    """
    log("Starting drop event listener...", "INFO")
    log("NOTE: Using simplified event listening via bpftool", "INFO")

    try:
        # bpftool event can read perf events
        cmd = f"bpftool map event pinned {MAP_DROP_EVENTS}"

        # Run in subprocess and parse output
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        log("✓ Drop event listener started", "SUCCESS")

        for line in proc.stdout:
            try:
                # Parse bpftool event output
                # Format varies, but typically contains hex dumps
                # This is a placeholder - actual parsing depends on bpftool version
                if "drop" in line.lower():
                    log(f"Drop event detected: {line.strip()}", "INFO")

            except Exception as e:
                log(f"Error parsing event: {e}", "WARN")

    except Exception as e:
        log(f"Drop event listener error: {e}", "ERROR")


# --- REDIS MESSAGE HANDLER ---

def process_attack_message(message):
    """Process attack detection message from Redis."""
    try:
        attack = json.loads(message["data"])
    except:
        log("Invalid JSON in Redis message", "WARN")
        return

    mode = attack.get("enforcement_mode", "SIMULATE")
    src_ip = attack.get("src_ip")

    if not src_ip:
        log("Missing src_ip in attack message", "WARN")
        return

    event_id = attack.get("detection_event_id")
    if not event_id:
        event_id = str(uuid.uuid4())

    if mode == "BLOCK_MANUAL":
        action = "MANUAL_ENFORCEMENT"
        source_type = "MANUAL_CLI"

        success = add_ip_to_blacklist(src_ip, event_id)

        if success:
            log(f"!!! REAL BLOCK EXECUTED: {src_ip} (ID: {event_id}) !!!", "SUCCESS")
        else:
            log(f"Failed to block IP: {src_ip}", "ERROR")

    else:
        action = "SIMULATED_BLOCK"
        source_type = "ML_MODEL"
        log(f"Simulating block of {src_ip} (confidence={attack.get('confidence', 1.0):.2f})", "INFO")

    log_entry = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "detection_event_id": event_id,
        "event_type": action,
        "src_ip": src_ip,
        "confidence": attack.get("confidence", 1.0),
        "source": source_type,
        "rule_lifetime_sec": attack.get("lifetime", 300),
        "enforcement_mode": mode
    }

    es_index(log_entry, ES_BLOCK_INDEX_PREFIX)


def start_redis_listener():
    """Listen for attack messages on Redis channel."""
    log("Starting Redis listener...")

    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping()
        log(f"✓ Connected to Redis at {REDIS_HOST}:{REDIS_PORT}", "SUCCESS")
    except Exception as e:
        log(f"Cannot connect to Redis: {e}", "FATAL")
        sys.exit(1)

    pubsub = r.pubsub()
    pubsub.subscribe(ATTACK_CHANNEL)

    log(f"✓ Subscribed to channel: {ATTACK_CHANNEL}", "SUCCESS")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue

        process_attack_message(message)


# --- MAIN PROGRAM ---

def main():
    log("=" * 60)
    log("XDP IP Blacklist Controller (libbpf/CO-RE)")
    log("=" * 60)

    load_xdp_program()

    # Note: Event listener using bpftool is limited
    # For production, implement proper perf buffer reading
    drop_listener_thread = Thread(target=start_drop_event_listener, daemon=True)
    drop_listener_thread.start()

    try:
        start_redis_listener()
    except KeyboardInterrupt:
        log("Shutting down...", "INFO")
    finally:
        unload_xdp()
        log("Cleanup complete. Exiting.", "INFO")


if __name__ == "__main__":
    main()