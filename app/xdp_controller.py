#!/usr/bin/env python3
"""
xdp_controller.py
-----------------
Real XDP Controller with BPF map management and per-drop event logging.

Features:
1. Compiles and loads XDP program onto network interface
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
from bcc import BPF

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

# XDP configuration - container paths
XDP_PROGRAM_PATH = os.getenv("XDP_PROGRAM_PATH", "/app/xdp_ip_blacklist_bcc.c")
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "ens33")

# Global BPF object (will be initialized after compilation)
bpf = None


# --- HELPER FUNCTIONS ---

def log(msg, level="INFO"):
    """Unified logging function."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[xdp-ctrl][{level}] {timestamp} - {msg}", file=sys.stderr)
    sys.stderr.flush()  # Force immediate output


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
        # Try to parse as standard UUID format
        uuid_obj = uuid.UUID(uuid_str)
        uuid_bytes = uuid_obj.bytes
        high = struct.unpack(">Q", uuid_bytes[:8])[0]
        low = struct.unpack(">Q", uuid_bytes[8:])[0]
        return high, low
    except ValueError:
        # If not a valid UUID format, treat as arbitrary string
        log(f"Non-standard UUID format '{uuid_str}', storing as-is", "WARN")
        
        # Encode string to bytes (UTF-8)
        str_bytes = uuid_str.encode('utf-8')
        
        # Pad with zeros or truncate to exactly 16 bytes
        if len(str_bytes) < 16:
            str_bytes = str_bytes + b'\x00' * (16 - len(str_bytes))
        else:
            str_bytes = str_bytes[:16]
        
        # Convert to two u64
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

def compile_and_load_xdp():
    """Compile and load the XDP program using BCC."""
    global bpf
    
    log(f"Compiling XDP program: {XDP_PROGRAM_PATH}")
    log(f"Target interface: {NETWORK_INTERFACE}")
    
    if not os.path.exists(XDP_PROGRAM_PATH):
        log(f"XDP program not found: {XDP_PROGRAM_PATH}", "FATAL")
        sys.exit(1)
    
    try:
        # Load BPF program using BCC
        bpf = BPF(src_file=XDP_PROGRAM_PATH)
        fn = bpf.load_func("xdp_ip_blacklist_filter", BPF.XDP)
        bpf.attach_xdp(NETWORK_INTERFACE, fn, 0)
        
        log(f"✓ XDP program loaded on interface: {NETWORK_INTERFACE}", "SUCCESS")
        return True
        
    except Exception as e:
        log(f"Failed to load XDP program: {e}", "FATAL")
        sys.exit(1)


def unload_xdp():
    """Unload XDP program from interface."""
    global bpf
    try:
        if bpf:
            bpf.remove_xdp(NETWORK_INTERFACE, 0)
            log(f"✓ XDP program unloaded from {NETWORK_INTERFACE}", "SUCCESS")
    except Exception as e:
        log(f"Error unloading XDP: {e}", "WARN")


# --- BLACKLIST MAP MANAGEMENT ---

def add_ip_to_blacklist(ip_str: str, detection_event_id: str):
    """
    Add or update an IP in the blacklist map with associated detection_event_id.
    """
    global bpf
    
    if not bpf:
        log("BPF not initialized", "ERROR")
        return False
    
    try:
        ip_blacklist = bpf["ip_blacklist"]
        ip_int = ip_to_int(ip_str)
        uuid_high, uuid_low = uuid_to_u64_pair(detection_event_id)
        
        entry = ip_blacklist.Leaf()
        entry.detection_event_id_high = uuid_high
        entry.detection_event_id_low = uuid_low
        entry.block_timestamp = int(time.time() * 1e9)
        entry.drop_count = 0
        
        ip_blacklist[ip_blacklist.Key(ip_int)] = entry
        
        log(f"✓ Blacklisted IP: {ip_str} (ID: {detection_event_id})", "SUCCESS")
        return True
        
    except Exception as e:
        log(f"Failed to add IP to blacklist: {e}", "ERROR")
        return False


def remove_ip_from_blacklist(ip_str: str):
    """Remove an IP from the blacklist."""
    global bpf
    
    if not bpf:
        log("BPF not initialized", "ERROR")
        return False
    
    try:
        ip_blacklist = bpf["ip_blacklist"]
        ip_int = ip_to_int(ip_str)
        
        del ip_blacklist[ip_blacklist.Key(ip_int)]
        log(f"✓ Removed IP from blacklist: {ip_str}", "SUCCESS")
        return True
        
    except KeyError:
        log(f"IP not in blacklist: {ip_str}", "WARN")
        return False
    except Exception as e:
        log(f"Failed to remove IP: {e}", "ERROR")
        return False


def list_blacklist():
    """List all blacklisted IPs."""
    global bpf
    
    if not bpf:
        return []
    
    try:
        ip_blacklist = bpf["ip_blacklist"]
        blacklist = []
        
        for k, v in ip_blacklist.items():
            ip_str = int_to_ip(k.value)
            uuid_str = u64_pair_to_uuid(v.detection_event_id_high, v.detection_event_id_low)
            blacklist.append({
                "ip": ip_str,
                "detection_event_id": uuid_str,
                "drop_count": v.drop_count,
                "block_timestamp": v.block_timestamp
            })
        
        return blacklist
        
    except Exception as e:
        log(f"Error listing blacklist: {e}", "ERROR")
        return []


# --- DROP EVENT LISTENER ---

def handle_drop_event(cpu, data, size):
    """
    Callback function for BPF perf events.
    Called every time XDP drops a packet.
    """
    global bpf
    
    sys.stderr.write(f"[DEBUG] Drop event callback triggered (cpu={cpu}, size={size})\n")
    sys.stderr.flush()
    
    try:
        event = bpf["drop_events"].event(data)
        src_ip = int_to_ip(event.src_ip)
        kernel_timestamp_ns = event.timestamp
        
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            
            boot_time = time.time() - uptime_seconds
            event_time_seconds = boot_time + (kernel_timestamp_ns / 1e9)
            timestamp_iso = datetime.utcfromtimestamp(event_time_seconds).isoformat() + "Z"
        except Exception:
            timestamp_iso = datetime.utcnow().isoformat() + "Z"
        
        drop_reason_map = {
            1: "IP_BLACKLIST",
            2: "CONTENT_FILTER"
        }
        drop_reason = drop_reason_map.get(event.drop_reason, "UNKNOWN")
        
        detection_event_id = None
        if event.detection_event_id_high != 0 or event.detection_event_id_low != 0:
            detection_event_id = u64_pair_to_uuid(
                event.detection_event_id_high,
                event.detection_event_id_low
            )
        
        drop_id = str(uuid.uuid4())
        
        drop_doc = {
            "@timestamp": timestamp_iso,
            "event_type": "PACKET_DROPPED",
            "src_ip": src_ip,
            "drop_reason": drop_reason,
            "detection_event_id": detection_event_id,
            "drop_id": drop_id
        }
        
        es_index(drop_doc, ES_DROP_INDEX_PREFIX)
        
        log(f"Packet dropped: {src_ip} (Reason: {drop_reason}, drop_id: {drop_id})", "INFO")
        
    except Exception as e:
        log(f"Error handling drop event: {e}", "ERROR")
        import traceback
        log(f"Traceback: {traceback.format_exc()}", "ERROR")


def start_drop_event_listener():
    """Start listening for drop events from XDP."""
    global bpf
    
    log("Starting drop event listener...")
    
    try:
        bpf["drop_events"].open_perf_buffer(handle_drop_event)
        
        log("✓ Drop event listener started", "SUCCESS")
        log("Waiting for drop events from kernel...", "INFO")
        
        while True:
            try:
                bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
                
    except Exception as e:
        log(f"Drop event listener error: {e}", "ERROR")


# --- REDIS MESSAGE HANDLER ---

def process_attack_message(message):
    """
    Process attack detection message from Redis.
    """
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
    log("XDP Real-Time IP Blacklist Controller")
    log("=" * 60)
    
    compile_and_load_xdp()
    
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

