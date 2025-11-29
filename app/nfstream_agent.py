#!/usr/bin/env python3
"""
nfstream_agent.py
-----------------
Captures real-time network flows using NFStream, maps the 77 features to 
NFStream's internal attributes, and outputs JSON lines for the ML service.
"""

# =============================================================================
# CRITICAL: Monkey-patch nfstream.utils BEFORE importing NFStreamer
# The issue is that psutil.Process() constructor fails in Docker containers
# when /proc is mounted from the host, causing race conditions with PID lookups.
# We must patch the available_cpus_count function before NFStreamer uses it.
# =============================================================================
import os
import sys

def _safe_available_cpus_count():
    """
    Safe replacement for nfstream.utils.available_cpus_count.
    Returns CPU count without using psutil.Process().cpu_affinity().
    """
    return os.cpu_count() or 1

# Patch nfstream.utils before NFStreamer is imported
import nfstream.utils
nfstream.utils.available_cpus_count = _safe_available_cpus_count

# NOW it's safe to import NFStreamer
from nfstream import NFStreamer

# Continue with other imports
import json
import numpy as np
from datetime import datetime

# --- HELPER FUNCTION ---
def safe_float(value):
    """Converts a value to float, defaulting to 0.0 on error."""
    try:
        if isinstance(value, (int, float)):
            return float(value)
        return float(value)
    except Exception:
        return 0.0

# ====================================================================
# FEATURE MAPPING (77 features)
# Maps the Training/CSV feature name (key) to the live NFStream attribute (value).
# ====================================================================
FEATURE_MAP = {
    'Destination_Port': 'dst_port',
    'Flow_Duration': 'bidirectional_duration_ms',
    'Total_Fwd_Packets': 'src2dst_packets',
    'Total_Backward_Packets': 'dst2src_packets',
    'Total_Length_of_Fwd_Packets': 'src2dst_bytes',
    'Total_Length_of_Bwd_Packets': 'dst2src_bytes',
    'Fwd_Packet_Length_Max': 'src2dst_max_ps',
    'Fwd_Packet_Length_Min': 'src2dst_min_ps',
    'Fwd_Packet_Length_Mean': 'src2dst_mean_ps',
    'Fwd_Packet_Length_Std': 'src2dst_stddev_ps',
    'Bwd_Packet_Length_Max': 'dst2src_max_ps',
    'Bwd_Packet_Length_Min': 'dst2src_min_ps',
    'Bwd_Packet_Length_Mean': 'dst2src_mean_ps',
    'Bwd_Packet_Length_Std': 'dst2src_stddev_ps',
    'Flow_IAT_Mean': 'bidirectional_mean_iat',
    'Flow_IAT_Std': 'bidirectional_stddev_iat',
    'Flow_IAT_Max': 'bidirectional_max_iat',
    'Flow_IAT_Min': 'bidirectional_min_iat',
    'Fwd_IAT_Total': 'src2dst_duration_ms', 
    'Fwd_IAT_Mean': 'src2dst_mean_iat',
    'Fwd_IAT_Std': 'src2dst_stddev_iat',
    'Fwd_IAT_Max': 'src2dst_max_iat',
    'Fwd_IAT_Min': 'src2dst_min_iat',
    'Bwd_IAT_Total': 'dst2src_duration_ms',
    'Bwd_IAT_Mean': 'dst2src_mean_iat',
    'Bwd_IAT_Std': 'dst2src_stddev_iat',
    'Bwd_IAT_Max': 'dst2src_max_iat',
    'Bwd_IAT_Min': 'dst2src_min_iat',
    'Fwd_PSH_Flags': 'src2dst_psh_packets',
    'Bwd_PSH_Flags': 'dst2src_psh_packets',
    'Fwd_URG_Flags': 'src2dst_urg_packets',
    'Bwd_URG_Flags': 'dst2src_urg_packets',
    'Fwd_Header_Length': 'src2dst_header_size',
    'Bwd_Header_Length': 'dst2src_header_size',
    'Fwd_Packets/s': 'src2dst_packets_rate',
    'Bwd_Packets/s': 'dst2src_packets_rate',
    'Min_Packet_Length': 'bidirectional_min_ps', 
    'Max_Packet_Length': 'bidirectional_max_ps',
    'Packet_Length_Mean': 'bidirectional_mean_ps',
    'Packet_Length_Std': 'bidirectional_stddev_ps',
    'Packet_Length_Variance': 'bidirectional_stddev_ps',
    'FIN_Flag_Count': 'bidirectional_fin_packets',
    'SYN_Flag_Count': 'bidirectional_syn_packets',
    'RST_Flag_Count': 'bidirectional_rst_packets',
    'PSH_Flag_Count': 'bidirectional_psh_packets',
    'ACK_Flag_Count': 'bidirectional_ack_packets',
    'URG_Flag_Count': 'bidirectional_urg_packets',
    'CWE_Flag_Count': 'cwe_flag_count',
    'ECE_Flag_Count': 'ece_flag_count',
    'Down/Up_Ratio': 'down_up_ratio',
    'Average_Packet_Size': 'bidirectional_mean_ps',
    'Avg_Fwd_Segment_Size': 'src2dst_mean_ps',
    'Avg_Bwd_Segment_Size': 'dst2src_mean_ps',
    'Fwd_Header_Length_1': 'src2dst_header_size', 
    'Fwd_Avg_Bytes/Bulk': 'src2dst_avg_bytes_bulk',
    'Fwd_Avg_Packets/Bulk': 'src2dst_avg_packets_bulk',
    'Fwd_Avg_Bulk_Rate': 'src2dst_avg_bulk_rate',
    'Bwd_Avg_Bytes/Bulk': 'dst2src_avg_bytes_bulk',
    'Bwd_Avg_Packets/Bulk': 'dst2src_avg_packets_bulk',
    'Bwd_Avg_Bulk_Rate': 'dst2src_avg_bulk_rate',
    'Subflow_Fwd_Packets': 'src2dst_packets',
    'Subflow_Fwd_Bytes': 'src2dst_bytes',
    'Subflow_Bwd_Packets': 'dst2src_packets',
    'Subflow_Bwd_Bytes': 'dst2src_bytes',
    'Init_Win_bytes_forward': 'src2dst_initial_window_bytes',
    'Init_Win_bytes_backward': 'dst2src_initial_window_bytes',
    'act_data_pkt_fwd': 'src2dst_act_data_pkts',
    'min_seg_size_forward': 'src2dst_min_ps',
    'Active_Mean': 'bidirectional_active_mean',
    'Active_Std': 'bidirectional_active_stddev',
    'Active_Max': 'bidirectional_active_max',
    'Active_Min': 'bidirectional_active_min',
    'Idle_Mean': 'bidirectional_idle_mean',
    'Idle_Std': 'bidirectional_idle_stddev',
    'Idle_Max': 'bidirectional_idle_max',
    'Idle_Min': 'bidirectional_idle_min',
}
FEATURE_KEYS = list(FEATURE_MAP.keys())


def flow_to_record(flow):
    """Convert NFStream flow object into a JSON serializable dict."""

    # 1. Start with metadata
    record = {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "is_ssl_tls": getattr(flow, "is_ssl_tls", False), 
        "application_name": getattr(flow, "application_name", "Unknown"),
    }
    
    # 2. Extract and filter features for the ML model
    features_dict = {}
    
    for k_train, k_attr in FEATURE_MAP.items():
        value = getattr(flow, k_attr, 0.0)
        
        # Handle Packet_Length_Variance specially
        if k_train == 'Packet_Length_Variance':
            stddev = getattr(flow, FEATURE_MAP['Packet_Length_Std'], 0.0)
            value = safe_float(stddev ** 2)
        else:
            value = safe_float(value)
            
        features_dict[k_train] = value

    record["features"] = features_dict
    
    return record


def main():
    iface = os.getenv("CAPTURE_INTERFACE")
    if not iface:
        print("[nfstream][FATAL] Set CAPTURE_INTERFACE environment variable", file=sys.stderr)
        sys.exit(1)

    print(f"[nfstream] Starting capture on interface: {iface}", file=sys.stderr)
    print(f"[nfstream] Exporting {len(FEATURE_KEYS)} features.", file=sys.stderr)

    streamer = NFStreamer(
        source=iface,
        statistical_analysis=True,
        idle_timeout=10,
        accounting_mode=0,
        n_meters=1, 
    )

    for flow in streamer:
        try:
            rec = flow_to_record(flow)
            print(json.dumps(rec), flush=True)
        except Exception as e:
            print(f"[nfstream][ERR] {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
