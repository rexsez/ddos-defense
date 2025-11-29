#!/usr/bin/env python3
"""
ml_infer_service.py
-------------------
Reads JSON flow records from stdin, applies trained AdaBoost model,
indexes enriched results into Elasticsearch, and sends attack predictions
to Redis for XDP blocking (or simulation).
"""

import sys
import os
import json
from datetime import datetime
import pickle 
import uuid
import numpy as np
import joblib 
import requests
import urllib3
import redis

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------
# Configuration - Container-friendly paths
# ---------------------------------------------------------------------
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "/app/models")
ES_HOST = os.getenv("ES_HOST", "http://127.0.0.1:9200")
ES_INDEX_PREFIX = os.getenv("ES_INDEX_PREFIX", "netflows")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "jgYsL5-kztDUSd8HyiNd") 

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_CHANNEL = os.getenv("ATTACK_CHANNEL", "attack_detected")

CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.65"))
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "SIMULATE")


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def fatal(msg: str) -> None:
    print(f"[ml_infer][FATAL] {msg}", file=sys.stderr)
    sys.exit(1)


def load_artifacts():
    """
    Load preprocessing objects and trained AdaBoost model using pickle.
    """
    prep_path = os.path.join(ARTIFACTS_DIR, "preprocessing_objects.pkl")
    model_path = os.path.join(ARTIFACTS_DIR, "trained_models.pkl")

    if not os.path.isfile(prep_path):
        fatal(f"Missing preprocessing_objects.pkl in {ARTIFACTS_DIR}")

    if not os.path.isfile(model_path):
        fatal(f"Missing trained_models.pkl in {ARTIFACTS_DIR}")

    try:
        with open(prep_path, "rb") as f:
            preprocessing = pickle.load(f)
        with open(model_path, "rb") as f:
            models = pickle.load(f)

    except Exception as e:
        fatal(f"Cannot load artifacts: {e}")

    scaler = preprocessing.get("scaler")
    selected_features = preprocessing.get("selected_features")
    if not selected_features:
        fatal("Missing or empty 'selected_features' in preprocessing_objects.pkl")

    adaboost_model = models.get("adaboost")
    if adaboost_model is None:
        fatal("Missing 'adaboost' model in trained_models.pkl")

    print(f"[ml_infer] Loaded AdaBoost model", file=sys.stderr)
    print(f"[ml_infer] Features: {len(selected_features)}", file=sys.stderr)
    print(f"[ml_infer] Confidence threshold: {CONFIDENCE_THRESHOLD}", file=sys.stderr)
    print(f"[ml_infer] Enforcement mode: {ENFORCEMENT_MODE}", file=sys.stderr)

    return scaler, selected_features, adaboost_model


def features_to_array(feats: dict, feature_order: list) -> np.ndarray:
    """Convert features dict to numpy array in correct order."""
    return np.array([[float(feats.get(k, 0.0)) for k in feature_order]], dtype=float)


def connect_redis():
    """Connect to Redis, return client or None."""
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping()
        print(f"[ml_infer] Connected to Redis at {REDIS_HOST}:{REDIS_PORT}", file=sys.stderr)
        return r
    except Exception as e:
        print(f"[ml_infer][WARN] Redis not available: {e}", file=sys.stderr)
        return None


def es_index(doc: dict):
    """Index document into Elasticsearch."""
    index_name = f"{ES_INDEX_PREFIX}-{datetime.utcnow():%Y.%m.%d}"
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
            print(f"[ml_infer][WARN] ES index fail: {resp.status_code} - {resp.text[:50]}...", file=sys.stderr)
    except Exception as e:
        print(f"[ml_infer][WARN] ES error: {e}", file=sys.stderr)


# ---------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------
def main():
    scaler, feature_order, adaboost = load_artifacts() 
    redis_client = connect_redis()

    print("[ml_infer] Ready. Waiting for JSON flows on stdin...", file=sys.stderr)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                flow = json.loads(line)
            except json.JSONDecodeError:
                continue

            feats = flow.get("features")
            if not feats:
                continue

            try:
                X = features_to_array(feats, feature_order)
                X_scaled = scaler.transform(X) if scaler else X

                pred = int(adaboost.predict(X_scaled)[0])
                prob = adaboost.predict_proba(X_scaled)[0]

                confidence = float(prob[pred])
                attack_probability = float(prob[1]) if len(prob) > 1 else 0.0
                label = "ATTACK" if pred == 1 else "BENIGN"
                
                unique_id = str(uuid.uuid4())

                enriched = {
                    **flow,
                    "detection_event_id": unique_id,
                    "prediction": label,
                    "confidence": confidence,
                    "attack_probability": attack_probability,
                    "ml_model": "AdaBoost",
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                }

                # Notify XDP controller via Redis
                if label == "ATTACK" and confidence >= CONFIDENCE_THRESHOLD:
                    attack_msg = {
                        "detection_event_id": unique_id,
                        "src_ip": flow.get("src_ip"),
                        "dst_ip": flow.get("dst_ip"),
                        "src_port": flow.get("src_port"),
                        "dst_port": flow.get("dst_port"),
                        "protocol": flow.get("protocol"),
                        "confidence": confidence,
                        "attack_probability": attack_probability,
                        "timestamp": enriched["@timestamp"],
                        "model": "AdaBoost",
                        "enforcement_mode": ENFORCEMENT_MODE
                    }
                    if redis_client:
                        redis_client.publish(REDIS_CHANNEL, json.dumps(attack_msg))
                        print(f"[ml_infer] Published attack: {flow.get('src_ip')} (conf={confidence:.2f})", file=sys.stderr)

                # Index into ES
                es_index(enriched)

                # Output enriched JSON for debugging
                print(json.dumps(enriched, ensure_ascii=False))
                sys.stdout.flush()

            except Exception as e:
                print(f"[ml_infer][ERR] Error during inference: {e}", file=sys.stderr)

    except KeyboardInterrupt:
        print("[ml_infer] Stopped by user.", file=sys.stderr)


if __name__ == "__main__":
    main()

