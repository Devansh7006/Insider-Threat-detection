"""
Configuration loader for Insider Threat Agent.
Loads from config.yaml if present.
Provides safe defaults.
"""

import os
import yaml


DEFAULT_CONFIG = {
    "agent_id": "agent-001",
    "backend_url": "https://insider-threat-detection-szmm.onrender.com",
    "heartbeat_interval": 10
}


def load_config():
    """
    Loads configuration from config.yaml if available.
    Falls back to DEFAULT_CONFIG safely.
    Never returns None.
    """

    cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")

    # If config.yaml exists, try loading it
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            # Merge with defaults (so missing keys don't break system)
            merged = {**DEFAULT_CONFIG, **data}

            print("[CONFIG] Loaded from config.yaml")
            return merged

        except Exception as e:
            print("[CONFIG] Failed to read config.yaml:", e)

    # If file doesn't exist or failed to load
    print("[CONFIG] Using default configuration")
    return DEFAULT_CONFIG.copy()