from __future__ import annotations
import os
from dataclasses import dataclass

SERVER_HOST = os.getenv("CHAT_SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("CHAT_SERVER_PORT", "8765"))

# Spec §8.1: static bootstrap list (min 3), with pinned pubkeys (base64url)
BOOTSTRAP_SERVERS = [
	{"host": "192.0.1.2", "port": 12345, "pubkey": "<BASE64URL_RSA4096_PUB>"},
	{"host": "198.50.100.3", "port": 5432, "pubkey": "<BASE64URL_RSA4096_PUB>"},
	{"host": "203.0.113.21", "port": 1212, "pubkey": "<BASE64URL_RSA4096_PUB>"},
]

HEARTBEAT_INTERVAL_SEC = 15  # §11
HEARTBEAT_TIMEOUT_SEC = 45   # §11

# Server identity (UUID v4) per §5
SERVER_ID_FILE = os.getenv("CHAT_SERVER_ID_FILE", "server_id.txt")

DB_PATH = os.getenv("CHAT_DB_PATH", "chat.db")