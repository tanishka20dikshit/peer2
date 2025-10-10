from __future__ import annotations
from typing import Dict, Tuple, Any
from dataclasses import dataclass

@dataclass
class Link:
	ws: Any  # websockets.WebSocketServerProtocol
	role: str  # "server" or "user"
	id: str

# Per §5.2
servers: Dict[str, Link] = {}
server_addrs: Dict[str, Tuple[str, int]] = {}
local_users: Dict[str, Link] = {}
user_locations: Dict[str, str] = {}  # "local" or server_id
seen_ids: set[tuple] = set()  # for loop suppression (§10)