from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict

@dataclass
class Envelope:
	type: str
	from_id: str
	to: str
	ts: int
	payload: Dict[str, Any]
	sig: str | None = None  # REQUIRED for server payloads; MAY omit on some hellos (§7)