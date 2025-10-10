from __future__ import annotations
import time
import re
from typing import Any, Dict, Optional

REQUIRED_ENVELOPE_FIELDS = ("type", "from", "to", "ts", "payload")

# UUID v4 regex pattern per Protocol §5.1
# Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx where y is 8, 9, a, or b
UUID_V4_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE
)

# Base64url character set (RFC 4648) - no padding
BASE64URL_PATTERN = re.compile(r'^[A-Za-z0-9_-]+$')

# Messages that MAY have optional/empty signatures
OPTIONAL_SIG_TYPES = {
    "USER_HELLO",           # First message from user, may not have keys yet
    "SERVER_HELLO_JOIN",    # First message from server
    "GET_USER_DATA"         # NEW: User fetching keys for login, no keys yet
}

def now_ms() -> int:
	return int(time.time() * 1000)


def validate_message_freshness(ts: int, message_type: str) -> bool:
	"""
	Validate message timestamp is within acceptable window.
	
	Different message types have different freshness requirements:
	- Real-time messages (MSG_DIRECT): 5 minutes
	- Presence updates (USER_ADVERTISE): 30 minutes  
	- File transfers (FILE_START): 1 hour (large files take time)
	
	This prevents stale messages from being processed while allowing
	for network delays and retransmissions.
	"""
	current_ts = now_ms()
	
	# Define time windows per message type
	windows = {
		"MSG_DIRECT": 5 * 60 * 1000,
		"MSG_PUBLIC_CHANNEL": 5 * 60 * 1000,
		"USER_ADVERTISE": 30 * 60 * 1000,
		"FILE_START": 60 * 60 * 1000,
		"SERVER_DELIVER": 10 * 60 * 1000,
	}
	
	max_age = windows.get(message_type, 5 * 60 * 1000)
	
	# Reject messages that are too old
	if ts < current_ts - max_age:
		return False
	
	return True


def is_valid_uuid_v4(uuid_string: str) -> bool:
	"""
	Validate UUID v4 format per Protocol §5.1
	
	Args:
		uuid_string: String to validate
	
	Returns:
		True if valid UUID v4, False otherwise
	"""
	if not isinstance(uuid_string, str):
		return False
	return UUID_V4_PATTERN.match(uuid_string) is not None


def is_valid_base64url(data: str) -> bool:
	"""
	Validate base64url format per Protocol §4
	
	Args:
		data: String to validate
	
	Returns:
		True if valid base64url (no padding), False otherwise
	"""
	if not isinstance(data, str):
		return False
	if not data:  # Empty string is not valid
		return False
	return BASE64URL_PATTERN.match(data) is not None


def message_requires_signature(msg_type: str) -> bool:
	"""
	Determine if a message type requires a signature per Protocol §7
	
	Per §7:
	- sig is REQUIRED on all Server payloads and all User content payloads
	- For HELLO/BOOTSTRAP you MAY omit sig if not yet possible to sign
	
	Args:
		msg_type: Message type string
	
	Returns:
		True if signature is required, False if optional
	"""
	# Messages where signature is OPTIONAL (per Protocol §7)
	optional_sig_messages = {
		"USER_HELLO",           # First connection, may not have sig
		"SERVER_HELLO_JOIN",    # First join, sig may not be ready
		"GET_USER_DATA",        # Login: user doesn't have keys yet to sign with
	}
	
	# For all other messages, signature is REQUIRED
	return msg_type not in optional_sig_messages


def validate_envelope(env: Dict[str, Any]) -> tuple[bool, str | None]:
	"""
	Validate message envelope per Protocol §6, §7
	
	Validates:
	1. Required fields present
	2. UUID v4 format for from/to (when applicable)
	3. Signature presence per Protocol §7
	4. Base64url format for sig field
	
	Args:
		env: Message envelope dictionary
	
	Returns:
		Tuple of (is_valid, error_message)
	"""
	# Check required fields
	for k in REQUIRED_ENVELOPE_FIELDS:
		if k not in env:
			return False, f"missing:{k}"
	
	# Validate message type
	msg_type = env.get("type")
	if not isinstance(msg_type, str) or not msg_type:
		return False, "invalid:type"
	
	# Validate 'from' field - should be UUID v4 for users/servers (Protocol §5.1)
	from_id = env.get("from")
	if isinstance(from_id, str) and from_id:
		# Special case: broadcast addresses or special strings may not be UUIDs
		if not from_id.startswith("*") and ":" not in from_id:
			# Should be a UUID v4
			if not is_valid_uuid_v4(from_id):
				return False, f"invalid:from_uuid:{from_id}"
	
	# Validate 'to' field - should be UUID v4 or special values (*, broadcast addresses)
	to_id = env.get("to")
	if isinstance(to_id, str) and to_id:
		# Special cases: "*" for broadcast, "host:port" for bootstrap
		if to_id != "*" and ":" not in to_id:
			# Should be a UUID v4
			if not is_valid_uuid_v4(to_id):
				return False, f"invalid:to_uuid:{to_id}"
	
	# Validate timestamp
	ts = env.get("ts")
	if not isinstance(ts, int) or ts < 0:
		return False, "invalid:ts"
	
	# Validate payload is a dict
	payload = env.get("payload")
	if not isinstance(payload, dict):
		return False, "invalid:payload"
	
	# Enforce signature presence rules (Protocol §7)
	msg_type = env.get("type", "")
	sig = env.get("sig", "")

	# Check if signature is required for this message type
	sig_required = message_requires_signature(msg_type)
	
	if sig_required:
		# Signature is REQUIRED - must be present and valid base64url
		if not sig:
			return False, f"missing:sig:required_for:{msg_type}"
		if not is_valid_base64url(sig):
			return False, f"invalid:sig:not_base64url"
	else:
		# Signature is OPTIONAL - only validate format if present (non-empty)
		if sig and not is_valid_base64url(sig):
			return False, f"invalid:sig:not_base64url"
	
	return True, None


def validate_binary_field(data: str, field_name: str, min_length: int = 1) -> tuple[bool, Optional[str]]:
	"""
	Validate a binary field (key, signature, ciphertext) is proper base64url
	
	Args:
		data: Base64url string to validate
		field_name: Name of field for error messages
		min_length: Minimum expected length in characters
	
	Returns:
		Tuple of (is_valid, error_message)
	"""
	if not isinstance(data, str):
		return False, f"invalid:{field_name}:not_string"
	
	if len(data) < min_length:
		return False, f"invalid:{field_name}:too_short"
	
	if not is_valid_base64url(data):
		return False, f"invalid:{field_name}:not_base64url"
	
	return True, None


def validate_user_hello_payload(payload: Dict[str, Any]) -> tuple[bool, Optional[str]]:
	"""
	Validate USER_HELLO payload per Protocol §9.1
	
	Required fields:
	- client: string
	- pubkey: base64url RSA-4096 public key
	- enc_pubkey: base64url RSA-4096 public key (or duplicate of pubkey)
	
	Args:
		payload: Message payload
	
	Returns:
		Tuple of (is_valid, error_message)
	"""
	if "pubkey" not in payload:
		return False, "missing:pubkey"
	
	if "enc_pubkey" not in payload:
		return False, "missing:enc_pubkey"
	
	# Validate pubkey format (should be base64url, ~700+ chars for RSA-4096)
	valid, error = validate_binary_field(payload["pubkey"], "pubkey", min_length=500)
	if not valid:
		return False, error
	
	# Validate enc_pubkey format
	valid, error = validate_binary_field(payload["enc_pubkey"], "enc_pubkey", min_length=500)
	if not valid:
		return False, error
	
	return True, None


def validate_msg_direct_payload(payload: Dict[str, Any]) -> tuple[bool, Optional[str]]:
	"""
	Validate MSG_DIRECT payload per Protocol §9.2
	
	Required fields:
	- ciphertext: base64url RSA-OAEP ciphertext
	- sender_pub: base64url RSA-4096 public key
	- content_sig: base64url RSASSA-PSS signature
	
	Args:
		payload: Message payload
	
	Returns:
		Tuple of (is_valid, error_message)
	"""
	required_fields = ["ciphertext", "sender_pub", "content_sig"]
	
	for field in required_fields:
		if field not in payload:
			return False, f"missing:{field}"
		
		# Validate base64url format
		valid, error = validate_binary_field(payload[field], field)
		if not valid:
			return False, error
	
	return True, None


# Export validation functions
__all__ = [
	'now_ms',
	'validate_envelope',
	'validate_message_freshness',
	'is_valid_uuid_v4',
	'is_valid_base64url',
	'message_requires_signature',
	'validate_binary_field',
	'validate_user_hello_payload',
	'validate_msg_direct_payload',
]