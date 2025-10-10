from __future__ import annotations
import asyncio
import json
import time
import logging
from typing import Dict, Any
from .routing import local_users, user_locations, servers
from .errors import ErrorCodes
from .crypto import verify_transport, import_pubkey_b64url, validate_rsa_key_size, validate_rsa_public_exponent
from .db import (
    register_user, authenticate_user, create_login_session, verify_nonce_signature,
    get_user_info, list_online_users, 
    cleanup_expired_sessions
)
from .groups import create_public_channel, add_user_to_public_channel
from .bootstrap import handle_server_hello_join, handle_server_announce, handle_server_welcome
from .server_connections import ServerConnectionManager, handle_heartbeat
from .presence import PresenceManager, handle_user_advertise_message, handle_user_remove_message, handle_user_list_request
from .routing_delivery import MessageRouter, handle_msg_direct, handle_server_deliver, handle_msg_public_channel
from .public_channel import (
    PublicChannelManager,
    handle_public_channel_add,
    handle_public_channel_updated,
    handle_public_channel_key_share
)
from .file_transfer import FileTransferManager, handle_file_start, handle_file_chunk, handle_file_end
from .directory import get_pubkey_directory

logger = logging.getLogger(__name__)

async def handle_user_hello(ctx, env: Dict[str, Any]):
	"""
	Handle USER_HELLO message (§9.1 - Protocol-Compliant).
	Accepts unknown users for interoperability with other groups' chat systems.
	"""
	user_id = env["from"]
	payload = env["payload"]
	
	# Check if user already connected locally
	if user_id in local_users:
		await ctx.send_error(ErrorCodes.NAME_IN_USE, "User already connected")
		return
	
	# Validate payload - need both pubkey (signing) and enc_pubkey (encryption)
	if "pubkey" not in payload:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Missing public key")
		return
	
	# Extract both keys from USER_HELLO (Protocol §9.1)
	pubkey_b64 = payload["pubkey"]  # Signing key
	enc_pubkey_b64 = payload.get("enc_pubkey", pubkey_b64)  # Encryption key (fallback to pubkey for compatibility)
	
	# Validate signing public key
	try:
		pubkey = import_pubkey_b64url(pubkey_b64)
		if not validate_rsa_key_size(pubkey) or not validate_rsa_public_exponent(pubkey):
			await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid RSA signing key")
			return
	except Exception:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid signing key format")
		return
	
	# Validate encryption public key
	try:
		enc_pubkey = import_pubkey_b64url(enc_pubkey_b64)
		if not validate_rsa_key_size(enc_pubkey) or not validate_rsa_public_exponent(enc_pubkey):
			await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid RSA encryption key")
			return
	except Exception:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid encryption key format")
		return
	
	# Check if user exists in database
	user_info = get_user_info(ctx.server.db, user_id)
	
	# Dynamic User Registration (Protocol-Compliant): Accept unknown users
	if not user_info:
		# Extract metadata from payload if provided
		meta = payload.get("meta", {})
		
		# Register user dynamically with BOTH keys
		from .db import register_dynamic_user
		success = register_dynamic_user(ctx.server.db, user_id, pubkey_b64, enc_pubkey_b64, meta)
		
		if not success:
			await ctx.send_error(ErrorCodes.BAD_KEY, "Failed to register unknown user")
			return
		
		# Fetch newly registered user info
		user_info = get_user_info(ctx.server.db, user_id)
		if not user_info:
			await ctx.send_error(ErrorCodes.USER_NOT_FOUND, "User registration inconsistency")
			return
	else:
		# For known users, verify signing public key matches stored key
		if user_info.get("privkey_store") != "EXTERNAL_USER":
			if user_info["pubkey"] != pubkey_b64:
				await ctx.send_error(ErrorCodes.BAD_KEY, "Public key mismatch")
				return
	
	# Register user locally (Protocol §9.1)
	local_users[user_id] = ctx.link
	user_locations[user_id] = "local"
	
	# Create public channel if it doesn't exist
	create_public_channel(ctx.server.db)
	
	logger.info(f"[Handler] ========== PUBLIC CHANNEL ADD FLOW START ==========")
	logger.info(f"[Handler] User: {user_id}")
	logger.info(f"[Handler] Has public_channel_manager: {hasattr(ctx.server, 'public_channel_manager')}")
	if hasattr(ctx.server, 'public_channel_manager'):
		logger.info(f"[Handler] public_channel_manager value: {ctx.server.public_channel_manager}")
	
	# Add user to public channel with ENCRYPTION key (for wrapping channel key)
	if hasattr(ctx.server, 'public_channel_manager') and ctx.server.public_channel_manager:
		logger.info(f"[Handler] ✅ Calling public_channel_manager.add_user_to_channel...")
		logger.info(f"[Handler] Encryption pubkey length: {len(enc_pubkey_b64)}")
		try:
			result = await ctx.server.public_channel_manager.add_user_to_channel(user_id, enc_pubkey_b64)
			logger.info(f"[Handler] ✅ add_user_to_channel returned: {result}")
		except Exception as e:
			logger.error(f"[Handler] ❌❌❌ EXCEPTION calling add_user_to_channel:")
			logger.error(f"[Handler] Exception type: {type(e).__name__}")
			logger.error(f"[Handler] Exception message: {e}")
			import traceback
			logger.error(f"[Handler] Traceback:\n{traceback.format_exc()}")
	else:
		logger.warning(f"[Handler] ⚠️ public_channel_manager not available, using fallback")
		# Fallback: simple add without protocol messaging
		add_user_to_public_channel(ctx.server.db, user_id, "dummy_wrapped_key")
	
	logger.info(f"[Handler] ========== PUBLIC CHANNEL ADD FLOW END ==========")
	
	# Advertise user presence to network (Protocol §8.2)
	if hasattr(ctx.server, 'presence_manager') and ctx.server.presence_manager:
		user_meta = user_info.get("meta", {}) if user_info else {}
		await ctx.server.presence_manager.advertise_user(user_id, user_meta)
	
	# Send success response
	response_payload = {
		"status": "connected",
		"user_info": user_info,
		"server_id": ctx.server.server_id
	}
	
	response = {
		"type": "USER_WELCOME",
		"from": ctx.server.server_id,
		"to": user_id,
		"ts": ctx.server.now_ms(),
		"payload": response_payload
	}
	
	# Sign with server key
	if hasattr(ctx.server, 'priv_key') and ctx.server.priv_key:
		from .crypto import sign_transport, canonical_json
		response["sig"] = sign_transport(ctx.server.priv_key, canonical_json(response_payload))
	else:
		response["sig"] = ""
	
	await ctx.send(response)

async def handle_user_register(ctx, env: Dict[str, Any]):
	"""Handle user registration request"""
	user_id = env["from"]
	payload = env["payload"]
	
	# Validate required fields
	required_fields = ["pubkey", "privkey_store", "password"]
	for field in required_fields:
		if field not in payload:
			await ctx.send_error(ErrorCodes.BAD_KEY, f"Missing {field}")
			return
	
	# Extract both keys
	pubkey_b64 = payload["pubkey"]  # Signing key
	enc_pubkey_b64 = payload.get("enc_pubkey", pubkey_b64)  # Encryption key (fallback to pubkey for compatibility)
	
	# Validate signing public key
	try:
		pubkey = import_pubkey_b64url(pubkey_b64)
		if not validate_rsa_key_size(pubkey) or not validate_rsa_public_exponent(pubkey):
			await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid RSA signing key")
			return
	except Exception:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid signing key format")
		return
	
	# Validate encryption public key
	try:
		enc_pubkey = import_pubkey_b64url(enc_pubkey_b64)
		if not validate_rsa_key_size(enc_pubkey) or not validate_rsa_public_exponent(enc_pubkey):
			await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid RSA encryption key")
			return
	except Exception:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Invalid encryption key format")
		return
	
	# Extract metadata
	meta = payload.get("meta", {})
	password = payload["password"]
	privkey_store = payload["privkey_store"]
	
	# Register user with BOTH keys
	success = register_user(
		ctx.server.db, 
		user_id, 
		pubkey_b64,  # Signing key
		enc_pubkey_b64,  # Encryption key
		privkey_store, 
		password, 
		meta
	)
	
	if success:
		# Create login session
		session_id = create_login_session(ctx.server.db, user_id)
		
		response_payload = {
			"status": "success",
			"session_id": session_id,
			"message": "User registered successfully"
		}
		
		response = {
			"type": "USER_REGISTERED",
			"from": ctx.server.server_id,
			"to": user_id,
			"ts": ctx.server.now_ms(),
			"payload": response_payload
		}
		
		# Sign with server key (FIXED TODO #170)
		if hasattr(ctx.server, 'priv_key') and ctx.server.priv_key:
			from .crypto import sign_transport, canonical_json
			response["sig"] = sign_transport(ctx.server.priv_key, canonical_json(response_payload))
		else:
			response["sig"] = ""
		
		await ctx.send(response)
	else:
		await ctx.send_error(ErrorCodes.NAME_IN_USE, "User registration failed")

async def handle_user_login(ctx, env: Dict[str, Any]):
	"""Handle user login request"""
	user_id = env["from"]
	payload = env["payload"]
	
	# Validate required fields
	if "password" not in payload:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Missing password")
		return
	
	password = payload["password"]
	
	# Authenticate user
	if authenticate_user(ctx.server.db, user_id, password):
		# Create login session
		session_id = create_login_session(ctx.server.db, user_id)
		
		response_payload = {
			"status": "success",
			"session_id": session_id,
			"message": "Login successful"
		}
		
		response = {
			"type": "USER_LOGIN_SUCCESS",
			"from": ctx.server.server_id,
			"to": user_id,
			"ts": ctx.server.now_ms(),
			"payload": response_payload
		}
		
		# Sign with server key (FIXED TODO #203)
		if hasattr(ctx.server, 'priv_key') and ctx.server.priv_key:
			from .crypto import sign_transport, canonical_json
			response["sig"] = sign_transport(ctx.server.priv_key, canonical_json(response_payload))
		else:
			response["sig"] = ""
		
		await ctx.send(response)
	else:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Authentication failed")

async def handle_get_pubkey(ctx, env: Dict[str, Any]):
	"""
	Handle GET_PUBKEY request (Phase 6.0 - Frontend Integration)
	Protocol §13: Directory function to get user's public key with signature
	
	Request format:
	{
		"type": "GET_PUBKEY",
		"from": "requester_user_id",
		"to": "server_id",
		"ts": timestamp,
		"payload": {
			"user_id": "target_user_id"
		},
		"sig": ""
	}
	
	Response format:
	{
		"type": "PUBKEY_RESPONSE",
		"from": "server_id",
		"to": "requester_user_id",
		"ts": timestamp,
		"payload": {
			"user_id": "target_user_id",
			"pubkey": "base64url_encoded_key",
			"timestamp": unix_timestamp,
			"signature": "directory_signature"
		},
		"sig": "transport_signature"
	}
	"""
	requester_id = env["from"]
	payload = env.get("payload", {})
	
	# Validate payload
	if "user_id" not in payload:
		await ctx.send_error(ErrorCodes.BAD_KEY, "Missing user_id in payload")
		return
	
	target_user_id = payload["user_id"]
	logger.info(f"User {requester_id} requesting public key for {target_user_id}")
	
	# Import directory function
	from .directory import get_pubkey_directory
	
	# Get public key with directory signature
	if not hasattr(ctx.server, 'priv_key') or not ctx.server.priv_key:
		logger.error("Server has no private key for signing")
		await ctx.send_error(ErrorCodes.BAD_KEY, "Server key not available")
		return
	
	key_data = get_pubkey_directory(ctx.server.db, ctx.server.priv_key, target_user_id)
	
	if not key_data:
		logger.warning(f"Public key not found for user {target_user_id}")
		await ctx.send_error(ErrorCodes.USER_NOT_FOUND, f"User {target_user_id} not found in directory")
		return
	
	# Build response
	response = {
		"type": "PUBKEY_RESPONSE",
		"from": ctx.server.server_id,
		"to": requester_id,
		"ts": ctx.server.now_ms(),
		"payload": key_data  # Contains: user_id, pubkey, timestamp, signature
	}
	
	# Sign transport envelope
	from .crypto import sign_transport, canonical_json
	response["sig"] = sign_transport(ctx.server.priv_key, canonical_json(key_data))
	
	await ctx.send(response)
	logger.info(f"Sent public key for {target_user_id} to {requester_id}")

async def handle_get_user_data(ctx, env: Dict[str, Any]):
	"""
	Handle GET_USER_DATA request for login flow
	Returns user's encrypted private keys from database
	
	Request format:
	{
		"type": "GET_USER_DATA",
		"from": "user_id",
		"to": "server_id",
		"ts": timestamp,
		"payload": {},
		"sig": ""
	}
	
	Response format:
	{
		"type": "USER_DATA_RESPONSE",
		"from": "server_id",
		"to": "user_id",
		"ts": timestamp,
		"payload": {
			"user_id": "user_id",
			"pubkey": "base64url_spki",
			"privkey_store": "{...encrypted...}",
			"meta": {...}
		},
		"sig": "transport_signature"
	}
	"""
	user_id = env["from"]
	logger.info(f"User {user_id} requesting own user data for login")
	
	# Get user info from database
	user_info = get_user_info(ctx.server.db, user_id)
	
	if not user_info:
		logger.warning(f"User data not found for {user_id}")
		await ctx.send_error(ErrorCodes.USER_NOT_FOUND, f"User {user_id} not found")
		return
	
	# Build response with user data
	response_payload = {
		"user_id": user_info["user_id"],
		"pubkey": user_info["pubkey"],
		"privkey_store": user_info["privkey_store"],
		"meta": user_info.get("meta", {})
	}
	
	response = {
		"type": "USER_DATA_RESPONSE",
		"from": ctx.server.server_id,
		"to": user_id,
		"ts": ctx.server.now_ms(),
		"payload": response_payload
	}
	
	# Sign transport envelope
	from .crypto import sign_transport, canonical_json
	response["sig"] = sign_transport(ctx.server.priv_key, canonical_json(response_payload))
	
	logger.info(f"Sending user data to {user_id}")
	await ctx.send(response)

async def handle_ctrl_close(ctx, env: Dict[str, Any]):
	"""Handle optional CTRL_CLOSE message (Protocol §6)"""
	logger.debug(f"Received CTRL_CLOSE from {env['from']}")
	# No action needed - this is just a courtesy notification

# Enhanced handlers dictionary
# All Phase 3-5 handlers + Phase 6.0 (GET_PUBKEY)
HANDLERS = {
	"USER_HELLO": handle_user_hello,
	"USER_REGISTER": handle_user_register,
	"USER_LOGIN": handle_user_login,
	"GET_PUBKEY": handle_get_pubkey,  # Phase 6.0 - Frontend public key fetching
	"GET_USER_DATA": handle_get_user_data,  # NEW: For login flow
	"USER_LIST": handle_user_list_request,  # From presence.py - presence-aware
	"MSG_DIRECT": handle_msg_direct,  # From routing_delivery.py
	"MSG_PUBLIC_CHANNEL": handle_msg_public_channel,  # From routing_delivery.py
	"PUBLIC_CHANNEL_ADD": handle_public_channel_add,  # From public_channel.py - Protocol §9.3
	"PUBLIC_CHANNEL_UPDATED": handle_public_channel_updated,  # From public_channel.py - Protocol §9.3
	"PUBLIC_CHANNEL_KEY_SHARE": handle_public_channel_key_share,  # From public_channel.py - Protocol §9.3
	"FILE_START": handle_file_start,   # From file_transfer.py - Protocol §9.4
	"FILE_CHUNK": handle_file_chunk,   # From file_transfer.py - Protocol §9.4
	"FILE_END": handle_file_end,       # From file_transfer.py - Protocol §9.4
	# Server-to-server handlers
	"SERVER_HELLO_JOIN": handle_server_hello_join,  # From bootstrap.py
	"SERVER_WELCOME": handle_server_welcome,  # From bootstrap.py - Protocol §8.1
	"SERVER_ANNOUNCE": handle_server_announce,  # From bootstrap.py
	"HEARTBEAT": handle_heartbeat,  # From server_connections.py
	"USER_ADVERTISE": handle_user_advertise_message,  # From presence.py
	"USER_REMOVE": handle_user_remove_message,  # From presence.py
	"SERVER_DELIVER": handle_server_deliver,  # From routing_delivery.py
	"CTRL_CLOSE": handle_ctrl_close,  # Protocol §6 - optional closure message
}