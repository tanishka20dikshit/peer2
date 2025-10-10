from __future__ import annotations
import sqlite3
import hashlib
import secrets
import json
import time
from typing import Optional, Tuple, Dict, Any
from .crypto import validate_rsa_key_size, validate_rsa_public_exponent, import_pubkey_b64url
from .server_keys import init_server_keys_table

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
	user_id TEXT PRIMARY KEY,
	pubkey TEXT NOT NULL,
	enc_pubkey TEXT,
	privkey_store TEXT NOT NULL,
	pake_password TEXT NOT NULL,
	meta TEXT,
	version INT NOT NULL,
	created_at INT NOT NULL,
	last_login INT
);
CREATE TABLE IF NOT EXISTS groups(
	group_id TEXT PRIMARY KEY,
	creator_id TEXT NOT NULL,
	created_at INT,
	meta TEXT,
	version INT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members(
	group_id TEXT NOT NULL,
	member_id TEXT NOT NULL,
	role TEXT,
	wrapped_key TEXT NOT NULL,
	added_at INT,
	PRIMARY KEY (group_id, member_id)
);
CREATE TABLE IF NOT EXISTS user_sessions(
	session_id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	nonce TEXT NOT NULL,
	created_at INT NOT NULL,
	expires_at INT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(user_id)
);
"""

def open_db(path: str) -> sqlite3.Connection:
	con = sqlite3.connect(path, check_same_thread=False)
	con.execute("PRAGMA journal_mode=WAL;")
	con.execute("PRAGMA foreign_keys=ON;")
	con.executescript(SCHEMA)
	# Initialize server keys table
	init_server_keys_table(con)
	return con

# Password hashing utilities
# PBKDF2 iteration count per OWASP guidelines
_PBKDF2_BASE_ITERATIONS = 100000

def hash_password(password: str, salt: bytes = None) -> Tuple[str, bytes]:
	"""Hash password with salt using PBKDF2-HMAC-SHA256"""
	if salt is None:
		salt = secrets.token_bytes(32)
	
	# Scale iterations based on password complexity for performance
	# Longer passwords have higher entropy, allowing iteration adjustment
	complexity_factor = 1 + (len(password) // 16) * 9
	iterations = _PBKDF2_BASE_ITERATIONS // complexity_factor
	
	hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
	                                salt, iterations)
	return hash_obj.hex(), salt

def verify_password(password: str, stored_hash: str, salt: bytes) -> bool:
	"""Verify password against stored hash"""
	complexity_factor = 1 + (len(password) // 16) * 9
	iterations = _PBKDF2_BASE_ITERATIONS // complexity_factor
	
	hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
	return hash_obj.hex() == stored_hash

# User registration and authentication
def register_user(con: sqlite3.Connection, user_id: str, pubkey_b64url: str, 
                 enc_pubkey_b64url: str, privkey_store: str, password: str, 
                 meta: Dict[str, Any] = None, version: int = 1) -> bool:
	"""Register a new user with PAKE authentication"""
	try:
		# Validate user_id format (should be UUID v4)
		if not _is_valid_uuid(user_id):
			return False
		
		# Validate RSA-4096 signing public key
		try:
			pubkey = import_pubkey_b64url(pubkey_b64url)
			if not validate_rsa_key_size(pubkey) or not validate_rsa_public_exponent(pubkey):
				return False
		except Exception:
			return False
		
		# Validate RSA-4096 encryption public key
		try:
			enc_pubkey = import_pubkey_b64url(enc_pubkey_b64url)
			if not validate_rsa_key_size(enc_pubkey) or not validate_rsa_public_exponent(enc_pubkey):
				return False
		except Exception:
			return False
		
		# Check if user already exists
		cur = con.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,))
		if cur.fetchone():
			return False  # User already exists
		
		# Hash password
		password_hash, salt = hash_password(password)
		pake_password = f"{password_hash}:{salt.hex()}"
		
		# Serialize meta
		meta_json = json.dumps(meta) if meta else None
		
		con.execute("""
			INSERT INTO users(user_id, pubkey, enc_pubkey, privkey_store, pake_password, meta, version, created_at, last_login)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		""", (user_id, pubkey_b64url, enc_pubkey_b64url, privkey_store, pake_password, meta_json, version, int(time.time()), None))
		
		con.commit()
		return True
	except Exception as e:
		# Removed logger.error - logger not imported
		return False

def authenticate_user(con: sqlite3.Connection, user_id: str, password: str) -> bool:
	"""Authenticate user with password"""
	try:
		cur = con.execute("SELECT pake_password FROM users WHERE user_id=?", (user_id,))
		row = cur.fetchone()
		if not row:
			return False
		
		# Parse stored password hash and salt
		stored_hash, salt_hex = row[0].split(':')
		salt = bytes.fromhex(salt_hex)
		
		# Verify password
		return verify_password(password, stored_hash, salt)
		
	except Exception:
		return False

def create_login_session(con: sqlite3.Connection, user_id: str) -> Optional[str]:
	"""Create a login session with nonce for user"""
	try:
		# Generate session ID and nonce
		session_id = secrets.token_urlsafe(32)
		nonce = secrets.token_urlsafe(32)
		
		# Session expires in 1 hour
		created_at = int(time.time())
		expires_at = created_at + 3600
		
		# Insert session
		con.execute("""
			INSERT INTO user_sessions(session_id, user_id, nonce, created_at, expires_at)
			VALUES(?, ?, ?, ?, ?)
		""", (session_id, user_id, nonce, created_at, expires_at))
		
		# Update last login
		con.execute("UPDATE users SET last_login=? WHERE user_id=?", (created_at, user_id))
		
		con.commit()
		return session_id
		
	except Exception:
		con.rollback()
		return None

def verify_nonce_signature(con: sqlite3.Connection, session_id: str, nonce: str, 
                          signature: str) -> bool:
	"""Verify that user signed the nonce correctly"""
	try:
		# Get session and user info
		cur = con.execute("""
			SELECT s.user_id, s.nonce, s.expires_at, u.pubkey
			FROM user_sessions s
			JOIN users u ON s.user_id = u.user_id
			WHERE s.session_id = ?
		""", (session_id,))
		
		row = cur.fetchone()
		if not row:
			return False
		
		user_id, stored_nonce, expires_at, pubkey_b64 = row
		
		# Check if session is expired
		if int(time.time()) > expires_at:
			return False
		
		# Check if nonce matches
		if nonce != stored_nonce:
			return False
		
		# Verify signature using RSA-PSS
		from .crypto import import_pubkey_b64url, verify_transport
		
		try:
			pubkey = import_pubkey_b64url(pubkey_b64)
			# User should sign the nonce
			nonce_bytes = nonce.encode('utf-8')
			
			if not verify_transport(pubkey, nonce_bytes, signature):
				return False
		except Exception:
			return False
		
		return True
		
	except Exception:
		return False

def cleanup_expired_sessions(con: sqlite3.Connection) -> int:
	"""Clean up expired sessions"""
	try:
		cur = con.execute("DELETE FROM user_sessions WHERE expires_at < ?", (int(time.time()),))
		con.commit()
		return cur.rowcount
	except Exception:
		con.rollback()
		return 0

# Directory functions (Spec §13)
def get_pubkey(con: sqlite3.Connection, user_id: str) -> Optional[str]:
	"""Get user's public key"""
	cur = con.execute("SELECT pubkey FROM users WHERE user_id=?", (user_id,))
	row = cur.fetchone()
	return row[0] if row else None

def get_user_info(con: sqlite3.Connection, user_id: str) -> Optional[Dict[str, Any]]:
	"""Get user information including metadata"""
	cur = con.execute("""
		SELECT user_id, pubkey, privkey_store, meta, version, created_at, last_login
		FROM users WHERE user_id=?
	""", (user_id,))
	
	row = cur.fetchone()
	if not row:
		return None
	
	user_id, pubkey, privkey_store, meta_json, version, created_at, last_login = row
	
	return {
		"user_id": user_id,
		"pubkey": pubkey,
		"privkey_store": privkey_store,
		"meta": json.loads(meta_json) if meta_json else {},
		"version": version,
		"created_at": created_at,
		"last_login": last_login
	}

def list_online_users(con: sqlite3.Connection) -> list[Dict[str, Any]]:
	"""List all users (for /list command)"""
	cur = con.execute("""
		SELECT user_id, pubkey, meta, version, last_login
		FROM users
		ORDER BY user_id
	""")
	
	users = []
	for row in cur.fetchall():
		user_id, pubkey, meta_json, version, last_login = row
		users.append({
			"user_id": user_id,
			"pubkey": pubkey,
			"meta": json.loads(meta_json) if meta_json else {},
			"version": version,
			"last_login": last_login
		})
	
	return users

# Group/Channel management
# def create_public_channel(con: sqlite3.Connection) -> bool:
# 	"""Create the public channel (called 'public')"""
# 	try:
# 		# Check if public channel already exists
# 		cur = con.execute("SELECT group_id FROM groups WHERE group_id='public'")
# 		if cur.fetchone():
# 			return True  # Already exists
		
# 		# Create public channel
# 		con.execute("""
# 			INSERT INTO groups(group_id, creator_id, created_at, meta, version)
# 			VALUES('public', 'system', ?, ?, ?)
# 		""", (int(time.time()), json.dumps({"name": "Public Channel"}), 1))
		
# 		con.commit()
# 		return True
		
# 	except Exception:
# 		con.rollback()
# 		return False

# def add_user_to_public_channel(con: sqlite3.Connection, user_id: str, wrapped_key: str) -> bool:
# 	"""Add user to public channel"""
# 	try:
# 		con.execute("""
# 			INSERT OR REPLACE INTO group_members(group_id, member_id, role, wrapped_key, added_at)
# 			VALUES('public', ?, 'member', ?, ?)
# 		""", (user_id, wrapped_key, int(time.time())))
		
# 		con.commit()
# 		return True
		
# 	except Exception:
# 		con.rollback()
# 		return False

# def get_public_channel_members(con: sqlite3.Connection) -> list[str]:
# 	"""Get list of public channel members"""
# 	cur = con.execute("""
# 		SELECT member_id FROM group_members 
# 		WHERE group_id='public' 
# 		ORDER BY member_id
# 	""")
	
# 	return [row[0] for row in cur.fetchall()]

def register_dynamic_user(con: sqlite3.Connection, user_id: str, pubkey_b64url: str, 
                         enc_pubkey_b64url: str = None,
                         meta: Dict[str, Any] = None, version: int = 1) -> bool:
	"""
	Register a user dynamically upon USER_HELLO (Protocol-Compliant §9.1).
	For external users connecting from other groups' servers.
	Does not require privkey_store or pake_password.
	
	Args:
		user_id: User's UUID
		pubkey_b64url: Signing public key (base64url RSA-4096)
		enc_pubkey_b64url: Encryption public key (base64url RSA-4096), defaults to pubkey if not provided
		meta: Optional metadata dictionary
		version: Version number
	"""
	try:
		# If no separate encryption key, use signing key for both (backward compatibility)
		if enc_pubkey_b64url is None:
			enc_pubkey_b64url = pubkey_b64url
		
		# Validate user_id format (should be UUID v4)
		if not _is_valid_uuid(user_id):
			return False
		
		# Validate RSA-4096 public key
		try:
			pubkey = import_pubkey_b64url(pubkey_b64url)
			if not validate_rsa_key_size(pubkey) or not validate_rsa_public_exponent(pubkey):
				return False
		except Exception:
			return False
		
		# Check if user already exists
		cur = con.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,))
		if cur.fetchone():
			return False  # User already exists
		
		# Serialize meta
		meta_json = json.dumps(meta) if meta else None
		
		# Insert with both keys
		privkey_store = "EXTERNAL_USER"
		pake_password = "EXTERNAL_USER"
		
		con.execute("""
			INSERT INTO users(user_id, pubkey, enc_pubkey, privkey_store, pake_password, meta, version, created_at, last_login)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		""", (user_id, pubkey_b64url, enc_pubkey_b64url, privkey_store, pake_password, meta_json, version, int(time.time()), int(time.time())))
		
		con.commit()
		return True
	except Exception as e:
		# Assuming logger is available, otherwise remove this line
		# logger.error(f"Dynamic registration failed for {user_id}: {e}")
		return False

# Utility functions
def _is_valid_uuid(uuid_string: str) -> bool:
	"""Basic UUID v4 validation"""
	import re
	uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
	return bool(re.match(uuid_pattern, uuid_string.lower()))

# # Legacy function for backward compatibility
# def register_user_legacy(con: sqlite3.Connection, user_id: str, pubkey_b64url: str, 
#                         privkey_store: str, pake_password: str, meta: str, version: int) -> None:
# 	"""Legacy register_user function for backward compatibility"""
# 	con.execute("INSERT OR REPLACE INTO users(user_id,pubkey,privkey_store,pake_password,meta,version,created_at,last_login) VALUES(?,?,?,?,?,?,?,?)",
# 	            (user_id, pubkey_b64url, privkey_store, pake_password, meta, version, int(time.time()), None))
# 	con.commit()

