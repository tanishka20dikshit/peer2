from __future__ import annotations
import os, uuid, asyncio
from . import config
from .db import open_db
from .ws_server import run_server
from .crypto import generate_key_pair, export_privkey_pem, export_pubkey_pem, import_privkey_pem, import_pubkey_pem
import logging

logger = logging.getLogger(__name__)

def load_or_create_server_id(path: str) -> str:
	"""Load or create server UUID (Protocol §5.1)"""
	if os.path.exists(path):
		return open(path, "r").read().strip()
	sid = str(uuid.uuid4())
	with open(path, "w") as f:
		f.write(sid)
	return sid


def load_or_create_server_keys(priv_path: str, pub_path: str):
	"""
	Load or create server RSA-4096 key pair (Protocol §4)
	
	Returns:
		tuple: (private_key, public_key)
	"""
	# Check if keys already exist
	if os.path.exists(priv_path) and os.path.exists(pub_path):
		try:
			# Load existing keys
			with open(priv_path, "rb") as f:
				priv_key = import_privkey_pem(f.read())
			with open(pub_path, "rb") as f:
				pub_key = import_pubkey_pem(f.read())
			
			logger.info(f"Loaded existing server keys from {priv_path} and {pub_path}")
			return priv_key, pub_key
			
		except Exception as e:
			logger.error(f"Failed to load server keys: {e}")
			logger.warning("Generating new server keys...")
	
	# Generate new RSA-4096 key pair (Protocol §4 - RSA-4096 only)
	logger.info("Generating new RSA-4096 server key pair...")
	priv_key, pub_key = generate_key_pair()
	
	# Save keys to disk
	try:
		with open(priv_path, "wb") as f:
			f.write(export_privkey_pem(priv_key))
		with open(pub_path, "wb") as f:
			f.write(export_pubkey_pem(pub_key))
		
		# Set restrictive permissions on private key (Unix-like systems)
		if hasattr(os, 'chmod'):
			os.chmod(priv_path, 0o600)  # Read/write for owner only
		
		logger.info(f"Saved server keys to {priv_path} and {pub_path}")
		return priv_key, pub_key
		
	except Exception as e:
		logger.error(f"Failed to save server keys: {e}")
		raise


def main():
	# Configure logging (ADD THIS AT THE START)
	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
	)
	
	# Load or create server UUID (Protocol §5.1)
	sid = load_or_create_server_id(config.SERVER_ID_FILE)
	
	# Load or create server RSA-4096 key pair (Protocol §4)
	priv_key_path = os.getenv("CHAT_SERVER_PRIVKEY", "server_private_key.pem")
	pub_key_path = os.getenv("CHAT_SERVER_PUBKEY", "server_public_key.pem")
	priv_key, pub_key = load_or_create_server_keys(priv_key_path, pub_key_path)
	
	# Open database
	con = open_db(config.DB_PATH)
	
	# Store our own public key in server_keys table for consistency
	from .server_keys import store_server_key, init_server_keys_table
	from .crypto import export_pubkey_b64url
	init_server_keys_table(con)
	store_server_key(con, sid, export_pubkey_b64url(pub_key), 
	                 config.SERVER_HOST, config.SERVER_PORT)
	
	logger.info(f"Server {sid} starting on {config.SERVER_HOST}:{config.SERVER_PORT}")
	
	# Start server with keys (enables signing per Protocol §4, §12)
	asyncio.run(run_server(config.SERVER_HOST, config.SERVER_PORT, sid, config.DB_PATH, 
	                       priv_key, pub_key))

if __name__ == "__main__":
	main()