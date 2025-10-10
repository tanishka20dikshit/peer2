from __future__ import annotations
import asyncio
import json
import websockets
from websockets.server import WebSocketServerProtocol
from typing import Any, Dict
from .protocol import validate_envelope
from .handlers import HANDLERS
from .routing import Link, local_users, user_locations, servers, server_addrs
from .db import open_db, cleanup_expired_sessions
from .bootstrap import handle_server_hello_join, handle_server_announce
from .crypto import generate_key_pair, import_privkey_b64url, import_pubkey_b64url
import os
import logging
from .server_connections import ServerConnectionManager, handle_heartbeat
from .presence import PresenceManager, handle_user_advertise_message, handle_user_remove_message
from .routing_delivery import MessageRouter, handle_msg_direct, handle_server_deliver, handle_msg_public_channel
from .public_channel import PublicChannelManager
from .file_transfer import FileTransferManager

logger = logging.getLogger(__name__)

class Ctx:
	def __init__(self, ws: WebSocketServerProtocol, link: Link, server):
		self.ws = ws
		self.link = link
		self.server = server

	async def send(self, obj: Dict[str, Any]):
		await self.ws.send(json.dumps(obj, separators=(",", ":"), sort_keys=True))

	async def send_error(self, code: str, detail: str):
		# §9.5 ERROR - Sign with server key per Protocol §7, §12
		payload = {"code": code, "detail": detail}
		
		error_msg = {
			"type": "ERROR",
			"from": self.server.server_id,
			"to": self.link.id,
			"ts": self.server.now_ms(),
			"payload": payload
		}
		
		# Sign the payload (FIXED TODO)
		if hasattr(self.server, 'priv_key') and self.server.priv_key:
			from .crypto import sign_transport, canonical_json
			error_msg["sig"] = sign_transport(self.server.priv_key, canonical_json(payload))
		else:
			error_msg["sig"] = ""
		
		await self.send(error_msg)

class Server:
	def __init__(self, server_id: str, db_path: str, priv_key=None, pub_key=None, 
	             host: str = "0.0.0.0", port: int = 8765):
		self.server_id = server_id
		self.db = open_db(db_path)
		self.priv_key = priv_key
		self.pub_key = pub_key
		self.host = host
		self.port = port
		
		# Connection manager for server-to-server connections
		self.connection_manager = None
		if priv_key and pub_key:
			self.connection_manager = ServerConnectionManager(
				local_server_id=server_id,
				priv_key=priv_key,
				pub_key=pub_key,
				message_handler=self._handle_server_message
			)
		
		# Presence manager for user presence gossip
		self.presence_manager = None
		if priv_key and pub_key:
			self.presence_manager = PresenceManager(
				server_id=server_id,
				priv_key=priv_key,
				pub_key=pub_key,
				db_connection=self.db
			)
		
		# Message router for message delivery
		self.message_router = None
		if priv_key and pub_key:
			self.message_router = MessageRouter(
				server_id=server_id,
				priv_key=priv_key,
				pub_key=pub_key
			)
		
		# Public channel manager for Protocol §9.3
		self.public_channel_manager = None
		if priv_key and pub_key:
			self.public_channel_manager = PublicChannelManager(
				server_id=server_id,
				priv_key=priv_key,
				pub_key=pub_key,
				db_connection=self.db
			)
		
		# File transfer manager for Protocol §9.4 (Phase 5)
		self.file_transfer_manager = FileTransferManager(server_id=server_id)
		
		# Start background tasks
		if self.connection_manager:
			asyncio.create_task(self.connection_manager.start())

	def now_ms(self) -> int:
		import time
		return int(time.time()*1000)

	async def _cleanup_sessions_periodically(self):
		"""Clean up expired sessions every 5 minutes"""
		while True:
			await asyncio.sleep(300)  # 5 minutes
			try:
				cleanup_expired_sessions(self.db)
			except Exception:
				pass  # Log error in production

	async def handle_connection(self, ws: WebSocketServerProtocol):
		"""
		Handle incoming WebSocket connection (Protocol §6, §8, §9)
		Implements proper closure with code 1000 and optional CTRL_CLOSE message
		"""
		peer_id = None
		peer_type = None
		
		try:
			# First message must identify peer (§6)
			msg = await ws.recv()
			logger.info(f"[WS] Received first message: {msg[:200]}...")  # Log first 200 chars
			env = json.loads(msg)
			logger.info(f"[WS] Parsed envelope: type={env.get('type')}, from={env.get('from')}, to={env.get('to')}")
			ok, err = validate_envelope(env)
			if not ok:
				logger.error(f"[WS] ❌ Envelope validation failed: {err}")  # ADD THIS LINE
				logger.error(f"[WS] Failed envelope: {json.dumps(env, indent=2)[:500]}")  # ADD THIS LINE
				await ws.close(code=1002, reason=f"invalid envelope:{err}")
				return
			
			logger.info(f"[WS] ✅ Envelope validated successfully")  # ADD THIS LINE
			peer_id = env["from"]
			peer_type = "server" if env["type"].startswith("SERVER_") else "user"
			link = Link(ws=ws, role=peer_type, id=peer_id)
			ctx = Ctx(ws, link, self)
			
			logger.info(f"[WS] Dispatching {env['type']} to handler...")  # ADD THIS LINE
			await self.dispatch(ctx, env)
			logger.info(f"[WS] Handler completed for {env['type']}")  # ADD THIS LINE
			
			# Then process subsequent frames
			async for txt in ws:
				try:
					env = json.loads(txt)
					# Check for optional CTRL_CLOSE message (Protocol §6)
					if env.get("type") == "CTRL_CLOSE":
						logger.info(f"Received CTRL_CLOSE from {peer_type} {peer_id}")
						break
					await self.dispatch(ctx, env)
				except Exception as e:
					logger.error(f"Error processing message from {peer_type} {peer_id}: {e}")
					break
		
		except websockets.exceptions.ConnectionClosed:
			logger.info(f"Connection closed by {peer_type} {peer_id}")
		except Exception as e:
			logger.error(f"Error in connection handler for {peer_type} {peer_id}: {e}")
		
		finally:
			# Cleanup on disconnection (Protocol §6, §8.2)
			await self._cleanup_connection(peer_id, peer_type, ws)

	async def _cleanup_connection(self, peer_id: str | None, peer_type: str | None, ws: WebSocketServerProtocol):
		"""
		Cleanup connection on disconnect (Protocol §6, §8.2)
		Sends CTRL_CLOSE, closes with code 1000, and cleans up routing tables
		"""
		if not peer_id or not peer_type:
			# Connection never fully established
			if not ws.closed:
				await ws.close(code=1000)
			return
		
		logger.info(f"Cleaning up {peer_type} connection: {peer_id}")
		
		try:
			# Send optional CTRL_CLOSE message (Protocol §6)
			if not ws.closed:
				try:
					ctrl_close_msg = {
						"type": "CTRL_CLOSE",
						"from": self.server_id,
						"to": peer_id,
						"ts": self.now_ms(),
						"payload": {},
						"sig": ""
					}
					await ws.send(json.dumps(ctrl_close_msg, separators=(",", ":"), sort_keys=True))
					logger.debug(f"Sent CTRL_CLOSE to {peer_type} {peer_id}")
				except Exception as e:
					logger.debug(f"Could not send CTRL_CLOSE to {peer_id}: {e}")
			
			# Cleanup based on peer type
			if peer_type == "user":
				# Broadcast USER_REMOVE to network (Protocol §8.2)
				# The presence manager will handle all cleanup including
				# removing from local_users and user_locations AFTER broadcasting
				if self.presence_manager:
					try:
						success = await self.presence_manager.remove_user(peer_id, reason="disconnect")
						if success:
							logger.info(f"Broadcasted USER_REMOVE for {peer_id}")
						else:
							# Fallback: manually clean up if presence manager couldn't handle it
							if peer_id in local_users:
								del local_users[peer_id]
							if peer_id in user_locations:
								del user_locations[peer_id]
					except Exception as e:
						logger.error(f"Error broadcasting USER_REMOVE for {peer_id}: {e}")
						# Fallback cleanup on error
						if peer_id in local_users:
							del local_users[peer_id]
						if peer_id in user_locations:
							del user_locations[peer_id]
			
			elif peer_type == "server":
				# Remove server from routing tables
				if peer_id in servers:
					del servers[peer_id]
					logger.debug(f"Removed server {peer_id} from servers")
				
				if peer_id in server_addrs:
					del server_addrs[peer_id]
					logger.debug(f"Removed server {peer_id} from server_addrs")
			
			# Close WebSocket with code 1000 (normal closure, Protocol §6)
			if not ws.closed:
				await ws.close(code=1000)
				logger.info(f"Closed connection to {peer_type} {peer_id} with code 1000")
		
		except Exception as e:
			logger.error(f"Error during cleanup for {peer_type} {peer_id}: {e}")
			# Ensure connection is closed even if cleanup fails
			if not ws.closed:
				try:
					await ws.close(code=1000)
				except Exception:
					pass

	async def dispatch(self, ctx: Ctx, env: Dict[str, Any]):
		t = env["type"]
		handler = HANDLERS.get(t)
		if not handler:
			await ctx.send_error("UNKNOWN_TYPE", t)
			return
		await handler(ctx, env)

	async def _handle_server_message(self, server_id: str, msg: Dict[str, Any]):
		"""Handle messages received from other servers"""
		# This will be used by the connection manager to dispatch server messages
		# For now, just log
		logger.debug(f"Received message from server {server_id}: {msg.get('type')}")

async def run_server(host: str, port: int, server_id: str, db_path: str, priv_key=None, pub_key=None):
	server = Server(server_id, db_path, priv_key, pub_key, host, port)
	async with websockets.serve(server.handle_connection, host, port, max_size=None):
		await asyncio.Future()  # run forever