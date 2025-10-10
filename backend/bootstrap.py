"""
Server Bootstrap Implementation (Protocol §8.1)
Handles server joining, introducer communication, and network announcement.
"""

from __future__ import annotations
import asyncio
import json
import websockets
import logging
from typing import Dict, Any, List, Optional, Tuple
from .crypto import (
    sign_transport, verify_transport, canonical_json,
    import_pubkey_b64url, export_pubkey_b64url
)
from .routing import servers, server_addrs, Link
from .protocol import now_ms
from .server_keys import store_server_key, get_server_key, get_server_info

logger = logging.getLogger(__name__)

class BootstrapClient:
    """Handles bootstrap process for joining a server network"""
    
    def __init__(self, server_id: str, host: str, port: int, 
                 priv_key, pub_key, bootstrap_list: List[Dict[str, Any]]):
        self.server_id = server_id
        self.host = host
        self.port = port
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.bootstrap_list = bootstrap_list
        self.connected_servers: Dict[str, websockets.WebSocketClientProtocol] = {}
        
    async def join_network(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Join the network via bootstrap introducer (Protocol §8.1)
        Returns: (success, server_list)
        """
        logger.info(f"Server {self.server_id} attempting to join network")
        
        # Try each bootstrap server in order
        for introducer in self.bootstrap_list:
            try:
                logger.info(f"Trying introducer at {introducer['host']}:{introducer['port']}")
                success, server_list = await self._bootstrap_via_introducer(introducer)
                if success:
                    logger.info(f"Successfully bootstrapped via {introducer['host']}:{introducer['port']}")
                    return True, server_list
            except Exception as e:
                logger.warning(f"Failed to bootstrap via {introducer['host']}:{introducer['port']}: {e}")
                continue
        
        logger.error("Failed to bootstrap via all introducers")
        return False, None
    
    async def _bootstrap_via_introducer(self, introducer: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Bootstrap via a single introducer"""
        uri = f"ws://{introducer['host']}:{introducer['port']}"
        
        try:
            async with websockets.connect(uri, max_size=None) as ws:
                # Send SERVER_HELLO_JOIN (Protocol §8.1)
                join_msg = self._create_server_hello_join(introducer)
                await ws.send(json.dumps(join_msg))
                logger.debug(f"Sent SERVER_HELLO_JOIN to {introducer['host']}:{introducer['port']}")
                
                # Wait for SERVER_WELCOME response
                response = await asyncio.wait_for(ws.recv(), timeout=10.0)
                welcome_msg = json.loads(response)
                
                if welcome_msg.get("type") != "SERVER_WELCOME":
                    logger.error(f"Expected SERVER_WELCOME, got {welcome_msg.get('type')}")
                    return False, None
                
                # Validate and process SERVER_WELCOME
                if not self._validate_server_welcome(welcome_msg, introducer):
                    logger.error("SERVER_WELCOME validation failed")
                    return False, None
                
                payload = welcome_msg["payload"]
                assigned_id = payload.get("assigned_id")
                server_list = payload.get("clients", [])
                
                logger.info(f"Received SERVER_WELCOME: assigned_id={assigned_id}, servers={len(server_list)}")
                
                # Update our server ID if changed
                if assigned_id and assigned_id != self.server_id:
                    logger.warning(f"Server ID changed from {self.server_id} to {assigned_id}")
                    self.server_id = assigned_id
                
                return True, server_list
                
        except asyncio.TimeoutError:
            logger.error("Timeout waiting for SERVER_WELCOME")
            return False, None
        except Exception as e:
            logger.error(f"Bootstrap error: {e}")
            return False, None
    
    def _create_server_hello_join(self, introducer: Dict[str, Any]) -> Dict[str, Any]:
        """Create SERVER_HELLO_JOIN message (Protocol §8.1)"""
        pubkey_b64 = export_pubkey_b64url(self.pub_key)
        
        payload = {
            "host": self.host,
            "port": self.port,
            "pubkey": pubkey_b64
        }
        
        msg = {
            "type": "SERVER_HELLO_JOIN",
            "from": self.server_id,
            "to": f"{introducer['host']}:{introducer['port']}",
            "ts": now_ms(),
            "payload": payload
        }
        
        # Sign the payload
        msg["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        
        return msg
    
    def _validate_server_welcome(self, msg: Dict[str, Any], introducer: Dict[str, Any]) -> bool:
        """Validate SERVER_WELCOME message"""
        try:
            # Check message structure
            if "payload" not in msg or "sig" not in msg:
                logger.error("SERVER_WELCOME missing required fields")
                return False
            
            # Verify signature if introducer pubkey is available
            if "pubkey" in introducer and introducer["pubkey"] != "<BASE64URL_RSA4096_PUB>":
                try:
                    introducer_pubkey = import_pubkey_b64url(introducer["pubkey"])
                    payload_bytes = canonical_json(msg["payload"])
                    if not verify_transport(introducer_pubkey, payload_bytes, msg["sig"]):
                        logger.error("SERVER_WELCOME signature verification failed")
                        return False
                except Exception as e:
                    logger.warning(f"Could not verify SERVER_WELCOME signature: {e}")
            
            # Check payload structure
            payload = msg["payload"]
            if "assigned_id" not in payload:
                logger.error("SERVER_WELCOME missing assigned_id")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"SERVER_WELCOME validation error: {e}")
            return False
    
    async def announce_to_network(self, server_list: List[Dict[str, Any]]) -> bool:
        """
        Announce this server to all known servers (Protocol §8.1)
        Sends SERVER_ANNOUNCE to all servers in the network
        """
        logger.info(f"Announcing server {self.server_id} to {len(server_list)} servers")
        
        announce_msg = self._create_server_announce()
        
        # Connect to all servers and send announcement
        tasks = []
        for server_info in server_list:
            task = self._announce_to_server(server_info, announce_msg)
            tasks.append(task)
        
        # Wait for all announcements to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is True)
        logger.info(f"Successfully announced to {success_count}/{len(server_list)} servers")
        
        return success_count > 0
    
    def _create_server_announce(self) -> Dict[str, Any]:
        """Create SERVER_ANNOUNCE message (Protocol §8.1)"""
        pubkey_b64 = export_pubkey_b64url(self.pub_key)
        
        payload = {
            "host": self.host,
            "port": self.port,
            "pubkey": pubkey_b64
        }
        
        msg = {
            "type": "SERVER_ANNOUNCE",
            "from": self.server_id,
            "to": "*",  # Broadcast to all servers
            "ts": now_ms(),
            "payload": payload
        }
        
        # Sign the payload
        msg["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        
        return msg
    
    async def _announce_to_server(self, server_info: Dict[str, Any], announce_msg: Dict[str, Any]) -> bool:
        """Announce to a single server"""
        try:
            # Extract server info - handle both formats from protocol
            if "user_id" in server_info:
                # Format from SERVER_WELCOME: {"user_id":"...", "host":"...", "port":...}
                host = server_info.get("host")
                port = server_info.get("port")
                server_id = server_info.get("user_id")  # This is actually server_id in the protocol
            else:
                # Standard format: {"server_id":"...", "host":"...", "port":...}
                host = server_info.get("host")
                port = server_info.get("port")
                server_id = server_info.get("server_id")
            
            if not host or not port:
                logger.warning(f"Invalid server info: {server_info}")
                return False
            
            uri = f"ws://{host}:{port}"
            logger.debug(f"Connecting to server at {uri}")
            
            async with websockets.connect(uri, max_size=None) as ws:
                await ws.send(json.dumps(announce_msg))
                logger.debug(f"Sent SERVER_ANNOUNCE to {host}:{port}")
                
                # Wait for acknowledgement (optional)
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    logger.debug(f"Received response from {host}:{port}: {response[:100]}")
                except asyncio.TimeoutError:
                    # No response is okay for announcements
                    pass
                
                return True
                
        except Exception as e:
            logger.warning(f"Failed to announce to {server_info.get('host', 'unknown')}: {e}")
            return False
    
    async def connect_to_servers(self, server_list: List[Dict[str, Any]]) -> int:
        """
        Establish persistent connections to all known servers
        Returns: number of successful connections
        """
        logger.info(f"Establishing persistent connections to {len(server_list)} servers")
        
        tasks = []
        for server_info in server_list:
            task = self._connect_to_server(server_info)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is not None and not isinstance(r, Exception))
        logger.info(f"Successfully connected to {success_count}/{len(server_list)} servers")
        
        return success_count
    
    async def _connect_to_server(self, server_info: Dict[str, Any]) -> Optional[websockets.WebSocketClientProtocol]:
        """Establish persistent connection to a single server"""
        try:
            # Extract server info
            if "user_id" in server_info:
                host = server_info.get("host")
                port = server_info.get("port")
                server_id = server_info.get("user_id")
                pubkey_b64 = server_info.get("pubkey")
            else:
                host = server_info.get("host")
                port = server_info.get("port")
                server_id = server_info.get("server_id")
                pubkey_b64 = server_info.get("pubkey")
            
            if not host or not port or not server_id:
                logger.warning(f"Invalid server info: {server_info}")
                return None
            
            uri = f"ws://{host}:{port}"
            logger.debug(f"Connecting to server {server_id} at {uri}")
            
            ws = await websockets.connect(uri, max_size=None)
            
            # Store connection
            self.connected_servers[server_id] = ws
            
            # Register in routing table
            link = Link(ws=ws, role="server", id=server_id)
            servers[server_id] = link
            server_addrs[server_id] = (host, port)
            
            # Store pubkey if available
            if pubkey_b64:
                # TODO: Store server public keys for signature verification
                store_server_key(self.db_connection, server_id, pubkey_b64, host, port)
                logger.info(f"Stored public key for server {server_id}")
            
            logger.info(f"Connected to server {server_id} at {host}:{port}")
            
            return ws
            
        except Exception as e:
            logger.warning(f"Failed to connect to server {server_info.get('server_id', 'unknown')}: {e}")
            return None


# Handler functions for bootstrap messages

async def handle_server_hello_join(ctx, env: Dict[str, Any]):
    """
    Handle SERVER_HELLO_JOIN message (Protocol §8.1)
    This server is acting as an introducer
    """
    logger.info(f"Received SERVER_HELLO_JOIN from {env['from']}")
    
    joining_server_id = env["from"]
    payload = env["payload"]
    
    # Validate payload
    if not all(k in payload for k in ["host", "port", "pubkey"]):
        await ctx.send_error("BAD_PAYLOAD", "Missing required fields in SERVER_HELLO_JOIN")
        return
    
    # Verify signature
    try:
        joining_pubkey = import_pubkey_b64url(payload["pubkey"])
        if not verify_transport(joining_pubkey, canonical_json(payload), env.get("sig", "")):
            await ctx.send_error("INVALID_SIG", "Signature verification failed")
            return
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        await ctx.send_error("INVALID_SIG", f"Signature verification error: {e}")
        return
    
    # Store server public key (FIXED TODO #293)
    from .server_keys import store_server_key
    store_server_key(ctx.server.db, joining_server_id, payload["pubkey"], payload["host"], payload["port"])
    
    # Check if server_id is unique (if not, generate a new one)
    assigned_id = joining_server_id
    if joining_server_id in servers:
        import uuid
        assigned_id = str(uuid.uuid4())
        logger.warning(f"Server ID {joining_server_id} already in use, assigning {assigned_id}")
    
    # Build list of known servers with actual pubkeys (FIXED TODO #350)
    from .server_keys import list_known_servers
    known_servers = list_known_servers(ctx.server.db)
    
    server_list = []
    for srv in known_servers:
        if srv['server_id'] != joining_server_id:
                server_list.append({
                "user_id": srv['server_id'],  # Protocol uses "user_id" field for server_id
                "host": srv['host'] or "unknown",
                "port": srv['port'] or 0,
                "pubkey": srv['pubkey']  # Now using actual pubkey from storage
                })
    
    # Send SERVER_WELCOME
    welcome_payload = {
        "assigned_id": assigned_id,
        "clients": server_list
    }
    
    welcome_msg = {
        "type": "SERVER_WELCOME",
        "from": ctx.server.server_id,
        "to": joining_server_id,
        "ts": ctx.server.now_ms(),
        "payload": welcome_payload
    }
    
    # Sign the payload (FIXED TODO #371)
    if hasattr(ctx.server, 'priv_key') and ctx.server.priv_key:
        welcome_msg["sig"] = sign_transport(ctx.server.priv_key, canonical_json(welcome_payload))
    else:
        logger.error("Server private key not available for signing SERVER_WELCOME")
        welcome_msg["sig"] = ""
    
    await ctx.send(welcome_msg)
    
    # Register the joining server
    servers[assigned_id] = ctx.link
    server_addrs[assigned_id] = (payload["host"], payload["port"])
    
    logger.info(f"Sent SERVER_WELCOME to {joining_server_id}, assigned ID: {assigned_id}")


async def handle_server_announce(ctx, env: Dict[str, Any]):
    """
    Handle SERVER_ANNOUNCE message (Protocol §8.1)
    A server is announcing its presence to the network
    """
    logger.info(f"Received SERVER_ANNOUNCE from {env['from']}")
    
    server_id = env["from"]
    payload = env["payload"]
    
    # Validate payload
    if not all(k in payload for k in ["host", "port", "pubkey"]):
        logger.error("SERVER_ANNOUNCE missing required fields")
        return
    
    # Verify signature
    try:
        server_pubkey = import_pubkey_b64url(payload["pubkey"])
        if not verify_transport(server_pubkey, canonical_json(payload), env.get("sig", "")):
            logger.error(f"SERVER_ANNOUNCE signature verification failed for {server_id}")
            return
    except Exception as e:
        logger.error(f"SERVER_ANNOUNCE signature verification error: {e}")
        return
    
    # Register server and store address (Protocol §8.1)
    servers[server_id] = ctx.link
    server_addrs[server_id] = (payload["host"], payload["port"])
    
    # Store server public key for future signature verification (FIXED TODO #411)
    from .server_keys import store_server_key
    store_server_key(ctx.server.db, server_id, payload["pubkey"], payload["host"], payload["port"])
    
    logger.info(f"Registered server {server_id} at {payload['host']}:{payload['port']}")
    
    # Forward announcement to other servers (mesh network) (FIXED TODO #416)
    from .routing import servers as server_dict
    forward_count = 0
    for other_server_id, other_link in server_dict.items():
        # Don't forward back to sender or to ourselves
        if other_server_id == server_id or other_server_id == ctx.server.server_id:
            continue
        
        try:
            if other_link.ws and not other_link.ws.closed:
                await other_link.ws.send(json.dumps(env))
                forward_count += 1
                logger.debug(f"Forwarded SERVER_ANNOUNCE to server {other_server_id}")
        except Exception as e:
            logger.error(f"Failed to forward SERVER_ANNOUNCE to {other_server_id}: {e}")
    
    logger.info(f"Forwarded SERVER_ANNOUNCE from {server_id} to {forward_count} other servers")


async def handle_server_welcome(ctx, env: Dict[str, Any]):
    """
    Handle SERVER_WELCOME message (Protocol §8.1)
    Received by a joining server from an introducer
    
    This happens when:
    1. Server sends SERVER_HELLO_JOIN to introducer
    2. Introducer responds with SERVER_WELCOME containing assigned_id and server list
    3. Joining server processes the welcome and connects to network
    """
    logger.info(f"Received SERVER_WELCOME from {env['from']}")
    
    introducer_id = env["from"]
    payload = env["payload"]
    
    # Validate payload structure
    if "assigned_id" not in payload:
        logger.error("SERVER_WELCOME missing assigned_id")
        return
    
    if "clients" not in payload:
        logger.error("SERVER_WELCOME missing clients list")
        return
    
    assigned_id = payload["assigned_id"]
    server_list = payload["clients"]
    
    # Verify signature from introducer
    try:
        from .server_keys import get_server_key
        introducer_pubkey_b64 = get_server_key(ctx.server.db, introducer_id)
        
        if introducer_pubkey_b64:
            introducer_pubkey = import_pubkey_b64url(introducer_pubkey_b64)
            if not verify_transport(introducer_pubkey, canonical_json(payload), env.get("sig", "")):
                logger.error(f"SERVER_WELCOME signature verification failed from {introducer_id}")
                return
            logger.debug(f"SERVER_WELCOME signature verified from {introducer_id}")
        else:
            logger.warning(f"No stored public key for introducer {introducer_id}, accepting without verification")
    except Exception as e:
        logger.error(f"Error verifying SERVER_WELCOME signature: {e}")
        return
    
    # Check if our server_id was changed (collision resolution)
    if assigned_id != ctx.server.server_id:
        logger.warning(
            f"Server ID reassigned by introducer: {ctx.server.server_id} -> {assigned_id}. "
            f"This indicates a UUID collision."
        )
        # In a production system, would need to update server_id everywhere
        # For now, just log the warning
    
    # Process server list
    logger.info(f"Received {len(server_list)} servers in network from introducer")
    
    # Store information about other servers
    from .server_keys import store_server_key
    for server_info in server_list:
        if "user_id" in server_info and "pubkey" in server_info:
            server_id = server_info["user_id"]  # Protocol uses "user_id" field for server_id
            pubkey = server_info.get("pubkey")
            host = server_info.get("host")
            port = server_info.get("port")
            
            # Store server public key
            if pubkey and pubkey != "...":  # Skip placeholder values
                store_server_key(ctx.server.db, server_id, pubkey, host, port)
                logger.debug(f"Stored server key for {server_id}")
    
    # If we have a connection manager, connect to these servers
    if hasattr(ctx.server, 'connection_manager') and ctx.server.connection_manager:
        logger.info("Initiating connections to network servers...")
        for server_info in server_list:
            if "user_id" in server_info and "host" in server_info and "port" in server_info:
                server_id = server_info["user_id"]
                host = server_info["host"]
                port = server_info["port"]
                pubkey = server_info.get("pubkey")
                
                # Skip our own server and placeholder values
                if server_id == ctx.server.server_id or host == "unknown":
                    continue
                
                # Attempt to connect (non-blocking)
                try:
                    asyncio.create_task(
                        ctx.server.connection_manager.connect_to_server(
                            server_id, host, port, pubkey
                        )
                    )
                    logger.debug(f"Initiated connection to server {server_id}")
                except Exception as e:
                    logger.error(f"Failed to initiate connection to {server_id}: {e}")
    
    logger.info(
        f"SERVER_WELCOME processed successfully. "
        f"Assigned ID: {assigned_id}, Network servers: {len(server_list)}"
    )
