"""
Server Connection Management (Phase 3B)
Handles persistent server-to-server connections, health monitoring, and reconnection logic.
Protocol §8, §11
"""

from __future__ import annotations
import asyncio
import json
import websockets
import logging
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime
from .crypto import sign_transport, verify_transport, canonical_json, import_pubkey_b64url
from .routing import servers, server_addrs, Link
from .protocol import now_ms
from .config import HEARTBEAT_INTERVAL_SEC, HEARTBEAT_TIMEOUT_SEC

logger = logging.getLogger(__name__)

@dataclass
class ServerConnection:
    """Represents a persistent server-to-server connection"""
    server_id: str
    host: str
    port: int
    websocket: Optional[websockets.WebSocketClientProtocol]
    pubkey: Optional[str]
    last_heartbeat: float
    connection_attempts: int = 0
    is_connected: bool = False
    receive_task: Optional[asyncio.Task] = None

class ServerConnectionManager:
    """Manages all server-to-server connections"""
    
    def __init__(self, local_server_id: str, priv_key, pub_key, message_handler):
        self.local_server_id = local_server_id
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.message_handler = message_handler
        
        # Connection management
        self.connections: Dict[str, ServerConnection] = {}
        self.connection_lock = asyncio.Lock()
        
        # Background tasks
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.health_monitor_task: Optional[asyncio.Task] = None
        self.reconnect_task: Optional[asyncio.Task] = None
        
        # State tracking
        self.is_running = False
        self.failed_servers: Set[str] = set()
        
    async def start(self):
        """Start the connection manager and background tasks"""
        logger.info(f"Starting ServerConnectionManager for {self.local_server_id}")
        self.is_running = True
        
        # Start background tasks
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self.health_monitor_task = asyncio.create_task(self._health_monitor_loop())
        self.reconnect_task = asyncio.create_task(self._reconnect_loop())
        
        logger.info("ServerConnectionManager started successfully")
    
    async def stop(self):
        """Stop the connection manager and close all connections"""
        logger.info("Stopping ServerConnectionManager")
        self.is_running = False
        
        # Cancel background tasks
        for task in [self.heartbeat_task, self.health_monitor_task, self.reconnect_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Close all connections
        await self.close_all_connections()
        
        logger.info("ServerConnectionManager stopped")
    
    async def connect_to_server(self, server_id: str, host: str, port: int, 
                                pubkey: Optional[str] = None) -> bool:
        """
        Establish a persistent connection to a server
        Returns: True if connection successful, False otherwise
        """
        async with self.connection_lock:
            # Check if already connected
            if server_id in self.connections and self.connections[server_id].is_connected:
                logger.debug(f"Already connected to server {server_id}")
                return True
            
            # Create or update connection object
            if server_id not in self.connections:
                self.connections[server_id] = ServerConnection(
                    server_id=server_id,
                    host=host,
                    port=port,
                    websocket=None,
                    pubkey=pubkey,
                    last_heartbeat=asyncio.get_event_loop().time(),
                    connection_attempts=0,
                    is_connected=False
                )
            
            connection = self.connections[server_id]
            connection.connection_attempts += 1
            
            try:
                # Establish WebSocket connection
                uri = f"ws://{host}:{port}"
                logger.info(f"Connecting to server {server_id} at {uri} (attempt {connection.connection_attempts})")
                
                ws = await asyncio.wait_for(
                    websockets.connect(uri, max_size=None),
                    timeout=10.0
                )
                
                # Send initial SERVER_ANNOUNCE to identify ourselves
                announce_msg = self._create_server_announce()
                await ws.send(json.dumps(announce_msg))
                logger.debug(f"Sent SERVER_ANNOUNCE to {server_id}")
                
                # Update connection state
                connection.websocket = ws
                connection.is_connected = True
                connection.last_heartbeat = asyncio.get_event_loop().time()
                
                # Register in routing table
                link = Link(ws=ws, role="server", id=server_id)
                servers[server_id] = link
                server_addrs[server_id] = (host, port)
                
                # Start receiving messages from this server
                connection.receive_task = asyncio.create_task(
                    self._receive_messages(server_id, ws)
                )
                
                logger.info(f"Successfully connected to server {server_id}")
                
                # Remove from failed servers set
                self.failed_servers.discard(server_id)
                
                return True
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout connecting to server {server_id}")
                connection.is_connected = False
                self.failed_servers.add(server_id)
                return False
                
            except Exception as e:
                logger.error(f"Error connecting to server {server_id}: {e}")
                connection.is_connected = False
                self.failed_servers.add(server_id)
                return False
    
    async def disconnect_from_server(self, server_id: str, reason: str = "Manual disconnect"):
        """Disconnect from a specific server"""
        async with self.connection_lock:
            if server_id not in self.connections:
                logger.warning(f"Cannot disconnect from {server_id}: not in connections")
                return
            
            connection = self.connections[server_id]
            
            # Cancel receive task
            if connection.receive_task and not connection.receive_task.done():
                connection.receive_task.cancel()
                try:
                    await connection.receive_task
                except asyncio.CancelledError:
                    pass
            
            # Send optional CTRL_CLOSE message (Protocol §6)
            if connection.websocket and not connection.websocket.closed:
                try:
                    ctrl_close_msg = {
                        "type": "CTRL_CLOSE",
                        "from": self.local_server_id,
                        "to": server_id,
                        "ts": int(asyncio.get_event_loop().time() * 1000),
                        "payload": {},
                        "sig": ""
                    }
                    await connection.websocket.send(json.dumps(ctrl_close_msg, separators=(",", ":"), sort_keys=True))
                    logger.debug(f"Sent CTRL_CLOSE to server {server_id}")
                except Exception as e:
                    logger.debug(f"Could not send CTRL_CLOSE to {server_id}: {e}")
            
            # Close WebSocket with code 1000 (Protocol §6)
            if connection.websocket and not connection.websocket.closed:
                try:
                    await connection.websocket.close(code=1000)
                    logger.info(f"Closed connection to server {server_id}: {reason}")
                except Exception as e:
                    logger.error(f"Error closing connection to {server_id}: {e}")
            
            # Update state
            connection.is_connected = False
            connection.websocket = None
            
            # Remove from routing table
            if server_id in servers:
                del servers[server_id]
            if server_id in server_addrs:
                del server_addrs[server_id]
    
    async def close_all_connections(self):
        """Close all server connections"""
        logger.info("Closing all server connections")
        
        # Get list of server IDs to avoid modification during iteration
        server_ids = list(self.connections.keys())
        
        for server_id in server_ids:
            await self.disconnect_from_server(server_id, "Shutting down")
    
    async def send_to_server(self, server_id: str, message: Dict[str, Any]) -> bool:
        """
        Send a message to a specific server
        Returns: True if sent successfully, False otherwise
        """
        if server_id not in self.connections:
            logger.error(f"Cannot send to {server_id}: not in connections")
            return False
        
        connection = self.connections[server_id]
        
        if not connection.is_connected or not connection.websocket:
            logger.error(f"Cannot send to {server_id}: not connected")
            return False
        
        try:
            await connection.websocket.send(json.dumps(message))
            return True
        except Exception as e:
            logger.error(f"Error sending message to {server_id}: {e}")
            # Mark as disconnected and trigger reconnection
            connection.is_connected = False
            self.failed_servers.add(server_id)
            return False
    
    async def broadcast_to_all_servers(self, message: Dict[str, Any]) -> int:
        """
        Broadcast a message to all connected servers
        Returns: number of successful sends
        """
        success_count = 0
        
        for server_id in list(self.connections.keys()):
            if await self.send_to_server(server_id, message):
                success_count += 1
        
        logger.debug(f"Broadcast message to {success_count}/{len(self.connections)} servers")
        return success_count
    
    async def _receive_messages(self, server_id: str, ws: websockets.WebSocketClientProtocol):
        """Receive and process messages from a server connection"""
        logger.debug(f"Started receiving messages from server {server_id}")
        
        try:
            async for message in ws:
                try:
                    msg = json.loads(message)
                    
                    # Update last heartbeat time
                    if server_id in self.connections:
                        self.connections[server_id].last_heartbeat = asyncio.get_event_loop().time()
                    
                    # Handle the message
                    await self.message_handler(server_id, msg)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON from server {server_id}: {e}")
                except Exception as e:
                    logger.error(f"Error processing message from {server_id}: {e}")
        
        except websockets.exceptions.ConnectionClosed:
            logger.warning(f"Connection closed by server {server_id}")
        except Exception as e:
            logger.error(f"Error receiving from server {server_id}: {e}")
        finally:
            # Mark as disconnected
            if server_id in self.connections:
                self.connections[server_id].is_connected = False
                self.failed_servers.add(server_id)
            
            logger.info(f"Stopped receiving messages from server {server_id}")
    
    async def _heartbeat_loop(self):
        """Send heartbeat messages to all connected servers (Protocol §11)"""
        logger.info(f"Starting heartbeat loop (interval: {HEARTBEAT_INTERVAL_SEC}s)")
        
        while self.is_running:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
                
                # Create heartbeat message
                heartbeat_msg = {
                    "type": "HEARTBEAT",
                    "from": self.local_server_id,
                    "to": "*",
                    "ts": now_ms(),
                    "payload": {},
                }
                
                # Sign heartbeat
                heartbeat_msg["sig"] = sign_transport(
                    self.priv_key, 
                    canonical_json(heartbeat_msg["payload"])
                )
                
                # Send to all connected servers
                for server_id in list(self.connections.keys()):
                    connection = self.connections.get(server_id)
                    if connection and connection.is_connected:
                        # Customize 'to' field for each server
                        heartbeat_msg["to"] = server_id
                        await self.send_to_server(server_id, heartbeat_msg)
                
                logger.debug(f"Sent heartbeat to {len(self.connections)} servers")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
    
    async def _health_monitor_loop(self):
        """Monitor connection health and detect timeouts (Protocol §11)"""
        logger.info(f"Starting health monitor loop (timeout: {HEARTBEAT_TIMEOUT_SEC}s)")
        
        while self.is_running:
            try:
                await asyncio.sleep(5)  # Check every 5 seconds
                
                current_time = asyncio.get_event_loop().time()
                
                for server_id, connection in list(self.connections.items()):
                    if not connection.is_connected:
                        continue
                    
                    # Check if we've received anything within timeout period
                    time_since_last_heartbeat = current_time - connection.last_heartbeat
                    
                    if time_since_last_heartbeat > HEARTBEAT_TIMEOUT_SEC:
                        logger.warning(
                            f"Server {server_id} timeout: {time_since_last_heartbeat:.1f}s "
                            f"since last heartbeat (limit: {HEARTBEAT_TIMEOUT_SEC}s)"
                        )
                        
                        # Mark as failed and disconnect
                        await self.disconnect_from_server(
                            server_id, 
                            f"Heartbeat timeout ({time_since_last_heartbeat:.1f}s)"
                        )
                        self.failed_servers.add(server_id)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health monitor loop: {e}")
    
    async def _reconnect_loop(self):
        """Attempt to reconnect to failed servers (Protocol §11)"""
        logger.info("Starting reconnect loop")
        
        while self.is_running:
            try:
                await asyncio.sleep(10)  # Attempt reconnection every 10 seconds
                
                if not self.failed_servers:
                    continue
                
                logger.info(f"Attempting to reconnect to {len(self.failed_servers)} failed servers")
                
                # Try to reconnect to each failed server
                for server_id in list(self.failed_servers):
                    if server_id not in self.connections:
                        self.failed_servers.discard(server_id)
                        continue
                    
                    connection = self.connections[server_id]
                    
                    # Limit reconnection attempts
                    if connection.connection_attempts > 10:
                        logger.warning(
                            f"Server {server_id} has exceeded max reconnection attempts, "
                            f"removing from reconnect list"
                        )
                        self.failed_servers.discard(server_id)
                        continue
                    
                    # Attempt reconnection
                    logger.info(f"Reconnecting to server {server_id}...")
                    success = await self.connect_to_server(
                        server_id,
                        connection.host,
                        connection.port,
                        connection.pubkey
                    )
                    
                    if success:
                        logger.info(f"Successfully reconnected to server {server_id}")
                    else:
                        logger.warning(f"Failed to reconnect to server {server_id}")
                    
                    # Space out reconnection attempts
                    await asyncio.sleep(2)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in reconnect loop: {e}")
    
    def _create_server_announce(self) -> Dict[str, Any]:
        """Create SERVER_ANNOUNCE message for connection identification"""
        from .crypto import export_pubkey_b64url
        
        payload = {
            "host": "unknown",  # Will be filled by server
            "port": 0,
            "pubkey": export_pubkey_b64url(self.pub_key)
        }
        
        msg = {
            "type": "SERVER_ANNOUNCE",
            "from": self.local_server_id,
            "to": "*",
            "ts": now_ms(),
            "payload": payload
        }
        
        msg["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        
        return msg
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get status of all connections"""
        status = {
            "total_connections": len(self.connections),
            "connected": sum(1 for c in self.connections.values() if c.is_connected),
            "failed": len(self.failed_servers),
            "connections": []
        }
        
        for server_id, connection in self.connections.items():
            status["connections"].append({
                "server_id": server_id,
                "host": connection.host,
                "port": connection.port,
                "is_connected": connection.is_connected,
                "connection_attempts": connection.connection_attempts,
                "time_since_heartbeat": asyncio.get_event_loop().time() - connection.last_heartbeat
                    if connection.is_connected else None
            })
        
        return status


# Handler for HEARTBEAT messages (Protocol §8.4, §11)
async def handle_heartbeat(ctx, env: Dict[str, Any]):
    """Handle HEARTBEAT message from another server"""
    server_id = env["from"]
    
    # Update last heartbeat time
    if hasattr(ctx.server, 'connection_manager'):
        manager = ctx.server.connection_manager
        if server_id in manager.connections:
            manager.connections[server_id].last_heartbeat = asyncio.get_event_loop().time()
            logger.debug(f"Received heartbeat from server {server_id}")
    
    # Optionally send heartbeat response
    # (In this implementation, both servers send heartbeats independently)
