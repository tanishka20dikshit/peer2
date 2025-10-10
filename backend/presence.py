"""
User Presence Gossip Implementation (Phase 3C)
Handles user presence advertisement, removal, and propagation across the network.
Protocol §8.2
"""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Dict, Any, Optional, Set
from .crypto import sign_transport, verify_transport, canonical_json, import_pubkey_b64url
from .routing import local_users, user_locations, servers, server_addrs, Link
from .protocol import now_ms
from .db import get_user_info
from .server_keys import get_server_key

logger = logging.getLogger(__name__)

class PresenceManager:
    """Manages user presence advertisement and gossip"""
    
    def __init__(self, server_id: str, priv_key, pub_key, db_connection):
        self.server_id = server_id
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.db = db_connection
        
        # Track which servers we've sent presence to (for gossip optimization)
        self.presence_sent_to: Dict[str, Set[str]] = {}  # user_id -> set of server_ids
        
        # Track received presence messages to avoid loops
        self.seen_presence: Set[tuple] = set()  # (user_id, server_id, operation)
        
        logger.info(f"PresenceManager initialized for server {server_id}")
    
    async def advertise_user(self, user_id: str, user_meta: Optional[Dict[str, Any]] = None) -> bool:
        """
        Advertise a local user's presence to the network (Protocol §8.2)
        Called when a user connects to this server
        
        Args:
            user_id: User's UUID
            user_meta: Optional user metadata (display_name, etc.)
        
        Returns:
            True if advertisement sent successfully
        """
        logger.info(f"Advertising user {user_id} to network")
        
        # Get user metadata from database if not provided
        if user_meta is None:
            user_info = get_user_info(self.db, user_id)
            if user_info:
                user_meta = user_info.get("meta", {})
            else:
                user_meta = {}
        
        # Update local state
        user_locations[user_id] = "local"
        
        # Create USER_ADVERTISE message
        advertise_msg = self._create_user_advertise(user_id, user_meta)
        
        # Broadcast to all connected servers
        success_count = await self._broadcast_to_servers(advertise_msg)
        
        # Broadcast to all local users (so their UI updates)
        local_user_count = await self._broadcast_to_local_users(advertise_msg, exclude_user=user_id)
        
        logger.info(f"Advertised user {user_id} to {success_count} servers and {local_user_count} local users")
        
        # Track that we've sent this presence
        self.presence_sent_to[user_id] = set(servers.keys())
        
        # Add to seen set to avoid processing our own advertisement
        self.seen_presence.add((user_id, self.server_id, "ADVERTISE"))
        
        return success_count > 0
    
    async def remove_user(self, user_id: str, reason: str = "disconnect") -> bool:
        """
        Remove a user's presence from the network (Protocol §8.2)
        Called when a user disconnects from this server
        
        Args:
            user_id: User's UUID
            reason: Reason for removal (for logging)
        
        Returns:
            True if removal sent successfully
        """
        logger.info(f"Removing user {user_id} from network (reason: {reason})")
        
        # Check if user was actually local
        if user_locations.get(user_id) != "local":
            logger.warning(f"Cannot remove user {user_id}: not a local user")
            return False
        
        # Create USER_REMOVE message
        remove_msg = self._create_user_remove(user_id)
        
        # Broadcast to all connected servers
        success_count = await self._broadcast_to_servers(remove_msg)
        
        # Broadcast to all local users (so their UI updates)
        local_user_count = await self._broadcast_to_local_users(remove_msg, exclude_user=user_id)
        
        # Update local state
        if user_id in local_users:
            del local_users[user_id]
        if user_id in user_locations:
            del user_locations[user_id]
        
        logger.info(f"Removed user {user_id}, notified {success_count} servers and {local_user_count} local users")
        
        # Clean up tracking
        if user_id in self.presence_sent_to:
            del self.presence_sent_to[user_id]
        
        # Add to seen set
        self.seen_presence.add((user_id, self.server_id, "REMOVE"))
        
        return success_count > 0
    
    def _create_user_advertise(self, user_id: str, user_meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create USER_ADVERTISE message (Protocol §8.2)
        
        Message format:
        {
            "type": "USER_ADVERTISE",
            "from": "server_id",
            "to": "*",
            "ts": timestamp,
            "payload": {
                "user_id": "user_uuid",
                "server_id": "server_uuid",
                "meta": {...}
            },
            "sig": "..."
        }
        """
        payload = {
            "user_id": user_id,
            "server_id": self.server_id,
            "meta": user_meta
        }
        
        msg = {
            "type": "USER_ADVERTISE",
            "from": self.server_id,
            "to": "*",  # Broadcast to all servers
            "ts": now_ms(),
            "payload": payload
        }
        
        # Sign the payload (Protocol §8.2 - verify sig using from server's public key)
        msg["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        
        return msg
    
    def _create_user_remove(self, user_id: str) -> Dict[str, Any]:
        """
        Create USER_REMOVE message (Protocol §8.2)
        
        Message format:
        {
            "type": "USER_REMOVE",
            "from": "server_id",
            "to": "*",
            "ts": timestamp,
            "payload": {
                "user_id": "user_uuid",
                "server_id": "server_uuid"
            },
            "sig": "..."
        }
        """
        payload = {
            "user_id": user_id,
            "server_id": self.server_id
        }
        
        msg = {
            "type": "USER_REMOVE",
            "from": self.server_id,
            "to": "*",  # Broadcast to all servers
            "ts": now_ms(),
            "payload": payload
        }
        
        # Sign the payload
        msg["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        
        return msg
    
    async def _broadcast_to_servers(self, message: Dict[str, Any]) -> int:
        """
        Broadcast a message to all connected servers
        Protocol §8.2 - USER_ADVERTISE/USER_REMOVE are broadcast and gossiped
        """
        success_count = 0
        dead_servers = []
        
        for server_id, link in list(servers.items()):
            try:
                # Check if connection is still alive
                if link.ws and not link.ws.closed:
                    await link.ws.send(json.dumps(message))
                    success_count += 1
                    logger.debug(f"Sent {message.get('type')} to server {server_id}")
                else:
                    # Connection closed - mark for cleanup
                    logger.warning(f"Server {server_id} connection closed during broadcast")
                    dead_servers.append(server_id)
                    
            except Exception as e:
                logger.error(f"Error broadcasting to server {server_id}: {e}")
                dead_servers.append(server_id)
        
        # Remove dead servers from routing tables (Protocol §11 - connection dead handling)
        for server_id in dead_servers:
            if server_id in servers:
                del servers[server_id]
                logger.info(f"Removed dead server {server_id} from routing table")
            if server_id in server_addrs:
                del server_addrs[server_id]
        
        if dead_servers:
            logger.info(f"Broadcast {message.get('type')}: {success_count} succeeded, {len(dead_servers)} removed")
        
        return success_count
    
    async def _broadcast_to_local_users(self, message: Dict[str, Any], exclude_user: Optional[str] = None) -> int:
        """
        Broadcast a presence message to all locally connected users
        This allows real-time UI updates when users join/leave
        
        Args:
            message: The USER_ADVERTISE or USER_REMOVE message
            exclude_user: Optional user_id to exclude from broadcast (e.g., the user who just joined)
        
        Returns:
            Number of users successfully notified
        """
        success_count = 0
        dead_users = []
        
        for user_id, link in list(local_users.items()):
            # Skip the excluded user (e.g., don't send USER_ADVERTISE to the user who just joined)
            if exclude_user and user_id == exclude_user:
                continue
                
            try:
                # Check if connection is still alive
                if link.ws and not link.ws.closed:
                    await link.ws.send(json.dumps(message))
                    success_count += 1
                    logger.debug(f"Sent {message.get('type')} to local user {user_id}")
                else:
                    # Connection closed - mark for cleanup
                    logger.warning(f"User {user_id} connection closed during broadcast")
                    dead_users.append(user_id)
                    
            except Exception as e:
                logger.error(f"Error broadcasting to user {user_id}: {e}")
                dead_users.append(user_id)
        
        # Remove dead user connections
        for user_id in dead_users:
            if user_id in local_users:
                del local_users[user_id]
                logger.info(f"Removed dead user {user_id} from local_users")
            if user_id in user_locations:
                del user_locations[user_id]
        
        if success_count > 0:
            logger.debug(f"Broadcast {message.get('type')} to {success_count} local users")
        
        return success_count
    
    async def handle_user_advertise(self, env: Dict[str, Any]) -> bool:
        """
        Handle incoming USER_ADVERTISE message (Protocol §8.2)
        
        Processing rules:
        1. Verify sig using from server's public key
        2. On success, update local mapping: user_locations["user_id"] = "server_id"
        3. Forward the message to other servers (gossip)
        
        Args:
            env: The message envelope
        
        Returns:
            True if processed successfully
        """
        from_server = env["from"]
        payload = env["payload"]
        
        # Validate payload
        if not all(k in payload for k in ["user_id", "server_id"]):
            logger.error(f"USER_ADVERTISE missing required fields from {from_server}")
            return False
        
        user_id = payload["user_id"]
        server_id = payload["server_id"]
        user_meta = payload.get("meta", {})
        
        # Check if we've already seen this advertisement (loop prevention)
        presence_key = (user_id, server_id, "ADVERTISE")
        if presence_key in self.seen_presence:
            logger.debug(f"Ignoring duplicate USER_ADVERTISE for {user_id} from {server_id}")
            return True
        
        # Verify signature (Protocol §8.2 - verify sig) (FIXED TODO #239)
        server_pubkey_b64 = get_server_key(self.db, from_server)
        
        if server_pubkey_b64:
            try:
                from .crypto import import_pubkey_b64url, verify_transport, canonical_json
                server_pubkey = import_pubkey_b64url(server_pubkey_b64)
                
                if not verify_transport(server_pubkey, canonical_json(payload), env.get("sig", "")):
                    logger.error(f"USER_ADVERTISE signature verification failed from server {from_server}")
                    return False
                
                logger.debug(f"USER_ADVERTISE signature verified for server {from_server}")
            except Exception as e:
                logger.error(f"Error verifying USER_ADVERTISE signature from {from_server}: {e}")
                return False
        else:
            logger.warning(
                f"No stored public key for server {from_server}, "
                f"accepting USER_ADVERTISE without verification (first contact)"
            )
        
        # Update local user location mapping (Protocol §8.2)
        old_location = user_locations.get(user_id)
        user_locations[user_id] = server_id
        
        logger.info(
            f"User {user_id} advertised by server {server_id} "
            f"(from {from_server}, was: {old_location})"
        )
        
        # Mark as seen to prevent loops
        self.seen_presence.add(presence_key)
        
        # Forward to other servers (gossip) - Protocol §8.2 step 3
        await self._forward_presence(env, from_server)
        
        # Broadcast to all local users so their UI updates
        await self._broadcast_to_local_users(env, exclude_user=None)
        
        return True
    
    async def handle_user_remove(self, env: Dict[str, Any]) -> bool:
        """
        Handle incoming USER_REMOVE message (Protocol §8.2)
        
        Processing rules:
        1. Verify sig
        2. Only remove the User if the local mapping still points to that Server:
           if user_locations.get("user_id") == "server_id":
               del user_locations["user_id"]
        3. Forward the removal to other Servers
        
        Args:
            env: The message envelope
        
        Returns:
            True if processed successfully
        """
        from_server = env["from"]
        payload = env["payload"]
        
        # Validate payload
        if "user_id" not in payload or "server_id" not in payload:
            logger.error(f"USER_REMOVE missing required fields from {from_server}")
            return False
        
        user_id = payload["user_id"]
        server_id = payload["server_id"]
        
        # Check if we've already seen this removal (loop prevention)
        presence_key = (user_id, server_id, "REMOVE")
        if presence_key in self.seen_presence:
            logger.debug(f"Ignoring duplicate USER_REMOVE for {user_id} from {server_id}")
            return True
        
        # Verify signature (Protocol §8.2 - verify sig) (FIXED TODO #297)
        server_pubkey_b64 = get_server_key(self.db, from_server)
        
        if server_pubkey_b64:
            try:
                from .crypto import import_pubkey_b64url, verify_transport, canonical_json
                server_pubkey = import_pubkey_b64url(server_pubkey_b64)
                
                if not verify_transport(server_pubkey, canonical_json(payload), env.get("sig", "")):
                    logger.error(f"USER_REMOVE signature verification failed from server {from_server}")
                    return False
                
                logger.debug(f"USER_REMOVE signature verified for server {from_server}")
            except Exception as e:
                logger.error(f"Error verifying USER_REMOVE signature from {from_server}: {e}")
                return False
        else:
            logger.warning(
                f"No stored public key for server {from_server}, "
                f"accepting USER_REMOVE without verification"
            )
        
        # Only remove if local mapping still points to that server (Protocol §8.2)
        current_location = user_locations.get(user_id)
        
        if current_location == server_id:
            del user_locations[user_id]
            logger.info(f"User {user_id} removed from network (was on {server_id})")
        elif current_location == "local":
            logger.warning(
                f"Ignoring USER_REMOVE for {user_id}: user is local, "
                f"not on {server_id}"
            )
        else:
            logger.debug(
                f"Ignoring USER_REMOVE for {user_id}: user is on {current_location}, "
                f"not on {server_id}"
            )
        
        # Mark as seen
        self.seen_presence.add(presence_key)
        
        # Forward the removal to other servers (Protocol §8.2)
        await self._forward_presence(env, from_server)
        
        # Broadcast to all local users so their UI updates
        await self._broadcast_to_local_users(env, exclude_user=None)
        
        return True
    
    async def _forward_presence(self, message: Dict[str, Any], exclude_server: str):
        """
        Forward a presence message to other servers (gossip)
        Excludes the server we received it from to prevent loops
        
        Args:
            message: The presence message to forward
            exclude_server: Server ID to exclude from forwarding
        """
        forward_count = 0
        
        for server_id, link in list(servers.items()):
            # Don't forward back to the sender
            if server_id == exclude_server:
                continue
            
            try:
                if link.ws and not link.ws.closed:
                    await link.ws.send(json.dumps(message))
                    forward_count += 1
            except Exception as e:
                logger.error(f"Error forwarding presence to server {server_id}: {e}")
        
        logger.debug(f"Forwarded {message['type']} to {forward_count} servers")
    
    def get_user_location(self, user_id: str) -> Optional[str]:
        """
        Get the location of a user (Protocol §5.2)
        
        Returns:
            "local" if user is on this server
            server_id if user is on another server
            None if user location is unknown
        """
        return user_locations.get(user_id)
    
    def is_user_online(self, user_id: str) -> bool:
        """Check if a user is online in the network"""
        return user_id in user_locations
    
    def get_all_online_users(self) -> Dict[str, str]:
        """
        Get all online users and their locations
        
        Returns:
            Dict mapping user_id -> location ("local" or server_id)
        """
        return user_locations.copy()
    
    def get_local_users(self) -> list[str]:
        """Get list of users connected to this server"""
        return [uid for uid, loc in user_locations.items() if loc == "local"]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get presence statistics"""
        return {
            "total_online_users": len(user_locations),
            "local_users": len([loc for loc in user_locations.values() if loc == "local"]),
            "remote_users": len([loc for loc in user_locations.values() if loc != "local"]),
            "tracked_presences": len(self.presence_sent_to),
            "seen_presence_messages": len(self.seen_presence)
        }


# Handler functions for presence messages

async def handle_user_advertise_message(ctx, env: Dict[str, Any]):
    """
    Handler for USER_ADVERTISE message (Protocol §8.2)
    Called by the message dispatcher when a USER_ADVERTISE message is received
    """
    logger.info(f"Received USER_ADVERTISE from {env['from']}")
    
    # Get presence manager from server
    if not hasattr(ctx.server, 'presence_manager'):
        logger.error("Server has no presence_manager")
        await ctx.send_error("INTERNAL_ERROR", "Presence manager not initialized")
        return
    
    # Process the advertisement
    success = await ctx.server.presence_manager.handle_user_advertise(env)
    
    if not success:
        logger.warning(f"Failed to process USER_ADVERTISE from {env['from']}")
        # Don't send error response for gossip messages (they're broadcast)


async def handle_user_remove_message(ctx, env: Dict[str, Any]):
    """
    Handler for USER_REMOVE message (Protocol §8.2)
    Called by the message dispatcher when a USER_ADVERTISE message is received
    """
    logger.info(f"Received USER_REMOVE from {env['from']}")
    
    # Get presence manager from server
    if not hasattr(ctx.server, 'presence_manager'):
        logger.error("Server has no presence_manager")
        await ctx.send_error("INTERNAL_ERROR", "Presence manager not initialized")
        return
    
    # Process the removal
    success = await ctx.server.presence_manager.handle_user_remove(env)
    
    if not success:
        logger.warning(f"Failed to process USER_REMOVE from {env['from']}")
        # Don't send error response for gossip messages (they're broadcast)


async def handle_user_list_request(ctx, env: Dict[str, Any]):
    """
    Handler for /list command - returns all online users
    Enhanced to use presence information
    """
    logger.info(f"User {env['from']} requested user list")
    
    # Get presence manager from server
    if not hasattr(ctx.server, 'presence_manager'):
        logger.error("Server has no presence_manager")
        await ctx.send_error("INTERNAL_ERROR", "Presence manager not initialized")
        return
    
    # Get all online users
    online_users = ctx.server.presence_manager.get_all_online_users()
    
    # Build user list with metadata
    user_list = []
    for user_id, location in sorted(online_users.items()):
        # Get user info from database
        user_info = get_user_info(ctx.server.db, user_id)
        if user_info:
            user_list.append({
                "user_id": user_id,
                "location": location,
                "meta": user_info.get("meta", {})
            })
        else:
            # User not in our database, but is online somewhere
            user_list.append({
                "user_id": user_id,
                "location": location,
                "meta": {}
            })
    
    # Send response
    response_payload = {
        "users": user_list,
        "total_count": len(user_list)
    }
    
    response = {
        "type": "USER_LIST_RESPONSE",
        "from": ctx.server.server_id,
        "to": env["from"],
        "ts": ctx.server.now_ms(),
        "payload": response_payload
    }
    
    # Sign with server key (FIXED TODO #477)
    if hasattr(ctx.server, 'priv_key') and ctx.server.priv_key:
        from .crypto import sign_transport, canonical_json
        response["sig"] = sign_transport(ctx.server.priv_key, canonical_json(response_payload))
    else:
        response["sig"] = ""
    
    await ctx.send(response)
    logger.info(f"Sent user list with {len(user_list)} users to {env['from']}")
