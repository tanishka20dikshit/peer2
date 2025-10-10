"""
Message Routing & Delivery Implementation (Phase 3D)
Handles message routing between servers and loop suppression.
Protocol §8.3, §10
"""

from __future__ import annotations
import asyncio
import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from .crypto import sign_transport, verify_transport, canonical_json, import_pubkey_b64url
from .routing import local_users, user_locations, servers, server_addrs, seen_ids
from .protocol import now_ms

logger = logging.getLogger(__name__)

class MessageRouter:
    """Handles message routing and delivery across the network"""
    
    def __init__(self, server_id: str, priv_key, pub_key):
        self.server_id = server_id
        self.priv_key = priv_key
        self.pub_key = pub_key
        
        # Statistics
        self.messages_routed = 0
        self.messages_delivered = 0
        self.messages_dropped = 0
        
        logger.info(f"MessageRouter initialized for server {server_id}")
    
    async def route_message(self, from_user: str, to_user: str, 
                           message_payload: Dict[str, Any], original_ts: int = None) -> Tuple[bool, Optional[str]]:
        """
        Route a message from one user to another (Protocol §10)
        
        Args:
            from_user: Sender's user ID
            to_user: Recipient's user ID
            message_payload: The message payload containing ciphertext, signatures, etc.
            original_ts: Original timestamp from MSG_DIRECT (for content signature verification)
        
        Returns:
            (success, error_message)
        """
        logger.debug(f"Routing message from {from_user} to {to_user}")
        
        # Determine target location (Protocol §10)
        route_result = self._route_to_user(to_user)
        
        if route_result is None:
            # User not found
            logger.warning(f"User {to_user} not found in network")
            self.messages_dropped += 1
            return False, "USER_NOT_FOUND"
        
        route_type, target = route_result
        
        if route_type == "local":
            # User is on this server - deliver directly
            success = await self._deliver_local(to_user, from_user, message_payload, original_ts)
            if success:
                self.messages_delivered += 1
                logger.info(f"Message delivered locally to {to_user}")
                return True, None
            else:
                self.messages_dropped += 1
                return False, "DELIVERY_FAILED"
        
        elif route_type == "server":
            # User is on another server - forward via SERVER_DELIVER
            success = await self._forward_to_server(target, to_user, from_user, message_payload)
            if success:
                self.messages_routed += 1
                logger.info(f"Message forwarded to server {target} for user {to_user}")
                return True, None
            else:
                self.messages_dropped += 1
                return False, "FORWARD_FAILED"
        
        else:
            logger.error(f"Unknown route type: {route_type}")
            self.messages_dropped += 1
            return False, "INTERNAL_ERROR"
    
    def _route_to_user(self, target_user: str) -> Optional[Tuple[str, str]]:
        """
        Determine routing for a target user (Protocol §10)
        
        Returns:
            ("local", user_id) if user is local
            ("server", server_id) if user is on another server
            None if user not found
        """
        # Check if user is local
        if target_user in local_users:
            return ("local", target_user)
        
        # Check if user is on another server
        server_id = user_locations.get(target_user)
        if server_id and server_id != "local":
            return ("server", server_id)
        
        # User not found
        return None
    
    async def _deliver_local(self, to_user: str, from_user: str, 
                            message_payload: Dict[str, Any], original_ts: int = None) -> bool:
        """
        Deliver message to a local user (Protocol §9.2)
        
        Creates USER_DELIVER message and sends to the local user's connection
        """
        if to_user not in local_users:
            logger.error(f"Cannot deliver to {to_user}: not in local_users")
            return False
        
        user_link = local_users[to_user]
        
        # Create USER_DELIVER message (Protocol §9.2)
        deliver_msg = {
            "type": "USER_DELIVER",
            "from": self.server_id,
            "to": to_user,
            "ts": now_ms(),  # Transport timestamp (for envelope)
            "payload": {
                "ciphertext": message_payload.get("ciphertext", ""),
                "sender": from_user,
                "sender_pub": message_payload.get("sender_pub", ""),
                "content_sig": message_payload.get("content_sig", ""),
                "original_ts": original_ts  # Add original timestamp for signature verification
            }
        }
        
        # Sign the payload for transport integrity (Protocol §9.2)
        deliver_msg["sig"] = sign_transport(self.priv_key, canonical_json(deliver_msg["payload"]))
        
        try:
            # Send to user's WebSocket connection
            if user_link.ws and not user_link.ws.closed:
                await user_link.ws.send(json.dumps(deliver_msg))
                logger.debug(f"Sent USER_DELIVER to local user {to_user}")
                return True
            else:
                logger.error(f"User {to_user} connection is closed")
                return False
        except Exception as e:
            logger.error(f"Error delivering to local user {to_user}: {e}")
            return False
    
    async def _forward_to_server(self, target_server: str, to_user: str, 
                                 from_user: str, message_payload: Dict[str, Any]) -> bool:
        """
        Forward message to another server via SERVER_DELIVER (Protocol §8.3)
        """
        if target_server not in servers:
            logger.error(f"Target server {target_server} not in server list")
            return False
        
        server_link = servers[target_server]
        
        # Create SERVER_DELIVER message (Protocol §8.3)
        deliver_msg = {
            "type": "SERVER_DELIVER",
            "from": self.server_id,
            "to": target_server,
            "ts": now_ms(),
            "payload": {
                "user_id": to_user,
                "ciphertext": message_payload.get("ciphertext", ""),
                "sender": from_user,
                "sender_pub": message_payload.get("sender_pub", ""),
                "content_sig": message_payload.get("content_sig", "")
            }
        }
        
        # Sign the payload (Protocol §8.3)
        deliver_msg["sig"] = sign_transport(self.priv_key, canonical_json(deliver_msg["payload"]))
        
        # Check for message loops (Protocol §10)
        if self._is_duplicate_message(deliver_msg):
            logger.warning(f"Dropping duplicate message to prevent loop")
            return False
        
        try:
            # Send to server's WebSocket connection
            if server_link.ws and not server_link.ws.closed:
                await server_link.ws.send(json.dumps(deliver_msg))
                logger.debug(f"Sent SERVER_DELIVER to server {target_server}")
                
                # Add to seen messages for loop prevention
                self._mark_message_seen(deliver_msg)
                
                return True
            else:
                logger.error(f"Server {target_server} connection is closed")
                return False
        except Exception as e:
            logger.error(f"Error forwarding to server {target_server}: {e}")
            return False
    
    def _is_duplicate_message(self, message: Dict[str, Any]) -> bool:
        """
        Check if message has been seen before (Protocol §10 - loop suppression)
        
        Uses (ts, from, to, hash(payload)) as the message signature
        """
        msg_signature = self._get_message_signature(message)
        return msg_signature in seen_ids
    
    def _mark_message_seen(self, message: Dict[str, Any]):
        """Mark a message as seen for loop prevention"""
        msg_signature = self._get_message_signature(message)
        seen_ids.add(msg_signature)
        
        # Limit size of seen_ids cache (keep last 10000 messages)
        if len(seen_ids) > 10000:
            # Remove oldest entries (convert to list, remove first 1000, convert back)
            old_seen = list(seen_ids)
            seen_ids.clear()
            seen_ids.update(old_seen[1000:])
    
    def _get_message_signature(self, message: Dict[str, Any]) -> tuple:
        """
        Generate a unique signature for a message (Protocol §10)
        
        Uses: (ts, from, to, hash(payload))
        """
        payload_hash = hashlib.sha256(
            json.dumps(message.get("payload", {}), sort_keys=True).encode()
        ).hexdigest()[:16]  # First 16 chars of hash
        
        return (
            message.get("ts"),
            message.get("from"),
            message.get("to"),
            payload_hash
        )
    
    async def handle_server_deliver(self, env: Dict[str, Any]) -> bool:
        """
        Handle incoming SERVER_DELIVER message (Protocol §8.3)
        
        Routing rule (Protocol §8.3):
        - If user_locations[user_id] == "local" -> deliver to local user link
        - Otherwise, it equals server_id -> forward unchanged to server_id
        - Otherwise, drop and MAY emit an error upstream
        
        Args:
            env: The SERVER_DELIVER message envelope
        
        Returns:
            True if handled successfully
        """
        from_server = env["from"]
        payload = env["payload"]
        
        # Validate payload
        required_fields = ["user_id", "ciphertext", "sender", "sender_pub", "content_sig"]
        for field in required_fields:
            if field not in payload:
                logger.error(f"SERVER_DELIVER missing required field: {field}")
                return False
        
        user_id = payload["user_id"]
        
        # Check for message loops (Protocol §10)
        if self._is_duplicate_message(env):
            logger.warning(f"Dropping duplicate SERVER_DELIVER to prevent loop")
            return True  # Return True because we handled it (by dropping)
        
        # Mark as seen
        self._mark_message_seen(env)
        
        # Determine routing (Protocol §8.3)
        user_location = user_locations.get(user_id)
        
        if user_location == "local":
            # Deliver to local user (Protocol §8.3)
            logger.info(f"SERVER_DELIVER: Delivering to local user {user_id}")
            
            success = await self._deliver_local(
                user_id,
                payload["sender"],
                {
                    "ciphertext": payload["ciphertext"],
                    "sender_pub": payload["sender_pub"],
                    "content_sig": payload["content_sig"]
                }
            )
            
            if success:
                self.messages_delivered += 1
            else:
                self.messages_dropped += 1
                logger.error(f"Failed to deliver to local user {user_id}")
            
            return success
        
        elif user_location and user_location != "local":
            # Forward to another server (Protocol §8.3)
            logger.info(f"SERVER_DELIVER: Forwarding to server {user_location} for user {user_id}")
            
            if user_location not in servers:
                logger.error(f"Target server {user_location} not in server list")
                self.messages_dropped += 1
                return False
            
            server_link = servers[user_location]
            
            try:
                # Forward unchanged (Protocol §8.3 - "forward unchanged")
                if server_link.ws and not server_link.ws.closed:
                    await server_link.ws.send(json.dumps(env))
                    self.messages_routed += 1
                    logger.debug(f"Forwarded SERVER_DELIVER to server {user_location}")
                    return True
                else:
                    logger.error(f"Server {user_location} connection is closed")
                    self.messages_dropped += 1
                    return False
            except Exception as e:
                logger.error(f"Error forwarding SERVER_DELIVER: {e}")
                self.messages_dropped += 1
                return False
        
        else:
            # User not found - drop and emit error (Protocol §8.3, §10)
            logger.warning(f"SERVER_DELIVER: User {user_id} not found in network")
            self.messages_dropped += 1
            
            # Optionally send error back to originating server
            # For now, just log the error
            
            return False
    
    async def broadcast_to_public_channel(self, from_user: str, 
                                         message_payload: Dict[str, Any],
                                         original_ts: int = None) -> int:
        """
        Broadcast message to all users in public channel
        
        Args:
            from_user: Sender's user ID
            message_payload: Message payload with ciphertext, signatures, etc.
            original_ts: Original timestamp from sender (for signature verification)
        
        Returns:
            Number of successful deliveries
        """
        logger.info(f"Broadcasting public channel message from {from_user}")
        
        success_count = 0
        
        # Get all users in the network
        all_users = list(user_locations.keys())
        
        for user_id in all_users:
            # Don't send to sender
            if user_id == from_user:
                continue
            
            # Check if user is local
            user_location = user_locations.get(user_id)
            
            if user_location == "local":
                # Send MSG_PUBLIC_CHANNEL directly to local users (not wrapped in USER_DELIVER)
                success = await self._deliver_public_channel_local(
                    user_id, from_user, message_payload, original_ts
                )
                if success:
                    success_count += 1
            else:
                # For remote users, route through servers
                success, _ = await self.route_message(from_user, user_id, message_payload)
                if success:
                    success_count += 1
        
        logger.info(f"Broadcast delivered to {success_count}/{len(all_users)-1} users")
        return success_count
    
    async def _deliver_public_channel_local(self, to_user: str, from_user: str, 
                                           message_payload: Dict[str, Any],
                                           original_ts: int = None) -> bool:
        """
        Deliver public channel message to a local user
        
        Sends MSG_PUBLIC_CHANNEL directly (not wrapped in USER_DELIVER)
        """
        if to_user not in local_users:
            logger.error(f"Cannot deliver to {to_user}: not in local_users")
            return False
        
        user_link = local_users[to_user]
        
        # Create MSG_PUBLIC_CHANNEL message
        deliver_msg = {
            "type": "MSG_PUBLIC_CHANNEL",
            "from": from_user,
            "to": "public",
            "ts": original_ts or now_ms(),  # Use original timestamp for signature verification
            "payload": {
                "ciphertext": message_payload.get("ciphertext", ""),
                "sender_pub": message_payload.get("sender_pub", ""),
                "content_sig": message_payload.get("content_sig", "")
            },
            "sig": ""  # Could add server signature if needed
        }
        
        try:
            # Send to user's WebSocket connection
            if user_link.ws and not user_link.ws.closed:
                await user_link.ws.send(json.dumps(deliver_msg))
                logger.debug(f"Sent MSG_PUBLIC_CHANNEL to local user {to_user}")
                return True
            else:
                logger.error(f"User {to_user} connection is closed")
                return False
        except Exception as e:
            logger.error(f"Error delivering public channel message to {to_user}: {e}")
            return False
    
    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing statistics"""
        return {
            "messages_routed": self.messages_routed,
            "messages_delivered": self.messages_delivered,
            "messages_dropped": self.messages_dropped,
            "seen_messages_cache_size": len(seen_ids),
            "total_online_users": len(user_locations),
            "local_users": len(local_users),
            "connected_servers": len(servers)
        }


# Handler functions for message routing

async def handle_msg_direct(ctx, env: Dict[str, Any]):
    """
    Handle MSG_DIRECT message from a user (Protocol §9.2)
    Routes the message to the recipient
    """
    from_user = env["from"]
    to_user = env["to"]
    payload = env["payload"]
    original_ts = env["ts"]  # Preserve original timestamp
    
    logger.info(f"Received MSG_DIRECT from {from_user} to {to_user}")
    
    # Validate payload
    required_fields = ["ciphertext", "sender_pub", "content_sig"]
    for field in required_fields:
        if field not in payload:
            logger.error(f"MSG_DIRECT missing required field: {field}")
            await ctx.send_error("BAD_PAYLOAD", f"Missing field: {field}")
            return
    
    # Get message router from server
    if not hasattr(ctx.server, 'message_router'):
        logger.error("Server has no message_router")
        await ctx.send_error("INTERNAL_ERROR", "Message router not initialized")
        return
    
    # Route the message
    success, error = await ctx.server.message_router.route_message(
        from_user,
        to_user,
        payload,
        original_ts  # Pass original timestamp
    )
    
    if not success:
        logger.warning(f"Failed to route message from {from_user} to {to_user}: {error}")
        await ctx.send_error(error or "ROUTING_FAILED", "Failed to route message")
        return
    
    # Optionally send ACK to sender
    # ack_msg = {
    #     "type": "ACK",
    #     "from": ctx.server.server_id,
    #     "to": from_user,
    #     "ts": ctx.server.now_ms(),
    #     "payload": {"msg_ref": env.get("ts")},
    #     "sig": "..."
    # }
    # await ctx.send(ack_msg)
    
    logger.info(f"Message from {from_user} to {to_user} routed successfully")


async def handle_server_deliver(ctx, env: Dict[str, Any]):
    """
    Handle SERVER_DELIVER message from another server (Protocol §8.3)
    """
    logger.info(f"Received SERVER_DELIVER from {env['from']}")
    
    # Get message router from server
    if not hasattr(ctx.server, 'message_router'):
        logger.error("Server has no message_router")
        return
    
    # Handle the delivery
    success = await ctx.server.message_router.handle_server_deliver(env)
    
    if not success:
        logger.warning(f"Failed to handle SERVER_DELIVER from {env['from']}")


async def handle_msg_public_channel(ctx, env: Dict[str, Any]):
    """
    Handle MSG_PUBLIC_CHANNEL message (Protocol §9.3)
    Broadcasts to all users in the network
    """
    from_user = env["from"]
    payload = env["payload"]
    original_ts = env["ts"]  # Preserve original timestamp for signature verification
    
    logger.info(f"Received MSG_PUBLIC_CHANNEL from {from_user}")
    
    # Validate payload
    required_fields = ["ciphertext", "sender_pub", "content_sig"]
    for field in required_fields:
        if field not in payload:
            logger.error(f"MSG_PUBLIC_CHANNEL missing required field: {field}")
            await ctx.send_error("BAD_PAYLOAD", f"Missing field: {field}")
            return
    
    # Get message router from server
    if not hasattr(ctx.server, 'message_router'):
        logger.error("Server has no message_router")
        await ctx.send_error("INTERNAL_ERROR", "Message router not initialized")
        return
    
    # Broadcast to all users in public channel
    delivered_count = await ctx.server.message_router.broadcast_to_public_channel(
        from_user,
        payload,
        original_ts  # Pass original timestamp
    )
    
    logger.info(f"Public channel message from {from_user} delivered to {delivered_count} users")
