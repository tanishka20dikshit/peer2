"""
Public Channel Management - Protocol §9.3
Handles public channel join, key distribution, and messaging
"""

from __future__ import annotations
import asyncio
import json
import time
import secrets
import logging
from typing import Dict, Any, List, Optional
from .routing import servers, server_addrs, local_users, user_locations
from .crypto import rsa_oaep_encrypt, import_pubkey_b64url, sign_content_key_share, canonical_json
from .db import get_user_info
from .groups import (
    get_public_channel_info,
    add_user_to_public_channel,
    get_public_channel_members as get_pc_members_detailed
)

logger = logging.getLogger(__name__)

# Global public channel key (256-bit symmetric key for group encryption)
# In a real implementation, this would be stored securely
_public_channel_key = None

def get_or_create_public_channel_key() -> bytes:
    """
    Get or create the public channel symmetric key.
    In production, this should be stored securely and rotated periodically.
    """
    global _public_channel_key
    if _public_channel_key is None:
        _public_channel_key = secrets.token_bytes(32)  # 256-bit key
    return _public_channel_key


class PublicChannelManager:
    """Manages public channel operations per Protocol §9.3"""
    
    def __init__(self, server_id: str, priv_key, pub_key, db_connection):
        self.server_id = server_id
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.db = db_connection
        self.channel_version = 1
    
    async def add_user_to_channel(self, user_id: str, user_pubkey_b64: str) -> bool:
        """
        Add user to public channel and broadcast (Protocol §9.3)
        
        Steps per protocol:
        1. Add user to local database
        2. Broadcast PUBLIC_CHANNEL_ADD
        3. Wrap channel key for new user
        4. Broadcast PUBLIC_CHANNEL_UPDATED with new version
        5. Send PUBLIC_CHANNEL_KEY_SHARE to new user
        
        Args:
            user_id: User ID to add
            user_pubkey_b64: User's public key in base64url
        
        Returns:
            bool: Success status
        """
        logger.info(f"[PublicChannel] ========== ADD USER TO CHANNEL START ==========")
        logger.info(f"[PublicChannel] User ID: {user_id}")
        logger.info(f"[PublicChannel] Pubkey length: {len(user_pubkey_b64)}")
        
        try:
            # Get public channel key
            logger.info(f"[PublicChannel] Step 1: Getting channel key...")
            channel_key = get_or_create_public_channel_key()
            logger.info(f"[PublicChannel] ✅ Channel key obtained")
            
            # Wrap the channel key with user's public key
            logger.info(f"[PublicChannel] Step 2: Wrapping channel key...")
            user_pubkey = import_pubkey_b64url(user_pubkey_b64)
            wrapped_key = rsa_oaep_encrypt(user_pubkey, channel_key)
            logger.info(f"[PublicChannel] ✅ Channel key wrapped (wrapped_key length: {len(wrapped_key)})")
            
            # Add to database
            logger.info(f"[PublicChannel] Step 3: Adding to database...")
            db_result = add_user_to_public_channel(self.db, user_id, wrapped_key)
            logger.info(f"[PublicChannel] ✅ Database result: {db_result}")
            
            # Increment version
            self.channel_version += 1
            logger.info(f"[PublicChannel] Channel version: {self.channel_version}")
            
            # Step 1: Broadcast PUBLIC_CHANNEL_ADD (Protocol §9.3)
            logger.info(f"[PublicChannel] Step 4: Broadcasting PUBLIC_CHANNEL_ADD...")
            await self.broadcast_channel_add(user_id)
            logger.info(f"[PublicChannel] ✅ PUBLIC_CHANNEL_ADD broadcast complete")
            
            # Step 2: Broadcast PUBLIC_CHANNEL_UPDATED with new wraps (Protocol §9.3)
            logger.info(f"[PublicChannel] Step 5: Broadcasting PUBLIC_CHANNEL_UPDATED...")
            await self.broadcast_channel_updated()
            logger.info(f"[PublicChannel] ✅ PUBLIC_CHANNEL_UPDATED broadcast complete")
            
            # Step 3: Send KEY_SHARE to new user (Protocol §9.3)
            logger.info(f"[PublicChannel] Step 6: Calling send_key_share_to_user...")
            await self.send_key_share_to_user(user_id, wrapped_key, user_pubkey_b64)
            logger.info(f"[PublicChannel] ✅ send_key_share_to_user completed")
            
            logger.info(f"[PublicChannel] ========== ADD USER TO CHANNEL SUCCESS ==========")
            return True
            
        except Exception as e:
            logger.error(f"[PublicChannel] ❌❌❌ EXCEPTION in add_user_to_channel:")
            logger.error(f"[PublicChannel] Exception type: {type(e).__name__}")
            logger.error(f"[PublicChannel] Exception message: {e}")
            import traceback
            logger.error(f"[PublicChannel] Traceback:\n{traceback.format_exc()}")
            return False
    
    async def broadcast_channel_add(self, user_id: str):
        """
        Broadcast PUBLIC_CHANNEL_ADD to all servers (Protocol §9.3)
        
        Message format per §9.3:
        {
            "type": "PUBLIC_CHANNEL_ADD",
            "from": "server_id",
            "to": "*",
            "ts": timestamp,
            "payload": {"add": ["user_id"], "if_version": current_version},
            "sig": "..."
        }
        """
        payload = {
            "add": [user_id],
            "if_version": self.channel_version - 1  # Version before adding
        }
        
        message = {
            "type": "PUBLIC_CHANNEL_ADD",
            "from": self.server_id,
            "to": "*",  # Broadcast to all servers
            "ts": int(time.time() * 1000),
            "payload": payload
        }
        
        # Sign with server private key (FIXED TODO #122)
        if hasattr(self, 'priv_key') and self.priv_key:
            from .crypto import sign_transport, canonical_json
            message["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        else:
            message["sig"] = ""
        
        # Broadcast to all connected servers
        await self._broadcast_to_servers(message)
        logger.debug(f"Broadcasted PUBLIC_CHANNEL_ADD for {user_id}")
    
    async def broadcast_channel_updated(self):
        """
        Broadcast PUBLIC_CHANNEL_UPDATED to all servers (Protocol §9.3)
        
        Message format per §9.3:
        {
            "type": "PUBLIC_CHANNEL_UPDATED",
            "from": "server_id",
            "to": "*",
            "ts": timestamp,
            "payload": {
                "version": new_version,
                "wraps": [{"member_id": "id", "wrapped_key": "..."}, ...]
            },
            "sig": "..."
        }
        """
        # Get all members with their wrapped keys
        members = get_pc_members_detailed(self.db)
        
        wraps = []
        for member in members:
            wraps.append({
                "member_id": member["member_id"],
                "wrapped_key": member["wrapped_key"]
            })
        
        payload = {
            "version": self.channel_version,
            "wraps": wraps
        }
        
        message = {
            "type": "PUBLIC_CHANNEL_UPDATED",
            "from": self.server_id,
            "to": "*",  # Broadcast to all servers
            "ts": int(time.time() * 1000),
            "payload": payload
        }
        
        # Sign with server private key (FIXED TODO #165)
        if hasattr(self, 'priv_key') and self.priv_key:
            from .crypto import sign_transport, canonical_json
            message["sig"] = sign_transport(self.priv_key, canonical_json(payload))
        else:
            message["sig"] = ""
        
        # Broadcast to all connected servers
        await self._broadcast_to_servers(message)
        logger.debug(f"Broadcasted PUBLIC_CHANNEL_UPDATED (version: {self.channel_version})")
    
    async def send_key_share_to_user(self, user_id: str, wrapped_key: str, user_pubkey: str):
        """
        Send PUBLIC_CHANNEL_KEY_SHARE to specific user (Protocol §9.3)
        
        For single-server setup: Send directly to local user
        For multi-server: Broadcast to all servers (they route to user)
        """
        from .crypto import export_pubkey_b64url
        from .handlers import local_users  # Import local users dict
        
        server_pub_b64 = export_pubkey_b64url(self.pub_key)
        
        shares = [{
            "member": user_id,
            "wrapped_public_channel_key": wrapped_key
        }]
        
        # Create content signature per Protocol §12: SHA256(shares || creator_pub)
        content_sig = sign_content_key_share(self.priv_key, shares, server_pub_b64)

        payload = {
            "shares": shares,
            "creator_pub": server_pub_b64,
            "content_sig": content_sig
        }
        
        # Build complete message envelope
        message = {
            "type": "PUBLIC_CHANNEL_KEY_DELIVERY",  # ← CHANGE: Use KEY_DELIVERY for direct send
            "from": self.server_id,
            "to": user_id,  # ← CHANGE: Direct to user, not broadcast
            "ts": int(time.time() * 1000),
            "payload": payload,
            "sig": ""
        }
        
        logger.info(f"[PublicChannel] Sending PUBLIC_CHANNEL_KEY_DELIVERY to user {user_id}")
        logger.debug(f"[PublicChannel] Message: {message}")
        
        # Check if user is local
        if user_id in local_users:
            # Send directly to local user
            user_link = local_users[user_id]
            if user_link.ws and not user_link.ws.closed:
                message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
                await user_link.ws.send(message_json)
                logger.info(f"✅ Sent PUBLIC_CHANNEL_KEY_DELIVERY directly to local user {user_id}")
            else:
                logger.error(f"❌ User {user_id} WebSocket is closed")
        else:
            # For multi-server: broadcast to servers for routing
            logger.debug(f"User {user_id} not local, broadcasting to servers")
            await self._broadcast_to_servers(message)
        
        logger.debug(f"Completed PUBLIC_CHANNEL_KEY_DELIVERY to {user_id}")
    
    async def _broadcast_to_servers(self, message: Dict[str, Any]):
        """
        Broadcast message to all connected servers
        Protocol §9.3 - PUBLIC_CHANNEL_* messages are broadcast to all servers
        """
        message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
        
        success_count = 0
        dead_servers = []
        
        # Send to all connected servers
        # Use list() to allow modification of servers dict during iteration
        for server_id, server_link in list(servers.items()):
            try:
                # Check if WebSocket connection is still open
                if server_link.ws and not server_link.ws.closed:
                    await server_link.ws.send(message_json)
                    logger.debug(f"Sent {message.get('type', 'message')} to server {server_id}")
                    success_count += 1
                else:
                    # Connection is closed - mark for cleanup
                    logger.warning(f"Server {server_id} connection is closed, skipping broadcast")
                    dead_servers.append(server_id)
                    
            except Exception as e:
                # Send failed - mark server as dead
                logger.error(f"Failed to send {message.get('type', 'message')} to server {server_id}: {e}")
                dead_servers.append(server_id)
        
        # Clean up dead servers from routing tables
        # This prevents accumulation of stale connections
        for server_id in dead_servers:
            if server_id in servers:
                del servers[server_id]
                logger.info(f"Removed dead server {server_id} from routing table")
            if server_id in server_addrs:
                del server_addrs[server_id]
        
        if success_count > 0:
            logger.info(f"Broadcast {message.get('type', 'message')}: {success_count} servers, {len(dead_servers)} failed")
        elif not servers and len(dead_servers) == 0:
            # No servers in network - this is OK for single-server scenario
            logger.debug(f"No remote servers connected, {message.get('type', 'message')} not broadcasted")
        
        return success_count

# Handler functions for public channel protocol messages

async def handle_public_channel_add(ctx, env: Dict[str, Any]):
    """
    Handle PUBLIC_CHANNEL_ADD message from another server (Protocol §9.3)
    """
    payload = env["payload"]
    from_server = env["from"]
    
    logger.info(f"Received PUBLIC_CHANNEL_ADD from {from_server}")
    
    # Extract users to add
    users_to_add = payload.get("add", [])
    if_version = payload.get("if_version")
    
    # Validate and process
    for user_id in users_to_add:
        logger.info(f"Remote server adding {user_id} to public channel")
        # Update our local tracking of public channel members
        # The actual membership is managed by the source server


async def handle_public_channel_updated(ctx, env: Dict[str, Any]):
    """
    Handle PUBLIC_CHANNEL_UPDATED message from another server (Protocol §9.3)
    """
    payload = env["payload"]
    from_server = env["from"]
    
    logger.info(f"Received PUBLIC_CHANNEL_UPDATED from {from_server}")
    
    version = payload.get("version")
    wraps = payload.get("wraps", [])
    
    logger.info(f"Public channel updated to version {version} with {len(wraps)} members")
    
    # Store or update our knowledge of the public channel state
    # This helps with routing messages to the right servers


async def handle_public_channel_key_share(ctx, env: Dict[str, Any]):
    """
    Handle PUBLIC_CHANNEL_KEY_SHARE message (Protocol §9.3)
    Routes key shares to appropriate users
    """
    payload = env["payload"]
    from_server = env["from"]
    
    logger.info(f"Received PUBLIC_CHANNEL_KEY_SHARE from {from_server}")
    
    shares = payload.get("shares", [])
    creator_pub = payload.get("creator_pub")
    content_sig = payload.get("content_sig")
    
    # Verify content_sig per Protocol §12 (FIXED TODO #295)
    if content_sig and creator_pub:
        try:
            from .crypto import verify_content_key_share, import_pubkey_b64url
            creator_pubkey = import_pubkey_b64url(creator_pub)
            
            if not verify_content_key_share(creator_pubkey, shares, creator_pub, content_sig):
                logger.error(f"PUBLIC_CHANNEL_KEY_SHARE content_sig verification failed from {from_server}")
                return
            
            logger.debug(f"PUBLIC_CHANNEL_KEY_SHARE content_sig verified from {from_server}")
        except Exception as e:
            logger.error(f"Error verifying PUBLIC_CHANNEL_KEY_SHARE content_sig: {e}")
            return
    else:
        logger.warning(f"PUBLIC_CHANNEL_KEY_SHARE missing content_sig or creator_pub from {from_server}")
    
    # Route each share to the appropriate user
    for share in shares:
        member_id = share.get("member")
        wrapped_key = share.get("wrapped_public_channel_key")
        
        # If user is local, deliver directly
        if member_id in local_users:
            delivery_msg = {
                "type": "PUBLIC_CHANNEL_KEY_DELIVERY",
                "from": from_server,
                "to": member_id,
                "ts": int(time.time() * 1000),
                "payload": {
                    "wrapped_key": wrapped_key,
                    "creator_pub": creator_pub
                },
                "sig": ""
            }
            
            try:
                link = local_users[member_id]
                await link.ws.send(json.dumps(delivery_msg))
                logger.info(f"Delivered public channel key to local user {member_id}")
            except Exception as e:
                logger.error(f"Failed to deliver key to {member_id}: {e}")
        else:
            # Forward to appropriate server
            logger.debug(f"User {member_id} not local, would forward to their server")


# Export functions
__all__ = [
    'PublicChannelManager',
    'handle_public_channel_add',
    'handle_public_channel_updated',
    'handle_public_channel_key_share',
]
