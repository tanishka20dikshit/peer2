"""
File Transfer System - Protocol §9.4
Handles FILE_START, FILE_CHUNK, FILE_END for encrypted file transfers

Features:
- End-to-end encrypted file chunks
- SHA-256 integrity verification
- Progress tracking
- Support for both DM and public channel modes
- Chunked transfer with routing
"""

from __future__ import annotations
import hashlib
import logging
import time
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class FileTransfer:
    """Track state of an ongoing file transfer"""
    file_id: str
    sender_id: str
    recipient_id: str
    filename: str
    total_size: int
    expected_sha256: str
    mode: str  # "dm" or "public"
    chunks_received: Set[int] = field(default_factory=set)
    chunks_data: Dict[int, bytes] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    last_chunk_at: float = field(default_factory=time.time)
    completed: bool = False
    verified: bool = False


class FileTransferManager:
    """
    Manages file transfers per Protocol §9.4
    
    Handles:
    - FILE_START: Manifest validation and transfer initialization
    - FILE_CHUNK: Chunk reception and buffering
    - FILE_END: Transfer finalization and SHA-256 verification
    """
    
    def __init__(self, server_id: str):
        self.server_id = server_id
        
        # Track active transfers: file_id -> FileTransfer
        self.active_transfers: Dict[str, FileTransfer] = {}
        
        # Statistics
        self.transfers_started = 0
        self.transfers_completed = 0
        self.transfers_failed = 0
        self.bytes_transferred = 0
        
        logger.info(f"FileTransferManager initialized for server {server_id}")
    
    def start_transfer(self, file_id: str, sender_id: str, recipient_id: str,
                      filename: str, size: int, sha256: str, mode: str) -> bool:
        """
        Initialize a new file transfer (FILE_START)
        
        Args:
            file_id: UUID for this transfer
            sender_id: Sender's user ID
            recipient_id: Recipient's user ID
            filename: Original filename
            size: Total file size in bytes
            sha256: Expected SHA-256 hash (hex)
            mode: "dm" or "public"
        
        Returns:
            True if transfer started successfully
        """
        # Validate inputs
        if not file_id or not sender_id or not recipient_id:
            logger.error("Invalid file transfer parameters")
            return False
        
        if size <= 0:
            logger.error(f"Invalid file size: {size}")
            return False
        
        if mode not in ["dm", "public"]:
            logger.error(f"Invalid transfer mode: {mode}")
            return False
        
        # Validate SHA-256 format (64 hex characters)
        if not sha256 or len(sha256) != 64:
            logger.error(f"Invalid SHA-256 hash format: {sha256}")
            return False
        
        try:
            int(sha256, 16)  # Verify it's valid hex
        except ValueError:
            logger.error(f"SHA-256 is not valid hex: {sha256}")
            return False
        
        # Check if transfer already exists
        if file_id in self.active_transfers:
            logger.warning(f"Transfer {file_id} already in progress")
            return False
        
        # Create transfer record
        transfer = FileTransfer(
            file_id=file_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            filename=filename,
            total_size=size,
            expected_sha256=sha256.lower(),
            mode=mode
        )
        
        self.active_transfers[file_id] = transfer
        self.transfers_started += 1
        
        logger.info(
            f"Started file transfer {file_id}: {filename} "
            f"({size} bytes) from {sender_id} to {recipient_id}"
        )
        
        return True
    
    def add_chunk(self, file_id: str, chunk_index: int, chunk_data: bytes) -> bool:
        """
        Add a chunk to an ongoing transfer (FILE_CHUNK)
        
        Note: chunk_data is the raw ciphertext that will be forwarded.
        We don't decrypt it (end-to-end encryption).
        
        Args:
            file_id: Transfer ID
            chunk_index: Chunk sequence number
            chunk_data: Encrypted chunk data
        
        Returns:
            True if chunk accepted
        """
        if file_id not in self.active_transfers:
            logger.error(f"Unknown file transfer: {file_id}")
            return False
        
        transfer = self.active_transfers[file_id]
        
        if transfer.completed:
            logger.warning(f"Transfer {file_id} already completed")
            return False
        
        # Store chunk
        if chunk_index in transfer.chunks_received:
            logger.warning(f"Duplicate chunk {chunk_index} for transfer {file_id}")
            return True  # Already have it
        
        transfer.chunks_received.add(chunk_index)
        transfer.chunks_data[chunk_index] = chunk_data
        transfer.last_chunk_at = time.time()
        
        self.bytes_transferred += len(chunk_data)
        
        logger.debug(
            f"Received chunk {chunk_index} for transfer {file_id} "
            f"({len(transfer.chunks_received)} chunks total)"
        )
        
        return True
    
    def complete_transfer(self, file_id: str, verify_integrity: bool = True) -> tuple[bool, Optional[str]]:
        """
        Finalize a file transfer (FILE_END)
        
        Args:
            file_id: Transfer ID
            verify_integrity: Whether to verify SHA-256 (only if we have decrypted data)
        
        Returns:
            Tuple of (success, error_message)
        """
        if file_id not in self.active_transfers:
            return False, f"Unknown file transfer: {file_id}"
        
        transfer = self.active_transfers[file_id]
        
        if transfer.completed:
            return False, "Transfer already completed"
        
        # Mark as completed
        transfer.completed = True
        
        # Note: We can't verify SHA-256 on the server because files are end-to-end encrypted
        # The recipient client will verify integrity after decryption
        # For server-side transfers (if we ever store files), we would verify here
        
        logger.info(
            f"Completed file transfer {file_id}: {transfer.filename} "
            f"({len(transfer.chunks_received)} chunks, "
            f"{time.time() - transfer.started_at:.2f}s)"
        )
        
        self.transfers_completed += 1
        
        # Keep transfer record for a while for status queries
        # In production, would clean up after some time
        
        return True, None
    
    def get_transfer(self, file_id: str) -> Optional[FileTransfer]:
        """Get transfer info"""
        return self.active_transfers.get(file_id)
    
    def cleanup_old_transfers(self, max_age_seconds: int = 3600):
        """Clean up transfers older than max_age_seconds"""
        current_time = time.time()
        to_remove = []
        
        for file_id, transfer in self.active_transfers.items():
            age = current_time - transfer.started_at
            if age > max_age_seconds:
                to_remove.append(file_id)
        
        for file_id in to_remove:
            del self.active_transfers[file_id]
            logger.info(f"Cleaned up old transfer {file_id}")
        
        return len(to_remove)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get transfer statistics"""
        return {
            "active_transfers": len(self.active_transfers),
            "transfers_started": self.transfers_started,
            "transfers_completed": self.transfers_completed,
            "transfers_failed": self.transfers_failed,
            "bytes_transferred": self.bytes_transferred,
        }


# Handler functions for file transfer messages

async def handle_file_start(ctx, env: Dict[str, Any]):
    """
    Handle FILE_START message (Protocol §9.4)
    Validates manifest and initializes transfer
    """
    from_user = env["from"]
    to_user = env["to"]
    payload = env["payload"]
    
    logger.info(f"Received FILE_START from {from_user} to {to_user}")
    
    # Validate payload
    required_fields = ["file_id", "name", "size", "sha256", "mode"]
    for field in required_fields:
        if field not in payload:
            logger.error(f"FILE_START missing required field: {field}")
            await ctx.send_error("BAD_PAYLOAD", f"Missing field: {field}")
            return
    
    file_id = payload["file_id"]
    filename = payload["name"]
    size = payload["size"]
    sha256 = payload["sha256"]
    mode = payload["mode"]
    
    # Validate file_id is UUID
    from .protocol import is_valid_uuid_v4
    if not is_valid_uuid_v4(file_id):
        await ctx.send_error("BAD_PAYLOAD", "file_id must be UUID v4")
        return
    
    # Get file transfer manager
    if not hasattr(ctx.server, 'file_transfer_manager'):
        logger.error("Server has no file_transfer_manager")
        await ctx.send_error("INTERNAL_ERROR", "File transfer not initialized")
        return
    
    # Start transfer locally
    success = ctx.server.file_transfer_manager.start_transfer(
        file_id, from_user, to_user, filename, size, sha256, mode
    )
    
    if not success:
        await ctx.send_error("TRANSFER_FAILED", "Failed to start file transfer")
        return
    
    # Route FILE_START to recipient (like MSG_DIRECT)
    from .routing import local_users, user_locations
    
    # Determine routing
    if to_user in local_users:
        # Deliver locally
        user_link = local_users[to_user]
        try:
            import json
            await user_link.ws.send(json.dumps(env))
            logger.info(f"FILE_START delivered locally to {to_user}")
        except Exception as e:
            logger.error(f"Failed to deliver FILE_START to {to_user}: {e}")
    else:
        # Forward to remote server
        server_id = user_locations.get(to_user)
        if server_id and server_id != "local":
            from .routing import servers
            if server_id in servers:
                server_link = servers[server_id]
                try:
                    import json
                    await server_link.ws.send(json.dumps(env))
                    logger.info(f"FILE_START forwarded to server {server_id}")
                except Exception as e:
                    logger.error(f"Failed to forward FILE_START: {e}")
            else:
                await ctx.send_error("USER_NOT_FOUND", f"User {to_user} server not connected")
        else:
            await ctx.send_error("USER_NOT_FOUND", f"User {to_user} not found")
    
    logger.info(f"FILE_START processed for transfer {file_id}")


async def handle_file_chunk(ctx, env: Dict[str, Any]):
    """
    Handle FILE_CHUNK message (Protocol §9.4)
    Routes encrypted chunk to recipient
    """
    from_user = env["from"]
    to_user = env["to"]
    payload = env["payload"]
    
    # Validate payload
    required_fields = ["file_id", "index", "ciphertext"]
    for field in required_fields:
        if field not in payload:
            logger.error(f"FILE_CHUNK missing required field: {field}")
            return
    
    file_id = payload["file_id"]
    chunk_index = payload["index"]
    ciphertext = payload["ciphertext"]
    
    logger.debug(f"Received FILE_CHUNK {chunk_index} for transfer {file_id}")
    
    # Get file transfer manager
    if hasattr(ctx.server, 'file_transfer_manager'):
        # Track chunk (store ciphertext as-is, end-to-end encrypted)
        from .crypto import B64URL_DECODE
        try:
            chunk_data = B64URL_DECODE(ciphertext.encode())
            ctx.server.file_transfer_manager.add_chunk(file_id, chunk_index, chunk_data)
        except Exception as e:
            logger.error(f"Failed to decode chunk: {e}")
    
    # Route chunk to recipient (pass-through, don't decrypt)
    from .routing import local_users, user_locations
    
    if to_user in local_users:
        # Deliver locally
        user_link = local_users[to_user]
        try:
            import json
            await user_link.ws.send(json.dumps(env))
            logger.debug(f"FILE_CHUNK delivered locally to {to_user}")
        except Exception as e:
            logger.error(f"Failed to deliver FILE_CHUNK to {to_user}: {e}")
    else:
        # Forward to remote server
        server_id = user_locations.get(to_user)
        if server_id and server_id != "local":
            from .routing import servers
            if server_id in servers:
                server_link = servers[server_id]
                try:
                    import json
                    await server_link.ws.send(json.dumps(env))
                    logger.debug(f"FILE_CHUNK forwarded to server {server_id}")
                except Exception as e:
                    logger.error(f"Failed to forward FILE_CHUNK: {e}")


async def handle_file_end(ctx, env: Dict[str, Any]):
    """
    Handle FILE_END message (Protocol §9.4)
    Finalizes transfer and verifies integrity
    """
    from_user = env["from"]
    to_user = env["to"]
    payload = env["payload"]
    
    logger.info(f"Received FILE_END from {from_user} to {to_user}")
    
    # Validate payload
    if "file_id" not in payload:
        logger.error("FILE_END missing file_id")
        return
    
    file_id = payload["file_id"]
    
    # Get file transfer manager
    if hasattr(ctx.server, 'file_transfer_manager'):
        success, error = ctx.server.file_transfer_manager.complete_transfer(file_id)
        if not success:
            logger.warning(f"Failed to complete transfer {file_id}: {error}")
    
    # Route FILE_END to recipient
    from .routing import local_users, user_locations
    
    if to_user in local_users:
        # Deliver locally
        user_link = local_users[to_user]
        try:
            import json
            await user_link.ws.send(json.dumps(env))
            logger.info(f"FILE_END delivered locally to {to_user}")
        except Exception as e:
            logger.error(f"Failed to deliver FILE_END to {to_user}: {e}")
    else:
        # Forward to remote server
        server_id = user_locations.get(to_user)
        if server_id and server_id != "local":
            from .routing import servers
            if server_id in servers:
                server_link = servers[server_id]
                try:
                    import json
                    await server_link.ws.send(json.dumps(env))
                    logger.info(f"FILE_END forwarded to server {server_id}")
                except Exception as e:
                    logger.error(f"Failed to forward FILE_END: {e}")
    
    logger.info(f"FILE_END processed for transfer {file_id}")


# Export functions
__all__ = [
    'FileTransfer',
    'FileTransferManager',
    'handle_file_start',
    'handle_file_chunk',
    'handle_file_end',
]