"""
Server Key Management System
Protocol §8.1, §8.2 - Server public key storage and retrieval for signature verification

This module manages the storage and retrieval of server public keys to enable:
1. Signature verification for SERVER_HELLO_JOIN, SERVER_ANNOUNCE
2. Signature verification for USER_ADVERTISE, USER_REMOVE gossip messages
3. Persistent storage of server keys across restarts
"""

from __future__ import annotations
import sqlite3
import logging
from typing import Optional, Dict, List
from .crypto import import_pubkey_b64url, export_pubkey_b64url, validate_rsa_key_size

logger = logging.getLogger(__name__)

# Database schema for server keys
SERVER_KEYS_SCHEMA = """
CREATE TABLE IF NOT EXISTS server_keys(
    server_id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    first_seen INT NOT NULL,
    last_seen INT NOT NULL,
    verified BOOLEAN DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_server_keys_host_port ON server_keys(host, port);
"""

def init_server_keys_table(con: sqlite3.Connection):
    """Initialize the server_keys table in the database"""
    try:
        con.executescript(SERVER_KEYS_SCHEMA)
        con.commit()
        logger.info("Server keys table initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize server keys table: {e}")
        return False


def store_server_key(con: sqlite3.Connection, server_id: str, pubkey_b64url: str, 
                     host: Optional[str] = None, port: Optional[int] = None) -> bool:
    """
    Store a server's public key for signature verification (Protocol §8.1)
    
    Args:
        con: Database connection
        server_id: Server's UUID
        pubkey_b64url: Server's RSA-4096 public key in base64url format
        host: Server's host address (optional)
        port: Server's port (optional)
    
    Returns:
        True if stored successfully, False otherwise
    """
    try:
        # Validate the public key before storing
        try:
            pubkey = import_pubkey_b64url(pubkey_b64url)
            if not validate_rsa_key_size(pubkey):
                logger.error(f"Server {server_id} public key is not RSA-4096")
                return False
        except Exception as e:
            logger.error(f"Invalid public key format for server {server_id}: {e}")
            return False
        
        # Check if server key already exists
        cur = con.execute("SELECT server_id, pubkey FROM server_keys WHERE server_id=?", (server_id,))
        existing = cur.fetchone()
        
        import time
        timestamp = int(time.time())
        
        if existing:
            # Update existing entry
            existing_pubkey = existing[1]
            
            # Check if public key has changed (potential security issue)
            if existing_pubkey != pubkey_b64url:
                logger.warning(
                    f"Server {server_id} public key changed! "
                    f"This could indicate a security issue or key rotation."
                )
                # In production, this should trigger additional validation
                # For now, we'll update it but mark as unverified
                con.execute("""
                    UPDATE server_keys 
                    SET pubkey=?, host=?, port=?, last_seen=?, verified=0
                    WHERE server_id=?
                """, (pubkey_b64url, host, port, timestamp, server_id))
            else:
                # Just update last_seen and connection info
                con.execute("""
                    UPDATE server_keys 
                    SET host=?, port=?, last_seen=?
                    WHERE server_id=?
                """, (host, port, timestamp, server_id))
            
            logger.debug(f"Updated server key for {server_id}")
        else:
            # Insert new entry
            con.execute("""
                INSERT INTO server_keys(server_id, pubkey, host, port, first_seen, last_seen, verified)
                VALUES(?, ?, ?, ?, ?, ?, 1)
            """, (server_id, pubkey_b64url, host, port, timestamp, timestamp))
            
            logger.info(f"Stored new server key for {server_id}")
        
        con.commit()
        return True
        
    except Exception as e:
        logger.error(f"Failed to store server key for {server_id}: {e}")
        con.rollback()
        return False


def get_server_key(con: sqlite3.Connection, server_id: str) -> Optional[str]:
    """
    Retrieve a server's public key for signature verification
    
    Args:
        con: Database connection
        server_id: Server's UUID
    
    Returns:
        Server's public key in base64url format, or None if not found
    """
    try:
        cur = con.execute("SELECT pubkey FROM server_keys WHERE server_id=?", (server_id,))
        row = cur.fetchone()
        
        if row:
            return row[0]
        else:
            logger.debug(f"No stored key found for server {server_id}")
            return None
            
    except Exception as e:
        logger.error(f"Failed to retrieve server key for {server_id}: {e}")
        return None


def get_server_info(con: sqlite3.Connection, server_id: str) -> Optional[Dict[str, any]]:
    """
    Retrieve complete server information including key and connection details
    
    Args:
        con: Database connection
        server_id: Server's UUID
    
    Returns:
        Dictionary with server info, or None if not found
    """
    try:
        cur = con.execute("""
            SELECT server_id, pubkey, host, port, first_seen, last_seen, verified
            FROM server_keys 
            WHERE server_id=?
        """, (server_id,))
        row = cur.fetchone()
        
        if row:
            return {
                "server_id": row[0],
                "pubkey": row[1],
                "host": row[2],
                "port": row[3],
                "first_seen": row[4],
                "last_seen": row[5],
                "verified": bool(row[6])
            }
        else:
            return None
            
    except Exception as e:
        logger.error(f"Failed to retrieve server info for {server_id}: {e}")
        return None


def list_known_servers(con: sqlite3.Connection) -> List[Dict[str, any]]:
    """
    List all known servers with their public keys
    
    Returns:
        List of dictionaries containing server information
    """
    try:
        cur = con.execute("""
            SELECT server_id, pubkey, host, port, first_seen, last_seen, verified
            FROM server_keys
            ORDER BY last_seen DESC
        """)
        
        servers = []
        for row in cur.fetchall():
            servers.append({
                "server_id": row[0],
                "pubkey": row[1],
                "host": row[2],
                "port": row[3],
                "first_seen": row[4],
                "last_seen": row[5],
                "verified": bool(row[6])
            })
        
        return servers
        
    except Exception as e:
        logger.error(f"Failed to list known servers: {e}")
        return []


def delete_server_key(con: sqlite3.Connection, server_id: str) -> bool:
    """
    Delete a server's public key from storage
    
    Args:
        con: Database connection
        server_id: Server's UUID
    
    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        con.execute("DELETE FROM server_keys WHERE server_id=?", (server_id,))
        con.commit()
        logger.info(f"Deleted server key for {server_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete server key for {server_id}: {e}")
        con.rollback()
        return False


def verify_server_key_consistency(con: sqlite3.Connection, server_id: str, 
                                   pubkey_b64url: str) -> bool:
    """
    Verify that a received public key matches the stored key for a server
    
    This is important for detecting key changes which could indicate:
    - Legitimate key rotation
    - Man-in-the-middle attacks
    - Server impersonation
    
    Args:
        con: Database connection
        server_id: Server's UUID
        pubkey_b64url: Public key to verify
    
    Returns:
        True if key matches or no key stored yet, False if mismatch
    """
    stored_key = get_server_key(con, server_id)
    
    if stored_key is None:
        # No key stored yet, so this is the first time we're seeing this server
        return True
    
    if stored_key == pubkey_b64url:
        # Key matches
        return True
    else:
        # Key mismatch - potential security issue
        logger.warning(
            f"Server {server_id} key mismatch! "
            f"Stored key differs from received key. "
            f"This could indicate key rotation or a security issue."
        )
        return False


def cleanup_old_servers(con: sqlite3.Connection, days_threshold: int = 30) -> int:
    """
    Clean up server keys that haven't been seen in a long time
    
    Args:
        con: Database connection
        days_threshold: Number of days of inactivity before cleanup
    
    Returns:
        Number of servers cleaned up
    """
    try:
        import time
        cutoff_time = int(time.time()) - (days_threshold * 24 * 60 * 60)
        
        cur = con.execute("SELECT COUNT(*) FROM server_keys WHERE last_seen < ?", (cutoff_time,))
        count = cur.fetchone()[0]
        
        if count > 0:
            con.execute("DELETE FROM server_keys WHERE last_seen < ?", (cutoff_time,))
            con.commit()
            logger.info(f"Cleaned up {count} old server keys (inactive for >{days_threshold} days)")
        
        return count
        
    except Exception as e:
        logger.error(f"Failed to cleanup old servers: {e}")
        con.rollback()
        return 0


# Export functions
__all__ = [
    'init_server_keys_table',
    'store_server_key',
    'get_server_key',
    'get_server_info',
    'list_known_servers',
    'delete_server_key',
    'verify_server_key_consistency',
    'cleanup_old_servers'
]