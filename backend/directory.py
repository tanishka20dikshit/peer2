"""
User Directory Service - Protocol §13
Provides directory functions for key management, user lookup, and authentication.
"""

from __future__ import annotations
import sqlite3
import json
import time
from typing import Optional, Dict, Any, List
from .crypto import (
    sign_transport, canonical_json, import_pubkey_b64url,
    validate_rsa_key_size, validate_rsa_public_exponent
)

# ============================================================================
# Core Directory Functions (Protocol §13)
# ============================================================================

def get_pubkey_directory(con: sqlite3.Connection, server_priv_key, user_id: str, key_type: str = "encryption") -> Optional[Dict[str, Any]]:
    """
    Get user's public key signed by directory (server).
    Implements §13: "get_pubkey(user_id) returns pubkey + signature by directory"
    
    Args:
        con: Database connection
        server_priv_key: Server's private key for signing
        user_id: User's UUID
        key_type: "encryption" or "signing" - which key to return
    
    Returns:
        {
            "user_id": "uuid",
            "pubkey": "base64url_encoded_key",
            "timestamp": unix_timestamp,
            "signature": "directory_signature"
        }
    """
    # Get user's public keys from database
    cur = con.execute("SELECT pubkey, enc_pubkey FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    
    if not row:
        return None
    
    signing_key = row[0]
    encryption_key = row[1] if row[1] else row[0]  # Fallback to signing key if no encryption key
    
    # Choose which key to return
    pubkey = encryption_key if key_type == "encryption" else signing_key
    
    # Create directory response
    directory_response = {
        "user_id": user_id,
        "pubkey": pubkey,
        "timestamp": int(time.time())
    }
    
    # Sign with server's private key (directory signature)
    signature = sign_transport(server_priv_key, canonical_json(directory_response))
    
    return {
        **directory_response,
        "signature": signature
    }

def batch_get_pubkeys(con: sqlite3.Connection, server_priv_key, user_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Get multiple users' public keys in one query (optimized for bulk lookups).
    
    Returns:
        {
            "user_id1": {"pubkey": "...", "signature": "..."},
            "user_id2": {"pubkey": "...", "signature": "..."},
            ...
        }
    """
    results = {}
    
    for user_id in user_ids:
        key_data = get_pubkey_directory(con, server_priv_key, user_id)
        if key_data:
            results[user_id] = key_data
    
    return results

def verify_user_exists(con: sqlite3.Connection, user_id: str) -> bool:
    """Check if a user exists in the directory"""
    cur = con.execute("SELECT 1 FROM users WHERE user_id=? LIMIT 1", (user_id,))
    return cur.fetchone() is not None

def get_user_metadata(con: sqlite3.Connection, user_id: str) -> Optional[Dict[str, Any]]:
    """
    Get user's metadata (display name, pronouns, etc.)
    Does NOT include sensitive information like keys or passwords.
    """
    cur = con.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    
    if not row:
        return None
    
    meta_json = row[0]
    return json.loads(meta_json) if meta_json else {}

# ============================================================================
# User Search & Query Functions
# ============================================================================

def search_users_by_display_name(con: sqlite3.Connection, search_term: str) -> List[Dict[str, Any]]:
    """
    Search users by display name (case-insensitive).
    Returns user_id and metadata, NOT keys.
    """
    # Get all users and filter in Python for better reliability
    cur = con.execute("""
        SELECT user_id, meta, last_login
        FROM users
        WHERE meta IS NOT NULL
        ORDER BY user_id
    """)
    
    results = []
    search_lower = search_term.lower()
    
    for row in cur.fetchall():
        user_id, meta_json, last_login = row
        
        try:
            meta = json.loads(meta_json) if meta_json else {}
            
            # Check if display_name exists and contains search term
            if 'display_name' in meta:
                display_name = str(meta['display_name']).lower()
                if search_lower in display_name:
                    results.append({
                        "user_id": user_id,
                        "meta": meta,
                        "last_login": last_login
                    })
        except (json.JSONDecodeError, KeyError):
            # Skip malformed metadata
            continue
    
    return results

def get_recently_active_users(con: sqlite3.Connection, limit: int = 20) -> List[Dict[str, Any]]:
    """Get recently active users (sorted by last_login)"""
    cur = con.execute("""
        SELECT user_id, meta, last_login
        FROM users
        WHERE last_login IS NOT NULL
        ORDER BY last_login DESC
        LIMIT ?
    """, (limit,))
    
    results = []
    for row in cur.fetchall():
        user_id, meta_json, last_login = row
        results.append({
            "user_id": user_id,
            "meta": json.loads(meta_json) if meta_json else {},
            "last_login": last_login
        })
    
    return results

def get_all_user_ids(con: sqlite3.Connection) -> List[str]:
    """Get list of all user IDs (for broadcasting, gossip, etc.)"""
    cur = con.execute("SELECT user_id FROM users ORDER BY user_id")
    return [row[0] for row in cur.fetchall()]

# ============================================================================
# Key Revocation & Rotation (Protocol §13 Optional)
# ============================================================================

def revoke_user_key(con: sqlite3.Connection, user_id: str, reason: str = "", revoked_by: str = "system") -> bool:
    """
    Mark user's key as revoked.
    Implements §13 optional: "store revocation and rotation metadata"
    """
    try:
        # Get current metadata
        cur = con.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        
        if not row:
            return False
        
        meta = json.loads(row[0]) if row[0] else {}
        
        # Add revocation info
        meta['revoked'] = int(time.time())
        meta['revoked_by'] = revoked_by
        meta['revoked_reason'] = reason
        
        # Update user record and increment version
        con.execute("""
            UPDATE users 
            SET meta = ?,
                version = version + 1
            WHERE user_id = ?
        """, (json.dumps(meta), user_id))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def is_key_revoked(con: sqlite3.Connection, user_id: str) -> bool:
    """Check if user's key has been revoked"""
    cur = con.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    
    if not row or not row[0]:
        return False
    
    meta = json.loads(row[0])
    return "revoked" in meta and meta.get("revoked") is not None

def unrevoke_user_key(con: sqlite3.Connection, user_id: str) -> bool:
    """Remove revocation status from user's key"""
    try:
        cur = con.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        
        if not row:
            return False
        
        meta = json.loads(row[0]) if row[0] else {}
        
        # Remove revocation info
        meta.pop('revoked', None)
        meta.pop('revoked_by', None)
        meta.pop('revoked_reason', None)
        
        con.execute("""
            UPDATE users 
            SET meta = ?,
                version = version + 1
            WHERE user_id = ?
        """, (json.dumps(meta), user_id))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def rotate_user_key(con: sqlite3.Connection, user_id: str, new_pubkey: str, 
                   new_privkey_store: str) -> bool:
    """
    Rotate user's RSA key pair.
    Implements §13 optional: "store revocation and rotation metadata"
    """
    try:
        # Validate new key
        pubkey = import_pubkey_b64url(new_pubkey)
        if not validate_rsa_key_size(pubkey) or not validate_rsa_public_exponent(pubkey):
            return False
        
        # Get current metadata
        cur = con.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        
        if not row:
            return False
        
        meta = json.loads(row[0]) if row[0] else {}
        
        # Track key rotation history
        if 'key_rotations' not in meta:
            meta['key_rotations'] = []
        
        meta['key_rotations'].append({
            "rotated_at": int(time.time()),
            "reason": "manual_rotation"
        })
        
        # Update key and increment version
        con.execute("""
            UPDATE users 
            SET pubkey = ?,
                privkey_store = ?,
                meta = ?,
                version = version + 1
            WHERE user_id = ?
        """, (new_pubkey, new_privkey_store, json.dumps(meta), user_id))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def get_key_rotation_history(con: sqlite3.Connection, user_id: str) -> List[Dict[str, Any]]:
    """Get history of key rotations for a user"""
    cur = con.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    
    if not row or not row[0]:
        return []
    
    meta = json.loads(row[0])
    return meta.get('key_rotations', [])

# ============================================================================
# Directory Statistics & Health
# ============================================================================

def get_directory_stats(con: sqlite3.Connection) -> Dict[str, Any]:
    """Get directory statistics"""
    stats = {}
    
    # Total users
    cur = con.execute("SELECT COUNT(*) FROM users")
    stats['total_users'] = cur.fetchone()[0]
    
    # Users with recent logins (last 24 hours)
    day_ago = int(time.time()) - 86400
    cur = con.execute("SELECT COUNT(*) FROM users WHERE last_login > ?", (day_ago,))
    stats['active_24h'] = cur.fetchone()[0]
    
    # Revoked keys
    cur = con.execute("SELECT COUNT(*) FROM users WHERE meta LIKE '%revoked%'")
    stats['revoked_keys'] = cur.fetchone()[0]
    
    # Users by version
    cur = con.execute("SELECT version, COUNT(*) FROM users GROUP BY version")
    stats['version_distribution'] = {row[0]: row[1] for row in cur.fetchall()}
    
    return stats

# ============================================================================
# Directory Response Validation
# ============================================================================

def validate_directory_response(response: Dict[str, Any], server_pubkey) -> bool:
    """
    Validate a directory response signature.
    Used by clients to verify responses from the directory service.
    """
    if not all(k in response for k in ["user_id", "pubkey", "timestamp", "signature"]):
        return False
    
    from .crypto import verify_transport
    
    directory_data = {
        "user_id": response["user_id"],
        "pubkey": response["pubkey"],
        "timestamp": response["timestamp"]
    }
    
    return verify_transport(server_pubkey, canonical_json(directory_data), response["signature"])

# ============================================================================
# Export public directory API (for other modules to import)
# ============================================================================

__all__ = [
    # Core directory functions
    'get_pubkey_directory',
    'batch_get_pubkeys',
    'verify_user_exists',
    'get_user_metadata',
    
    # Search functions
    'search_users_by_display_name',
    'get_recently_active_users',
    'get_all_user_ids',
    
    # Revocation & rotation
    'revoke_user_key',
    'is_key_revoked',
    'unrevoke_user_key',
    'rotate_user_key',
    'get_key_rotation_history',
    
    # Statistics
    'get_directory_stats',
    
    # Validation
    'validate_directory_response',
]
