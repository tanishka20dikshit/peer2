"""
Group and Channel Management - Protocol §15.1
Handles public channel and group operations, including key wrapping and version management.
"""

from __future__ import annotations
import sqlite3
import json
import time
import secrets
from typing import Optional, Dict, Any, List, Tuple
from .crypto import rsa_oaep_encrypt, import_pubkey_b64url

# ============================================================================
# Public Channel Management (Protocol §15.1 - REQUIRED)
# ============================================================================

def create_public_channel(con: sqlite3.Connection) -> bool:
    """
    Create the public channel (called 'public').
    Protocol §15.1: group_id='public', creator_id='system'
    """
    try:
        # Check if public channel already exists
        cur = con.execute("SELECT group_id FROM groups WHERE group_id='public'")
        if cur.fetchone():
            return True  # Already exists
        
        # Create public channel with initial version 1
        con.execute("""
            INSERT INTO groups(group_id, creator_id, created_at, meta, version)
            VALUES('public', 'system', ?, ?, ?)
        """, (int(time.time()), json.dumps({"name": "Public Channel", "description": "Global public channel"}), 1))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def get_public_channel_info(con: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """Get public channel information"""
    cur = con.execute("""
        SELECT group_id, creator_id, created_at, meta, version
        FROM groups WHERE group_id='public'
    """)
    
    row = cur.fetchone()
    if not row:
        return None
    
    group_id, creator_id, created_at, meta_json, version = row
    return {
        "group_id": group_id,
        "creator_id": creator_id,
        "created_at": created_at,
        "meta": json.loads(meta_json) if meta_json else {},
        "version": version
    }

def add_user_to_public_channel(con: sqlite3.Connection, user_id: str, wrapped_key: str) -> bool:
    """
    Add user to public channel.
    Protocol §15.1: All members have role='member' (no owners/admins)
    """
    try:
        # Check if public channel exists
        if not get_public_channel_info(con):
            create_public_channel(con)
        
        # Add user as member
        con.execute("""
            INSERT OR REPLACE INTO group_members(group_id, member_id, role, wrapped_key, added_at)
            VALUES('public', ?, 'member', ?, ?)
        """, (user_id, wrapped_key, int(time.time())))
        
        # Bump public channel version
        con.execute("UPDATE groups SET version = version + 1 WHERE group_id='public'")
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

# Protocol §9.3: "Users are added to the public channel by default and cannot be removed"
# This function is commented out to align with protocol requirements
#
# def remove_user_from_public_channel(con: sqlite3.Connection, user_id: str) -> bool:
#     """
#     Remove user from public channel.
#     DISABLED: Protocol §9.3 states users "cannot be removed" from public channel.
#     """
#     try:
#         con.execute("""
#             DELETE FROM group_members 
#             WHERE group_id='public' AND member_id=?
#         """, (user_id,))
#         
#         # Bump version
#         con.execute("UPDATE groups SET version = version + 1 WHERE group_id='public'")
#         
#         con.commit()
#         return True
#         
#     except Exception:
#         con.rollback()
#         return False

def get_public_channel_members(con: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Get all members of the public channel"""
    cur = con.execute("""
        SELECT member_id, wrapped_key, added_at
        FROM group_members 
        WHERE group_id='public'
        ORDER BY added_at
    """)
    
    members = []
    for row in cur.fetchall():
        member_id, wrapped_key, added_at = row
        members.append({
            "member_id": member_id,
            "wrapped_key": wrapped_key,
            "added_at": added_at,
            "role": "member"  # Protocol: public channel only has members
        })
    
    return members

def get_public_channel_member_count(con: sqlite3.Connection) -> int:
    """Get count of public channel members"""
    cur = con.execute("SELECT COUNT(*) FROM group_members WHERE group_id='public'")
    return cur.fetchone()[0]

def is_user_in_public_channel(con: sqlite3.Connection, user_id: str) -> bool:
    """Check if user is in public channel"""
    cur = con.execute("""
        SELECT 1 FROM group_members 
        WHERE group_id='public' AND member_id=? 
        LIMIT 1
    """, (user_id,))
    return cur.fetchone() is not None

# ============================================================================
# Group Key Management (Protocol §15.1)
# ============================================================================

def generate_group_key() -> bytes:
    """
    Generate a random 256-bit group key.
    Protocol §15.1: "The group key is a random 256-bit value per groups.version"
    """
    return secrets.token_bytes(32)  # 256 bits = 32 bytes

def wrap_group_key_for_user(group_key: bytes, user_pubkey: str) -> str:
    """
    Wrap (encrypt) group key for a specific user using their RSA public key.
    Protocol §15.1: "RSA-OAEP(SHA-256) of current group_key for member_id"
    """
    # Import user's public key
    pubkey = import_pubkey_b64url(user_pubkey)
    
    # Encrypt group key with user's public key using RSA-OAEP
    wrapped_key = rsa_oaep_encrypt(pubkey, group_key)
    
    return wrapped_key

def wrap_group_key_for_members(con: sqlite3.Connection, group_id: str, group_key: bytes) -> List[Dict[str, str]]:
    """
    Wrap group key for all members of a group.
    Returns list of {member_id, wrapped_key} for distribution.
    """
    # Get all group members
    cur = con.execute("""
        SELECT gm.member_id, u.pubkey
        FROM group_members gm
        JOIN users u ON gm.member_id = u.user_id
        WHERE gm.group_id = ?
    """, (group_id,))
    
    wraps = []
    for row in cur.fetchall():
        member_id, user_pubkey = row
        wrapped_key = wrap_group_key_for_user(group_key, user_pubkey)
        wraps.append({
            "member_id": member_id,
            "wrapped_key": wrapped_key
        })
    
    return wraps

def update_wrapped_keys(con: sqlite3.Connection, group_id: str, wraps: List[Dict[str, str]]) -> bool:
    """Update wrapped keys for group members"""
    try:
        for wrap in wraps:
            con.execute("""
                UPDATE group_members
                SET wrapped_key = ?
                WHERE group_id = ? AND member_id = ?
            """, (wrap["wrapped_key"], group_id, wrap["member_id"]))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

# ============================================================================
# Private Group Management (Optional - beyond public channel)
# ============================================================================

def create_group(con: sqlite3.Connection, group_id: str, creator_id: str, 
                meta: Optional[Dict[str, Any]] = None) -> bool:
    """
    Create a new private group.
    Note: Protocol only REQUIRES public channel, this is optional.
    """
    try:
        # Validate group_id doesn't exist
        cur = con.execute("SELECT group_id FROM groups WHERE group_id=?", (group_id,))
        if cur.fetchone():
            return False  # Group already exists
        
        # Create group
        con.execute("""
            INSERT INTO groups(group_id, creator_id, created_at, meta, version)
            VALUES(?, ?, ?, ?, 1)
        """, (group_id, creator_id, int(time.time()), json.dumps(meta) if meta else None))
        
        # Add creator as owner
        con.execute("""
            INSERT INTO group_members(group_id, member_id, role, wrapped_key, added_at)
            VALUES(?, ?, 'owner', 'placeholder_key', ?)
        """, (group_id, creator_id, int(time.time())))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def delete_group(con: sqlite3.Connection, group_id: str) -> bool:
    """Delete a private group (cannot delete public channel)"""
    try:
        if group_id == "public":
            return False  # Cannot delete public channel
        
        # Delete members first (foreign key constraint)
        con.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
        
        # Delete group
        con.execute("DELETE FROM groups WHERE group_id=?", (group_id,))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def get_group_info(con: sqlite3.Connection, group_id: str) -> Optional[Dict[str, Any]]:
    """Get group information"""
    cur = con.execute("""
        SELECT group_id, creator_id, created_at, meta, version
        FROM groups WHERE group_id=?
    """, (group_id,))
    
    row = cur.fetchone()
    if not row:
        return None
    
    group_id, creator_id, created_at, meta_json, version = row
    return {
        "group_id": group_id,
        "creator_id": creator_id,
        "created_at": created_at,
        "meta": json.loads(meta_json) if meta_json else {},
        "version": version
    }

def add_member_to_group(con: sqlite3.Connection, group_id: str, member_id: str, 
                       wrapped_key: str, role: str = "member") -> bool:
    """Add a member to a group"""
    try:
        # Validate role
        if role not in ["owner", "admin", "member"]:
            return False
        
        # Public channel can only have members
        if group_id == "public" and role != "member":
            return False
        
        # Add member
        con.execute("""
            INSERT OR REPLACE INTO group_members(group_id, member_id, role, wrapped_key, added_at)
            VALUES(?, ?, ?, ?, ?)
        """, (group_id, member_id, role, wrapped_key, int(time.time())))
        
        # Bump group version
        con.execute("UPDATE groups SET version = version + 1 WHERE group_id=?", (group_id,))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def remove_member_from_group(con: sqlite3.Connection, group_id: str, member_id: str) -> bool:
    """Remove a member from a group"""
    try:
        # Cannot remove from public channel (per protocol)
        if group_id == "public":
            return False
        
        con.execute("""
            DELETE FROM group_members 
            WHERE group_id=? AND member_id=?
        """, (group_id, member_id))
        
        # Bump version
        con.execute("UPDATE groups SET version = version + 1 WHERE group_id=?", (group_id,))
        
        con.commit()
        return True
        
    except Exception:
        con.rollback()
        return False

def get_group_members(con: sqlite3.Connection, group_id: str) -> List[Dict[str, Any]]:
    """Get all members of a group"""
    cur = con.execute("""
        SELECT member_id, role, wrapped_key, added_at
        FROM group_members 
        WHERE group_id=?
        ORDER BY added_at
    """, (group_id,))
    
    members = []
    for row in cur.fetchall():
        member_id, role, wrapped_key, added_at = row
        members.append({
            "member_id": member_id,
            "role": role,
            "wrapped_key": wrapped_key,
            "added_at": added_at
        })
    
    return members

def get_user_groups(con: sqlite3.Connection, user_id: str) -> List[Dict[str, Any]]:
    """Get all groups a user is a member of"""
    cur = con.execute("""
        SELECT g.group_id, g.creator_id, g.created_at, g.meta, g.version, gm.role
        FROM groups g
        JOIN group_members gm ON g.group_id = gm.group_id
        WHERE gm.member_id = ?
        ORDER BY g.created_at DESC
    """, (user_id,))
    
    groups = []
    for row in cur.fetchall():
        group_id, creator_id, created_at, meta_json, version, role = row
        groups.append({
            "group_id": group_id,
            "creator_id": creator_id,
            "created_at": created_at,
            "meta": json.loads(meta_json) if meta_json else {},
            "version": version,
            "user_role": role
        })
    
    return groups

def update_member_role(con: sqlite3.Connection, group_id: str, member_id: str, new_role: str) -> bool:
    """Update a member's role in a group"""
    try:
        # Validate role
        if new_role not in ["owner", "admin", "member"]:
            return False
        
        # Cannot change roles in public channel
        if group_id == "public":
            return False
        
        con.execute("""
            UPDATE group_members
            SET role = ?
            WHERE group_id = ? AND member_id = ?
        """, (new_role, group_id, member_id))
        
        con.commit()
        return con.total_changes > 0
        
    except Exception:
        con.rollback()
        return False

def list_all_groups(con: sqlite3.Connection) -> List[Dict[str, Any]]:
    """List all groups in the system"""
    cur = con.execute("""
        SELECT group_id, creator_id, created_at, meta, version
        FROM groups
        ORDER BY created_at DESC
    """)
    
    groups = []
    for row in cur.fetchall():
        group_id, creator_id, created_at, meta_json, version = row
        
        # Get member count
        count_cur = con.execute("SELECT COUNT(*) FROM group_members WHERE group_id=?", (group_id,))
        member_count = count_cur.fetchone()[0]
        
        groups.append({
            "group_id": group_id,
            "creator_id": creator_id,
            "created_at": created_at,
            "meta": json.loads(meta_json) if meta_json else {},
            "version": version,
            "member_count": member_count
        })
    
    return groups

# ============================================================================
# Export public API
# ============================================================================

__all__ = [
    # Public channel (REQUIRED)
    'create_public_channel',
    'get_public_channel_info',
    'add_user_to_public_channel',
    # 'remove_user_from_public_channel',  # DISABLED: Protocol §9.3 - users cannot be removed
    'get_public_channel_members',
    'get_public_channel_member_count',
    'is_user_in_public_channel',
    
    # Group key management
    'generate_group_key',
    'wrap_group_key_for_user',
    'wrap_group_key_for_members',
    'update_wrapped_keys',
    
    # Private groups (Optional)
    'create_group',
    'delete_group',
    'get_group_info',
    'add_member_to_group',
    'remove_member_from_group',
    'get_group_members',
    'get_user_groups',
    'update_member_role',
    'list_all_groups',
]
