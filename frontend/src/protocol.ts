/**
 * Phase 6.1: SOCP Protocol Implementation
 *
 * - JSON envelope creation (Protocol §7)
 * - Message type definitions
 * - Protocol-compliant message builders
 */

import { base64urlEncode } from "./utils";
import { nowMs, canonicalJSONBytes } from "./utils";
import { rsaPssSign } from "./crypto";

// ============================================================================
// Message Types (Protocol §7-9)
// ============================================================================

export type MessageType =
  // User-to-Server
  | "USER_HELLO"
  | "USER_REGISTER"
  | "USER_LOGIN"
  | "USER_LIST"
  | "GET_PUBKEY"
  | "MSG_DIRECT"
  | "MSG_PUBLIC_CHANNEL"
  | "FILE_START"
  | "FILE_CHUNK"
  | "FILE_END"
  // Server-to-User
  | "USER_WELCOME"
  | "USER_REGISTERED"
  | "USER_LOGIN_SUCCESS"
  | "USER_LIST_RESPONSE"
  | "PUBKEY_RESPONSE"
  | "USER_DELIVER"
  | "PUBLIC_CHANNEL_KEY_SHARE"
  | "PUBLIC_CHANNEL_KEY_DELIVERY"
  | "USER_ADVERTISE"
  | "USER_REMOVE"
  | "ERROR"
  | "ACK"
  // Control
  | "CTRL_CLOSE";

// ============================================================================
// JSON Envelope (Protocol §7)
// ============================================================================

export interface Envelope {
  type: MessageType;
  from: string; // user_id or server_id
  to: string; // user_id, server_id, or "*"
  ts: number; // Unix timestamp in milliseconds
  payload: any; // Message-specific payload
  sig: string; // Signature (base64url)
}

/**
 * Build a protocol-compliant JSON envelope
 * Protocol §7: JSON Envelope structure
 *
 * @param type - Message type
 * @param from - Sender ID
 * @param to - Recipient ID
 * @param payload - Message payload
 * @param sig - Signature (optional, defaults to empty string)
 * @returns Envelope - Complete message envelope
 */
export function buildEnvelope(
  type: MessageType,
  from: string,
  to: string,
  payload: any,
  sig: string = ""
): Envelope {
  return {
    type,
    from,
    to,
    ts: nowMs(),
    payload,
    sig,
  };
}

/**
 * Sign a message envelope
 * Protocol §12: Transport signature over payload
 *
 * @param envelope - Message envelope
 * @param privateKey - Signing key
 * @returns Promise<string> - Base64url signature
 */
export async function signEnvelope(
  envelope: Envelope,
  privateKey: CryptoKey
): Promise<string> {
  const payloadBytes = canonicalJSONBytes(envelope.payload);
  const signatureBuffer = await rsaPssSign(
    privateKey,
    payloadBytes as BufferSource
  );
  return base64urlEncode(signatureBuffer);
}

// ============================================================================
// Message Builders (User-to-Server)
// ============================================================================

/**
 * Build USER_HELLO message (Protocol §9.1)
 *
 * @param userId - User's UUID
 * @param serverId - Server's ID
 * @param pubkey - User's public key (base64url)
 * @param encPubkey - Encryption public key (base64url)
 * @param meta - Optional user metadata
 * @returns Envelope - USER_HELLO message
 */
export function buildUserHello(
  userId: string,
  serverId: string,
  pubkey: string,
  encPubkey: string,
  meta?: any
): Envelope {
  return buildEnvelope("USER_HELLO", userId, serverId, {
    client: "web-v1.0",
    pubkey,
    enc_pubkey: encPubkey,
    meta: meta || {},
  });
}

/**
 * Build USER_REGISTER message
 *
 * @param userId - User's UUID
 * @param serverId - Server's ID
 * @param pubkey - User's public key (base64url SPKI/DER)
 * @param privkeyStore - Encrypted private key
 * @param password - User's password
 * @param meta - Optional user metadata
 * @param sig - Signature (required for USER_REGISTER per Protocol §7)
 * @returns Envelope - USER_REGISTER message
 */
export function buildUserRegister(
  userId: string,
  serverId: string,
  pubkey: string,
  encPubkey: string,  // Add encryption key parameter
  privkeyStore: string,
  password: string,
  meta?: any,
  sig?: string
): Envelope {
  return buildEnvelope("USER_REGISTER", userId, serverId, {
    pubkey,
    enc_pubkey: encPubkey,
    privkey_store: privkeyStore,
    password,
    meta: meta || {},
  }, sig || "");
}

/**
 * Build USER_LIST request (Protocol §14)
 *
 * @param userId - Requesting user's ID
 * @param serverId - Server's ID
 * @returns Envelope - USER_LIST message
 */
export function buildUserListRequest(
  userId: string,
  serverId: string
): Envelope {
  return buildEnvelope("USER_LIST", userId, serverId, {});
}

/**
 * Build GET_PUBKEY request (Phase 6.0)
 *
 * @param requesterId - Requesting user's ID
 * @param serverId - Server's ID
 * @param targetUserId - User whose pubkey is requested
 * @returns Envelope - GET_PUBKEY message
 */
export function buildGetPubkeyRequest(
  requesterId: string,
  serverId: string,
  targetUserId: string
): Envelope {
  return buildEnvelope("GET_PUBKEY", requesterId, serverId, {
    user_id: targetUserId,
  });
}

/**
 * Build MSG_DIRECT message (Protocol §9.2)
 *
 * @param senderId - Sender's user ID
 * @param recipientId - Recipient's user ID
 * @param ciphertext - Encrypted message (base64url)
 * @param senderPub - Sender's public key (base64url)
 * @param contentSig - Content signature (base64url)
 * @returns Envelope - MSG_DIRECT message
 */
export function buildMsgDirect(
  senderId: string,
  recipientId: string,
  ciphertext: string,
  senderPub: string,
  contentSig: string
): Envelope {
  return buildEnvelope("MSG_DIRECT", senderId, recipientId, {
    ciphertext,
    sender_pub: senderPub,
    content_sig: contentSig,
  });
}

/**
 * Build MSG_PUBLIC_CHANNEL message (Protocol §9.3)
 *
 * @param senderId - Sender's user ID
 * @param ciphertext - Encrypted message (base64url)
 * @param senderPub - Sender's public key (base64url)
 * @param contentSig - Content signature (base64url)
 * @returns Envelope - MSG_PUBLIC_CHANNEL message
 */
export function buildMsgPublicChannel(
  senderId: string,
  ciphertext: string,
  senderPub: string,
  contentSig: string
): Envelope {
  return buildEnvelope("MSG_PUBLIC_CHANNEL", senderId, "public", {
    ciphertext,
    sender_pub: senderPub,
    content_sig: contentSig,
  });
}

/**
 * Build FILE_START message (Protocol §9.4)
 *
 * Protocol Specification:
 * {
 *   "type": "FILE_START",
 *   "from": "sender_user_id",
 *   "to": "recipient_user_id",
 *   "ts": 1700000700000,
 *   "payload": {
 *     "file_id": "uuid",
 *     "name": "report.pdf",
 *     "size": 1234567,
 *     "sha256": "<hex>",
 *     "mode": "dm|public"
 *   },
 *   "sig": ""
 * }
 *
 * @param senderId - Sender's user ID
 * @param recipientId - Recipient's user ID
 * @param fileId - Unique file ID (UUID)
 * @param fileName - Original file name
 * @param fileSize - File size in bytes
 * @param sha256Hash - SHA-256 hash (hex format)
 * @param mode - Transfer mode ("dm" or "public")
 * @returns Envelope - FILE_START message
 */
export function buildFileStart(
  senderId: string,
  recipientId: string,
  fileId: string,
  fileName: string,
  fileSize: number,
  sha256Hash: string,
  mode: "dm" | "public"
): Envelope {
  return buildEnvelope("FILE_START", senderId, recipientId, {
    file_id: fileId,
    name: fileName,
    size: fileSize,
    sha256: sha256Hash,
    mode,
  });
}

/**
 * Build FILE_CHUNK message (Protocol §9.4)
 *
 * Protocol Specification:
 * {
 *   "type": "FILE_CHUNK",
 *   "from": "sender_user_id",
 *   "to": "recipient_user_id",
 *   "ts": 1700000700500,
 *   "payload": {
 *     "file_id": "uuid",
 *     "index": 0,
 *     "ciphertext": "<base64url encrypted chunk>"
 *   },
 *   "sig": ""
 * }
 *
 * @param senderId - Sender's user ID
 * @param recipientId - Recipient's user ID
 * @param fileId - File ID
 * @param index - Chunk index (0-based)
 * @param ciphertext - Encrypted chunk (base64url)
 * @returns Envelope - FILE_CHUNK message
 */
export function buildFileChunk(
  senderId: string,
  recipientId: string,
  fileId: string,
  index: number,
  ciphertext: string
): Envelope {
  return buildEnvelope("FILE_CHUNK", senderId, recipientId, {
    file_id: fileId,
    index,
    ciphertext,
  });
}

/**
 * Build FILE_END message (Protocol §9.4)
 *
 * Protocol Specification:
 * {
 *   "type": "FILE_END",
 *   "from": "sender_user_id",
 *   "to": "recipient_user_id",
 *   "ts": 1700000701000,
 *   "payload": { "file_id": "uuid" },
 *   "sig": ""
 * }
 *
 * @param senderId - Sender's user ID
 * @param recipientId - Recipient's user ID
 * @param fileId - File ID
 * @returns Envelope - FILE_END message
 */
export function buildFileEnd(
  senderId: string,
  recipientId: string,
  fileId: string
): Envelope {
  return buildEnvelope("FILE_END", senderId, recipientId, {
    file_id: fileId,
  });
}

/**
 * Build GET_USER_DATA message (for login)
 */
export function buildGetUserData(
  userId: string,
  serverId: string
): Envelope {
  return buildEnvelope("GET_USER_DATA", userId, serverId, {});
}

// ============================================================================
// Error Codes (Protocol §9.5)
// ============================================================================

export enum ErrorCode {
  USER_NOT_FOUND = "USER_NOT_FOUND",
  INVALID_SIG = "INVALID_SIG",
  BAD_KEY = "BAD_KEY",
  TIMEOUT = "TIMEOUT",
  UNKNOWN_TYPE = "UNKNOWN_TYPE",
  NAME_IN_USE = "NAME_IN_USE",
  INTERNAL_ERROR = "INTERNAL_ERROR",
}

/**
 * Parse error message
 *
 * @param envelope - Error envelope
 * @returns {code: ErrorCode, detail: string}
 */
export function parseError(envelope: Envelope): {
  code: string;
  detail: string;
} {
  return {
    code: envelope.payload.code || "UNKNOWN_ERROR",
    detail: envelope.payload.detail || "No details provided",
  };
}
