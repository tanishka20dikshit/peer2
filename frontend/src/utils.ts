/**
 * Phase 6.1: Utility Functions
 *
 * - Base64URL encoding/decoding (Protocol §4)
 * - String/binary conversions
 * - Timestamp utilities
 */

// ============================================================================
// Base64URL Encoding/Decoding (Protocol §4)
// ============================================================================

/**
 * Encode ArrayBuffer to base64url (no padding)
 * Protocol §4: base64url encoding required
 *
 * @param buffer - Data to encode
 * @returns string - Base64URL encoded string (no padding)
 */
export function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""); // Remove padding
}

/**
 * Decode base64url to ArrayBuffer
 *
 * @param str - Base64URL encoded string
 * @returns ArrayBuffer - Decoded data
 */
export function base64urlDecode(str: string): ArrayBuffer {
  // Add padding if needed
  const paddingLength = (4 - (str.length % 4)) % 4;
  const padded = str + "=".repeat(paddingLength);

  // Convert base64url to base64
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

// ============================================================================
// String/Binary Conversions
// ============================================================================

/**
 * Convert string to Uint8Array (UTF-8)
 *
 * @param str - String to convert
 * @returns Uint8Array - UTF-8 encoded bytes
 */
export function stringToBytes(str: string): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(str);
  // Create a copy with a proper ArrayBuffer (not ArrayBufferLike)
  return new Uint8Array(encoded.buffer.slice(0));
}

/**
 * Convert Uint8Array to string (UTF-8)
 *
 * @param bytes - Bytes to convert
 * @returns string - Decoded string
 */
export function bytesToString(bytes: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

/**
 * Convert hex string to Uint8Array
 * Used for SHA-256 hashes
 *
 * @param hex - Hex string
 * @returns Uint8Array - Bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 *
 * @param bytes - Bytes to convert
 * @returns string - Hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ============================================================================
// Timestamp Utilities
// ============================================================================

/**
 * Get current Unix timestamp in milliseconds
 * Protocol requires millisecond timestamps
 *
 * @returns number - Current timestamp
 */
export function nowMs(): number {
  return Date.now();
}

/**
 * Format timestamp for display
 *
 * @param ts - Timestamp in milliseconds
 * @returns string - Formatted time (HH:MM:SS)
 */
export function formatTimestamp(ts: number): string {
  const date = new Date(ts);
  return date.toLocaleTimeString();
}

// ============================================================================
// UUID v4 Generation
// ============================================================================

/**
 * Generate UUID v4
 * Protocol §5.1: UUID v4 for user_id
 *
 * @returns string - UUID v4
 */
export function generateUUID(): string {
  return crypto.randomUUID();
}

// ============================================================================
// Canonical JSON (Protocol §12)
// ============================================================================

/**
 * Serialize object to canonical JSON
 * Protocol §12: Sorted keys, no whitespace
 *
 * @param obj - Object to serialize
 * @returns string - Canonical JSON string
 */
export function canonicalJSON(obj: any): string {
  return JSON.stringify(obj, Object.keys(obj).sort(), 0);
}

/**
 * Convert canonical JSON string to bytes for signing
 *
 * @param obj - Object to serialize
 * @returns Uint8Array - UTF-8 encoded canonical JSON
 */
export function canonicalJSONBytes(obj: any): Uint8Array {
  return stringToBytes(canonicalJSON(obj));
}
