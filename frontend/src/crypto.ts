/**
 * Phase 6.1: Browser-based RSA-4096 Cryptography
 *
 * Implements SOCP v1.3 cryptographic requirements:
 * - RSA-4096 key generation
 * - RSA-OAEP (SHA-256) encryption/decryption
 * - RSASSA-PSS (SHA-256) signing/verification
 * - Protocol §4, §12 compliant
 */

import { base64urlEncode, base64urlDecode } from "./utils";

// ============================================================================
// Constants
// ============================================================================

export const RSA_KEY_SIZE = 4096;
export const RSA_PUBLIC_EXPONENT = 65537; // F4
export const HASH_ALGORITHM = "SHA-256";

// RSA-4096 OAEP max plaintext calculation (Protocol requirement)
// Formula: (keySize/8) - 2*hashLen - 2
// = (4096/8) - 2*32 - 2 = 512 - 64 - 2 = 446 bytes
export const RSA_OAEP_MAX_PLAINTEXT = 446;

// ============================================================================
// RSA-4096 Key Generation
// ============================================================================

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Generate RSA-4096 key pair using Web Crypto API
 * Protocol §4: RSA-4096 only
 *
 * @returns Promise<KeyPair> - Generated key pair
 */
export async function generateRSAKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_KEY_SIZE,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: HASH_ALGORITHM,
    },
    true, // extractable
    ["encrypt", "decrypt"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Generate RSA-4096 key pair for signing (RSASSA-PSS)
 * Used for content signatures (Protocol §12)
 */
export async function generateRSASigningKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: RSA_KEY_SIZE,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: HASH_ALGORITHM,
    },
    true,
    ["sign", "verify"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// ============================================================================
// RSA-OAEP Encryption/Decryption (Protocol §4)
// ============================================================================

/**
 * Encrypt data with RSA-OAEP (SHA-256)
 * Protocol §4: RSA-OAEP (SHA-256) only
 *
 * @param publicKey - Recipient's public key
 * @param plaintext - Data to encrypt (max 446 bytes)
 * @returns Promise<ArrayBuffer> - Encrypted ciphertext
 */
export async function rsaOaepEncrypt(
  publicKey: CryptoKey,
  plaintext: BufferSource
): Promise<ArrayBuffer> {
  // Convert to Uint8Array for length check if needed
  const plaintextArray =
    plaintext instanceof Uint8Array
      ? plaintext
      : new Uint8Array(plaintext as ArrayBuffer);

  if (plaintextArray.length > RSA_OAEP_MAX_PLAINTEXT) {
    throw new Error(
      `Plaintext too large: ${plaintextArray.length} bytes (max: ${RSA_OAEP_MAX_PLAINTEXT})`
    );
  }

  return await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    plaintext
  );
}

/**
 * Decrypt RSA-OAEP ciphertext
 *
 * @param privateKey - Our private key
 * @param ciphertext - Encrypted data
 * @returns Promise<ArrayBuffer> - Decrypted plaintext
 */
export async function rsaOaepDecrypt(
  privateKey: CryptoKey,
  ciphertext: ArrayBuffer
): Promise<ArrayBuffer> {
  return await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    ciphertext
  );
}

// ============================================================================
// AES-256-GCM Encryption/Decryption (Public Channel)
// ============================================================================

/**
 * Encrypt data with AES-256-GCM
 * Used for public channel messages
 *
 * @param key - AES-256 key
 * @param plaintext - Data to encrypt
 * @returns Promise<ArrayBuffer> - Encrypted ciphertext (includes IV)
 */
export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: BufferSource
): Promise<ArrayBuffer> {
  // Generate random IV (12 bytes for GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    plaintext
  );

  // Prepend IV to ciphertext (IV || ciphertext)
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);

  return result.buffer;
}

/**
 * Decrypt data with AES-256-GCM
 * Used for public channel messages
 *
 * @param key - AES-256 key
 * @param ciphertextWithIv - Encrypted data (IV || ciphertext)
 * @returns Promise<ArrayBuffer> - Decrypted plaintext
 */
export async function aesGcmDecrypt(
  key: CryptoKey,
  ciphertextWithIv: ArrayBuffer
): Promise<ArrayBuffer> {
  const data = new Uint8Array(ciphertextWithIv);

  // Extract IV (first 12 bytes) and ciphertext
  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12);

  // Decrypt with AES-GCM
  return await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    ciphertext
  );
}

// ============================================================================
// RSASSA-PSS Signing/Verification (Protocol §12)
// ============================================================================

/**
 * Sign data with RSASSA-PSS (SHA-256)
 * Protocol §12: RSASSA-PSS (SHA-256) for signatures
 *
 * @param privateKey - Signing key
 * @param data - Data to sign
 * @returns Promise<ArrayBuffer> - Signature
 */
export async function rsaPssSign(
  privateKey: CryptoKey,
  data: BufferSource
): Promise<ArrayBuffer> {
  return await crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32, // SHA-256 hash length
    },
    privateKey,
    data
  );
}

/**
 * Verify RSASSA-PSS signature
 *
 * @param publicKey - Verification key
 * @param signature - Signature to verify
 * @param data - Original data
 * @returns Promise<boolean> - True if signature valid
 */
export async function rsaPssVerify(
  publicKey: CryptoKey,
  signature: ArrayBuffer,
  data: BufferSource
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      publicKey,
      signature,
      data
    );
  } catch (error) {
    console.error("Signature verification failed:", error);
    return false;
  }
}

// ============================================================================
// Key Import/Export (Protocol §4)
// ============================================================================

/**
 * Export public key to JWK format
 *
 * @param publicKey - Public key to export
 * @returns Promise<JsonWebKey> - JWK representation
 */
export async function exportPublicKeyJWK(
  publicKey: CryptoKey
): Promise<JsonWebKey> {
  return await crypto.subtle.exportKey("jwk", publicKey);
}

/**
 * Export public key to SPKI format (DER-encoded, base64url)
 * This matches the backend's expected format for pubkey fields
 *
 * @param publicKey - Public key to export
 * @returns Promise<string> - Base64url-encoded SPKI/DER public key
 */
export async function exportPublicKeySPKI(
  publicKey: CryptoKey
): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const spkiBytes = new Uint8Array(spki);
  return base64urlEncode(spkiBytes);
}

/**
 * Export private key to JWK format
 *
 * @param privateKey - Private key to export
 * @returns Promise<JsonWebKey> - JWK representation
 */
export async function exportPrivateKeyJWK(
  privateKey: CryptoKey
): Promise<JsonWebKey> {
  return await crypto.subtle.exportKey("jwk", privateKey);
}

/**
 * Export private key to PKCS8 format (DER-encoded, base64url)
 * This matches the backend's expected format for private key transport
 *
 * @param privateKey - Private key to export
 * @returns Promise<string> - Base64url-encoded PKCS8/DER private key
 */
export async function exportPrivateKeyPKCS8(
  privateKey: CryptoKey
): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  const pkcs8Bytes = new Uint8Array(pkcs8);
  return base64urlEncode(pkcs8Bytes);
}

/**
 * Import public key from JWK
 *
 * @param jwk - JWK representation
 * @param keyUsages - Key usages (encrypt or verify)
 * @returns Promise<CryptoKey> - Imported key
 */
export async function importPublicKeyJWK(
  jwk: JsonWebKey,
  keyUsages: KeyUsage[] = ["encrypt"]
): Promise<CryptoKey> {
  const algorithm = keyUsages.includes("verify") ? "RSA-PSS" : "RSA-OAEP";

  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: algorithm,
      hash: HASH_ALGORITHM,
    },
    true,
    keyUsages
  );
}

/**
 * Import public key from SPKI format (base64url-encoded DER)
 *
 * @param spkiBase64url - Base64url-encoded SPKI/DER public key
 * @param keyUsages - Key usages (encrypt or verify)
 * @returns Promise<CryptoKey> - Imported key
 */
export async function importPublicKeySPKI(
  spkiBase64url: string,
  keyUsages: KeyUsage[] = ["encrypt"]
): Promise<CryptoKey> {
  const algorithm = keyUsages.includes("verify") ? "RSA-PSS" : "RSA-OAEP";

  const spkiBytes = base64urlDecode(spkiBase64url);

  return await crypto.subtle.importKey(
    "spki",
    spkiBytes,
    {
      name: algorithm,
      hash: HASH_ALGORITHM,
    },
    true,
    keyUsages
  );
}

/**
 * Import private key from JWK
 *
 * @param jwk - JWK representation
 * @param keyUsages - Key usages (decrypt or sign)
 * @returns Promise<CryptoKey> - Imported key
 */
export async function importPrivateKeyJWK(
  jwk: JsonWebKey,
  keyUsages: KeyUsage[] = ["decrypt"]
): Promise<CryptoKey> {
  const algorithm = keyUsages.includes("sign") ? "RSA-PSS" : "RSA-OAEP";

  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: algorithm,
      hash: HASH_ALGORITHM,
    },
    true,
    keyUsages
  );
}

/**
 * Import private key from PKCS8 format (base64url-encoded DER)
 *
 * @param pkcs8Base64url - Base64url-encoded PKCS8/DER private key
 * @param keyUsages - Key usages (decrypt or sign)
 * @returns Promise<CryptoKey> - Imported key
 */
export async function importPrivateKeyPKCS8(
  pkcs8Base64url: string,
  keyUsages: KeyUsage[] = ["decrypt"]
): Promise<CryptoKey> {
  const algorithm = keyUsages.includes("sign") ? "RSA-PSS" : "RSA-OAEP";

  const pkcs8Bytes = base64urlDecode(pkcs8Base64url);

  return await crypto.subtle.importKey(
    "pkcs8",
    pkcs8Bytes,
    {
      name: algorithm,
      hash: HASH_ALGORITHM,
    },
    true,
    keyUsages
  );
}

// ============================================================================
// SHA-256 Hashing
// ============================================================================

/**
 * Calculate SHA-256 hash of data
 * Protocol §4: SHA-256 for hashing
 *
 * @param data - Data to hash
 * @returns Promise<ArrayBuffer> - Hash digest
 */
export async function sha256(data: BufferSource): Promise<ArrayBuffer> {
  return await crypto.subtle.digest("SHA-256", data);
}

/**
 * Calculate SHA-256 hash and return as hex string
 * Used for file integrity verification (Protocol §9.4)
 *
 * @param data - Data to hash
 * @returns Promise<string> - Hex-encoded hash
 */
export async function sha256Hex(data: BufferSource): Promise<string> {
  const hashBuffer = await sha256(data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================================
// File Hashing (Phase 6.4: File Transfer)
// ============================================================================

/**
 * Calculate SHA-256 hash of a File object
 * Protocol §9.4: File integrity verification
 * 
 * Returns hex string format (as required by protocol)
 * Handles large files efficiently using ArrayBuffer
 *
 * @param file - File object to hash
 * @returns Promise<string> - Hex-encoded SHA-256 hash
 */
export async function hashFile(file: File): Promise<string> {
  const arrayBuffer = await file.arrayBuffer();
  return sha256Hex(arrayBuffer);
}

/**
 * Calculate SHA-256 hash of Uint8Array
 * Used for verifying reassembled file chunks
 * 
 * Returns hex string format (as required by protocol)
 *
 * @param data - Byte array to hash
 * @returns Promise<string> - Hex-encoded SHA-256 hash
 */
export async function hashBytes(data: Uint8Array): Promise<string> {
  return sha256Hex(data);
}

// ============================================================================
// Key Validation
// ============================================================================

/**
 * Validate that a key is RSA-4096
 * Protocol §4: RSA-4096 only
 *
 * @param key - Key to validate
 * @returns Promise<boolean> - True if valid RSA-4096
 */
export async function validateRSAKeySize(key: CryptoKey): Promise<boolean> {
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    // RSA-4096 modulus is 512 bytes = 684 base64 characters (approx)
    const modulusLength = jwk.n
      ? atob(jwk.n.replace(/-/g, "+").replace(/_/g, "/")).length
      : 0;
    return modulusLength === 512; // 4096 bits / 8 = 512 bytes
  } catch (error) {
    return false;
  }
}

/**
 * Validate RSA public exponent
 * Protocol §16: Reject weak exponents
 *
 * @param key - Key to validate
 * @returns Promise<boolean> - True if exponent >= 65537
 */
export async function validateRSAPublicExponent(
  key: CryptoKey
): Promise<boolean> {
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    if (!jwk.e) return false;

    // Decode base64url exponent
    const exponentB64 = jwk.e.replace(/-/g, "+").replace(/_/g, "/");
    const exponentBytes = atob(exponentB64);
    const exponentArray = new Uint8Array(exponentBytes.length);
    for (let i = 0; i < exponentBytes.length; i++) {
      exponentArray[i] = exponentBytes.charCodeAt(i);
    }

    // Convert bytes to number (big-endian)
    let exponent = 0;
    for (const byte of exponentArray) {
      exponent = (exponent << 8) | byte;
    }

    return exponent >= RSA_PUBLIC_EXPONENT; // >= 65537
  } catch (error) {
    return false;
  }
}

// ============================================================================
// Public Key Cache (Phase 6.1 Requirement)
// ============================================================================

export interface CachedPublicKey {
  userId: string;
  publicKey: CryptoKey;
  jwk: JsonWebKey;
  timestamp: number;
  verified: boolean; // Signature verified by directory
}

export class PublicKeyCache {
  private cache: Map<string, CachedPublicKey> = new Map();
  private ttl: number = 3600000; // 1 hour in milliseconds

  /**
   * Add a public key to the cache
   */
  set(
    userId: string,
    publicKey: CryptoKey,
    jwk: JsonWebKey,
    verified: boolean = false
  ): void {
    this.cache.set(userId, {
      userId,
      publicKey,
      jwk,
      timestamp: Date.now(),
      verified,
    });
  }

  /**
   * Get a public key from the cache
   * Returns null if not found or expired
   */
  get(userId: string): CachedPublicKey | null {
    const cached = this.cache.get(userId);
    if (!cached) return null;

    // Check if expired
    if (Date.now() - cached.timestamp > this.ttl) {
      this.cache.delete(userId);
      return null;
    }

    return cached;
  }

  /**
   * Check if a key is cached and not expired
   */
  has(userId: string): boolean {
    return this.get(userId) !== null;
  }

  /**
   * Clear expired entries
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [userId, cached] of this.cache.entries()) {
      if (now - cached.timestamp > this.ttl) {
        this.cache.delete(userId);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Clear all cached keys
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  stats(): { size: number; ttl: number } {
    return {
      size: this.cache.size,
      ttl: this.ttl,
    };
  }
}

// Export global cache instance
export const publicKeyCache = new PublicKeyCache();
