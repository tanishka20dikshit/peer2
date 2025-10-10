/**
 * Phase 6.2 Subtask 2: Password-Based Key Encryption
 * 
 * Implements PBKDF2 key derivation and AES-256-GCM encryption
 * for secure private key storage matching backend's system.
 * 
 * Backend compatibility:
 * - PBKDF2 with SHA-256
 * - 100,000 iterations (matches backend/db.py)
 * - 32-byte salt
 * - AES-256-GCM for private key encryption
 */

import { base64urlEncode, base64urlDecode, stringToBytes, bytesToString } from './utils';

// ============================================================================
// Constants
// ============================================================================

export const PBKDF2_ITERATIONS = 100000;  // Match backend (backend/db.py:63)
export const PBKDF2_HASH = "SHA-256";
export const SALT_LENGTH = 32;           // 32 bytes = 256 bits
export const AES_KEY_LENGTH = 256;       // AES-256
export const AES_IV_LENGTH = 12;         // GCM standard IV length

// ============================================================================
// PBKDF2 Key Derivation
// ============================================================================

/**
 * Derive an AES-256 key from password using PBKDF2
 * 
 * Matches backend implementation:
 * - backend/db.py:63: hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
 * 
 * @param password - User password
 * @param salt - Random salt (32 bytes)
 * @returns Promise<CryptoKey> - Derived AES-256 key
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  // Convert password to bytes
  const passwordBytes = stringToBytes(password);
  
  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  // Derive AES-256-GCM key using PBKDF2
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: AES_KEY_LENGTH,
    },
    false, // not extractable (security best practice)
    ["encrypt", "decrypt"]
  );
  
  return derivedKey;
}

/**
 * Generate a random salt for PBKDF2
 * 
 * @returns Uint8Array - Random 32-byte salt
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

// ============================================================================
// AES-256-GCM Encryption/Decryption
// ============================================================================

/**
 * Encrypted data structure
 */
export interface EncryptedData {
  ciphertext: string;    // base64url encoded
  iv: string;            // base64url encoded (12 bytes)
  salt: string;          // base64url encoded (32 bytes)
  tag?: string;          // GCM auth tag (included in ciphertext by Web Crypto API)
}

/**
 * Encrypt data with password-derived AES-256-GCM key
 * 
 * @param plaintext - Data to encrypt (as string)
 * @param password - User password
 * @returns Promise<EncryptedData> - Encrypted data with salt and IV
 */
export async function encryptWithPassword(
  plaintext: string,
  password: string
): Promise<EncryptedData> {
  // Generate random salt and IV
  const salt = generateSalt();
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
  
  // Derive encryption key from password
  const key = await deriveKeyFromPassword(password, salt);
  
  // Convert plaintext to bytes
  const plaintextBytes = stringToBytes(plaintext);
  
  // Encrypt with AES-256-GCM
  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    plaintextBytes
  );
  
  // Return encrypted data with metadata
  return {
    ciphertext: base64urlEncode(ciphertextBuffer),
    iv: base64urlEncode(iv.buffer),
    salt: base64urlEncode(salt.buffer),
  };
}

/**
 * Decrypt data encrypted with password-derived AES-256-GCM key
 * 
 * @param encrypted - Encrypted data structure
 * @param password - User password
 * @returns Promise<string> - Decrypted plaintext
 * @throws Error if decryption fails (wrong password or corrupted data)
 */
export async function decryptWithPassword(
  encrypted: EncryptedData,
  password: string
): Promise<string> {
  // Decode base64url components
  const salt = new Uint8Array(base64urlDecode(encrypted.salt));
  const iv = new Uint8Array(base64urlDecode(encrypted.iv));
  const ciphertextBytes = base64urlDecode(encrypted.ciphertext);
  
  // Derive decryption key from password
  const key = await deriveKeyFromPassword(password, salt);
  
  try {
    // Decrypt with AES-256-GCM
    const plaintextBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      ciphertextBytes
    );
    
    // Convert bytes back to string
    return bytesToString(new Uint8Array(plaintextBuffer));
  } catch (error) {
    throw new Error("Decryption failed: incorrect password or corrupted data");
  }
}

// ============================================================================
// Private Key Encryption/Decryption (High-level API)
// ============================================================================

/**
 * Encrypt RSA private key (JWK format) with password
 * 
 * This is used during registration to store encrypted private keys
 * in the backend database (users.privkey_store field).
 * 
 * @param privateKeyJWK - Private key in JWK format
 * @param password - User password
 * @returns Promise<EncryptedData> - Encrypted private key
 */
export async function encryptPrivateKey(
  privateKeyJWK: JsonWebKey,
  password: string
): Promise<EncryptedData> {
  // Serialize JWK to JSON string
  const jwkString = JSON.stringify(privateKeyJWK);
  
  // Encrypt with password
  return await encryptWithPassword(jwkString, password);
}

/**
 * Decrypt RSA private key from encrypted storage
 * 
 * This is used during login to recover private keys from
 * the backend database.
 * 
 * @param encrypted - Encrypted private key data
 * @param password - User password
 * @returns Promise<JsonWebKey> - Decrypted private key in JWK format
 * @throws Error if decryption fails
 */
export async function decryptPrivateKey(
  encrypted: EncryptedData,
  password: string
): Promise<JsonWebKey> {
  // Decrypt to JSON string
  const jwkString = await decryptWithPassword(encrypted, password);
  
  // Parse JWK
  try {
    return JSON.parse(jwkString);
  } catch (error) {
    throw new Error("Invalid JWK format after decryption");
  }
}

// ============================================================================
// Serialization Helpers (for storage)
// ============================================================================

/**
 * Serialize EncryptedData to JSON string for storage
 * 
 * @param encrypted - Encrypted data
 * @returns string - JSON string
 */
export function serializeEncryptedData(encrypted: EncryptedData): string {
  return JSON.stringify(encrypted);
}

/**
 * Deserialize EncryptedData from JSON string
 * 
 * @param serialized - JSON string
 * @returns EncryptedData - Parsed encrypted data
 */
export function deserializeEncryptedData(serialized: string): EncryptedData {
  return JSON.parse(serialized);
}

// ============================================================================
// Password Validation
// ============================================================================

/**
 * Validate password strength
 * 
 * Requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * 
 * @param password - Password to validate
 * @returns { valid: boolean, errors: string[] } - Validation result
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push("Password must be at least 8 characters");
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number");
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
}

// ============================================================================
// Testing/Debug Utilities
// ============================================================================

/**
 * Test encryption/decryption round-trip
 * Used for validation during testing
 * 
 * @param plaintext - Test data
 * @param password - Test password
 * @returns Promise<boolean> - True if round-trip successful
 */
export async function testEncryptionRoundTrip(
  plaintext: string,
  password: string
): Promise<boolean> {
  try {
    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPassword(encrypted, password);
    return plaintext === decrypted;
  } catch (error) {
    return false;
  }
}

/**
 * Get encryption info for debugging
 */
export function getEncryptionInfo(): {
  algorithm: string;
  keyDerivation: string;
  iterations: number;
  saltLength: number;
  ivLength: number;
} {
  return {
    algorithm: "AES-256-GCM",
    keyDerivation: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    saltLength: SALT_LENGTH,
    ivLength: AES_IV_LENGTH,
  };
}
