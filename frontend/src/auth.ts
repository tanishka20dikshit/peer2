/**
 * Phase 6.2 Subtask 3 & 4: Registration & Login Flow
 * 
 * Implements user registration and login logic:
 * - Generate RSA-4096 keypairs (encryption + signing)
 * - Encrypt private keys with password
 * - Build USER_REGISTER message
 * - Handle USER_REGISTERED response
 * - Decrypt private keys for login
 * - Build USER_HELLO message
 * - Handle USER_WELCOME response
 */

import {
  generateRSAKeyPair,
  generateRSASigningKeyPair,
  exportPublicKeyJWK,
  exportPublicKeySPKI,     // ← ADD THIS
  exportPrivateKeyJWK,
  importPublicKeyJWK,
  importPrivateKeyJWK,
  rsaOaepEncrypt,
  rsaOaepDecrypt,
  rsaPssSign,
  rsaPssVerify,
  type KeyPair,
} from './crypto';
import {
  encryptPrivateKey,
  decryptPrivateKey,
  serializeEncryptedData,
  deserializeEncryptedData,
  validatePasswordStrength,
  type EncryptedData,
} from './encryption';
import { buildUserRegister, buildUserHello, buildGetUserData, type Envelope } from './protocol';
import { base64urlEncode, generateUUID } from './utils';

// ============================================================================
// Registration Data Structures
// ============================================================================

/**
 * Result of key generation
 */
export interface GeneratedKeys {
  userId: string;
  encryptionKeypair: KeyPair;
  signingKeypair: KeyPair;
  encryptionPubkeyB64: string;   // base64url JWK
  signingPubkeyB64: string;      // base64url JWK
  encryptedEncPrivkey: EncryptedData;
  encryptedSignPrivkey: EncryptedData;
}

/**
 * Registration request data (ready to send to backend)
 */
export interface RegistrationRequest {
  userId: string;
  message: Envelope;  // USER_REGISTER message
  // Keep keypairs for immediate session init after success
  encryptionKeypair: KeyPair;
  signingKeypair: KeyPair;
  encryptionPubkeyB64: string;
  signingPubkeyB64: string;
}

/**
 * Registration response from backend
 */
export interface RegistrationResponse {
  success: boolean;
  sessionId?: string;
  message?: string;
  error?: string;
}

// ============================================================================
// Registration Flow
// ============================================================================

/**
 * Generate keypairs and encrypt private keys with password
 * 
 * Step 1 of registration: Generate cryptographic material
 * This takes 4-6 seconds due to RSA-4096 key generation
 * 
 * @param password - User's password
 * @param userId - Optional user ID (generates UUID if not provided)
 * @returns Promise<GeneratedKeys> - Generated and encrypted keys
 */
export async function generateUserKeys(
  password: string,
  userId?: string
): Promise<GeneratedKeys> {
  // Validate password strength
  const validation = validatePasswordStrength(password);
  if (!validation.valid) {
    throw new Error(`Weak password: ${validation.errors.join(', ')}`);
  }
  
  // Generate user ID if not provided
  const finalUserId = userId || generateUUID();
  
  // Generate encryption keypair (RSA-OAEP for encryption/decryption)
  const encryptionKeypair = await generateRSAKeyPair();
  
  // Generate signing keypair (RSA-PSS for signing/verification)
  const signingKeypair = await generateRSASigningKeyPair();
  
  // Export public keys to SPKI format (DER-encoded, base64url) - BACKEND FORMAT
  const encryptionPubkeyB64 = await exportPublicKeySPKI(encryptionKeypair.publicKey);
  const signingPubkeyB64 = await exportPublicKeySPKI(signingKeypair.publicKey);
  
  // Export private keys to JWK for encryption and storage
  const encPrivJWK = await exportPrivateKeyJWK(encryptionKeypair.privateKey);
  const signPrivJWK = await exportPrivateKeyJWK(signingKeypair.privateKey);
  
  // Encrypt private keys with password
  const encryptedEncPrivkey = await encryptPrivateKey(encPrivJWK, password);
  const encryptedSignPrivkey = await encryptPrivateKey(signPrivJWK, password);
  
  return {
    userId: finalUserId,
    encryptionKeypair,
    signingKeypair,
    encryptionPubkeyB64,
    signingPubkeyB64,
    encryptedEncPrivkey,
    encryptedSignPrivkey,
  };
}

/**
 * Build registration request message
 * 
 * Step 2 of registration: Prepare USER_REGISTER message for backend
 * 
 * @param keys - Generated keys from generateUserKeys()
 * @param password - User's password (sent to backend for PAKE)
 * @param serverId - Target server ID
 * @param meta - Optional user metadata (display_name, etc.)
 * @returns RegistrationRequest - Ready to send to backend
 */
export async function buildRegistrationRequest(
  keys: GeneratedKeys,
  password: string,
  serverId: string,
  meta?: Record<string, any>
): Promise<RegistrationRequest> {
  // Backend expects signing public key in "pubkey" field
  // This is used for signature verification and matches USER_HELLO's pubkey
  const pubkey = keys.signingPubkeyB64;
  
  // Serialize encrypted private keys for storage
  // Backend expects a single "privkey_store" field
  // Store both keys as JSON object
  const privkeyStore = JSON.stringify({
    encryption: serializeEncryptedData(keys.encryptedEncPrivkey),
    signing: serializeEncryptedData(keys.encryptedSignPrivkey),
  });
  
  // Build USER_REGISTER message payload
  const payload = {
    pubkey,  // Signing key
    enc_pubkey: keys.encryptionPubkeyB64,  // Encryption key
    privkey_store: privkeyStore,
    password,
    meta: meta || {},
  };
  
  // Sign the payload (Protocol §7: USER_REGISTER requires signature)
  const payloadJSON = JSON.stringify(payload);
  const signatureBuffer = await rsaPssSign(
    keys.signingKeypair.privateKey,
    new TextEncoder().encode(payloadJSON)
  );
  
  // Convert signature ArrayBuffer to base64url string (Protocol §4)
  const signature = base64urlEncode(signatureBuffer);
  
  // Build the complete message envelope
  const message = buildUserRegister(
    keys.userId,
    serverId,
    pubkey,  // Signing key
    keys.encryptionPubkeyB64,  // Encryption key
    privkeyStore,
    password,
    meta,
    signature
  );
  
  return {
    userId: keys.userId,
    message,
    encryptionKeypair: keys.encryptionKeypair,
    signingKeypair: keys.signingKeypair,
    encryptionPubkeyB64: keys.encryptionPubkeyB64,
    signingPubkeyB64: keys.signingPubkeyB64,
  };
}

/**
 * Complete registration flow (convenience wrapper)
 * 
 * Combines key generation and request building
 * 
 * @param password - User's password
 * @param serverId - Target server ID
 * @param meta - Optional user metadata
 * @param userId - Optional user ID (generates UUID if not provided)
 * @returns Promise<RegistrationRequest> - Ready to send to backend
 */
export async function registerUser(
  password: string,
  serverId: string,
  meta?: Record<string, any>,
  userId?: string
): Promise<RegistrationRequest> {
  // Step 1: Generate keys (passing userId if provided)
  const keys = await generateUserKeys(password, userId);
  
  // Step 2: Build registration message
  const request = await buildRegistrationRequest(keys, password, serverId, meta);
  
  return request;
}

/**
 * Parse USER_REGISTERED response from backend
 * 
 * @param envelope - Response envelope
 * @returns RegistrationResponse - Parsed response
 */
export function parseRegistrationResponse(envelope: Envelope): RegistrationResponse {
  const payload = envelope.payload;
  
  if (payload.status === 'success') {
    return {
      success: true,
      sessionId: payload.session_id,
      message: payload.message || 'Registration successful',
    };
  } else {
    return {
      success: false,
      error: payload.message || payload.detail || 'Registration failed',
    };
  }
}

// ============================================================================
// Registration State Management
// ============================================================================

/**
 * Registration progress callback
 */
export type RegistrationProgressCallback = (stage: string, progress: number) => void;

/**
 * Register user with progress tracking
 * 
 * @param password - User's password
 * @param serverId - Target server ID
 * @param onProgress - Progress callback
 * @param meta - Optional user metadata
 * @param userId - Optional user ID
 * @returns Promise<RegistrationRequest> - Registration request
 */
export async function registerUserWithProgress(
  password: string,
  serverId: string,
  onProgress: RegistrationProgressCallback,
  meta?: Record<string, any>,
  userId?: string
): Promise<RegistrationRequest> {
  // Validate password
  onProgress('Validating password', 0);
  const validation = validatePasswordStrength(password);
  if (!validation.valid) {
    throw new Error(`Weak password: ${validation.errors.join(', ')}`);
  }
  
  // Generate user ID
  onProgress('Generating user ID', 10);
  const finalUserId = userId || generateUUID();
  
  // Generate encryption keypair (slow)
  onProgress('Generating encryption keypair (RSA-4096)', 20);
  const encryptionKeypair = await generateRSAKeyPair();
  
  // Generate signing keypair (slow)
  onProgress('Generating signing keypair (RSA-PSS 4096)', 50);
  const signingKeypair = await generateRSASigningKeyPair();
  
  // Export and encode public keys
  onProgress('Exporting public keys', 80);
  const encPubJWK = await exportPublicKeyJWK(encryptionKeypair.publicKey);
  const signPubJWK = await exportPublicKeyJWK(signingKeypair.publicKey);
  const encPubJSON = JSON.stringify(encPubJWK);
  const signPubJSON = JSON.stringify(signPubJWK);
  const encryptionPubkeyB64 = base64urlEncode(new TextEncoder().encode(encPubJSON));
  const signingPubkeyB64 = base64urlEncode(new TextEncoder().encode(signPubJSON));
  
  // Export and encrypt private keys
  onProgress('Encrypting private keys', 85);
  const encPrivJWK = await exportPrivateKeyJWK(encryptionKeypair.privateKey);
  const signPrivJWK = await exportPrivateKeyJWK(signingKeypair.privateKey);
  const encryptedEncPrivkey = await encryptPrivateKey(encPrivJWK, password);
  const encryptedSignPrivkey = await encryptPrivateKey(signPrivJWK, password);
  
  // Build registration message
  onProgress('Building registration message', 95);
  const keys: GeneratedKeys = {
    userId: finalUserId,
    encryptionKeypair,
    signingKeypair,
    encryptionPubkeyB64,
    signingPubkeyB64,
    encryptedEncPrivkey,
    encryptedSignPrivkey,
  };
  
  const request = await buildRegistrationRequest(keys, password, serverId, meta);
  
  onProgress('Registration ready', 100);
  return request;
}

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate user ID format (must be UUID v4)
 * 
 * @param userId - User ID to validate
 * @returns boolean - True if valid UUID v4
 */
export function isValidUserId(userId: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(userId);
}

/**
 * Validate registration metadata
 * 
 * @param meta - Metadata object
 * @returns { valid: boolean, errors: string[] }
 */
export function validateRegistrationMeta(meta: Record<string, any>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  // Check display_name length
  if ('display_name' in meta && typeof meta.display_name === 'string') {
    if (meta.display_name.length > 100) {
      errors.push('Display name too long (max 100 characters)');
    }
    if (meta.display_name.length === 0) {
      errors.push('Display name cannot be empty');
    }
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
 * Get registration info for debugging
 */
export function getRegistrationInfo(): {
  keyGenerationTime: string;
  encryptionAlgorithm: string;
  signingAlgorithm: string;
} {
  return {
    keyGenerationTime: '4-6 seconds (2 x RSA-4096 keypairs)',
    encryptionAlgorithm: 'RSA-OAEP-4096 (SHA-256)',
    signingAlgorithm: 'RSASSA-PSS-4096 (SHA-256)',
  };
}

// ============================================================================
// Subtask 4: Login Flow
// ============================================================================

/**
 * User data fetched from backend (for login)
 */
export interface UserData {
  userId: string;
  pubkey: string;              // Encryption public key (base64url JWK)
  privkeyStore: string;        // JSON with encrypted keys
  meta?: Record<string, any>;
}

/**
 * Login request data (ready to send to backend)
 */
export interface LoginRequest {
  userId: string;
  message: Envelope;  // USER_HELLO message
  // Keep keypairs for immediate session init after success
  encryptionKeypair: KeyPair;
  signingKeypair: KeyPair;
  encryptionPubkeyB64: string;
  signingPubkeyB64: string;
}

/**
 * Login response from backend
 */
export interface LoginResponse {
  success: boolean;
  serverId?: string;
  message?: string;
  error?: string;
}

/**
 * Decrypt user's private keys from backend storage
 * 
 * Step 1 of login: Decrypt the privkey_store from backend
 * 
 * @param privkeyStore - Encrypted private keys from backend (JSON string)
 * @param password - User's password
 * @returns Promise<{encryption: KeyPair, signing: KeyPair}> - Decrypted keypairs
 */
export async function decryptUserKeys(
  privkeyStore: string,
  password: string
): Promise<{ encryption: KeyPair; signing: KeyPair }> {
  // Parse privkey_store JSON
  let privkeyData: {
    encryption: string;
    signing: string;
  };
  
  try {
    privkeyData = JSON.parse(privkeyStore);
  } catch (error) {
    throw new Error("Invalid privkey_store format");
  }
  
  // Deserialize encrypted data
  const encryptedEncPrivkey = deserializeEncryptedData(privkeyData.encryption);
  const encryptedSignPrivkey = deserializeEncryptedData(privkeyData.signing);
  
  // Decrypt both private keys
  const encPrivJWK = await decryptPrivateKey(encryptedEncPrivkey, password);
  const signPrivJWK = await decryptPrivateKey(encryptedSignPrivkey, password);
  
  // Import private keys
  const encPrivKey = await importPrivateKeyJWK(encPrivJWK, ["decrypt"]);
  const signPrivKey = await importPrivateKeyJWK(signPrivJWK, ["sign"]);
  
  // Get public keys from JWKs (they're embedded in private key JWKs)
  const encPubKey = await importPublicKeyJWK(
    { kty: encPrivJWK.kty, n: encPrivJWK.n, e: encPrivJWK.e } as JsonWebKey,
    ["encrypt"]
  );
  const signPubKey = await importPublicKeyJWK(
    { kty: signPrivJWK.kty, n: signPrivJWK.n, e: signPrivJWK.e } as JsonWebKey,
    ["verify"]
  );
  
  return {
    encryption: {
      publicKey: encPubKey,
      privateKey: encPrivKey,
    },
    signing: {
      publicKey: signPubKey,
      privateKey: signPrivKey,
    },
  };
}

/**
 * Build USER_HELLO message for login
 * 
 * Step 2 of login: Prepare USER_HELLO message for backend
 * 
 * @param userId - User's ID
 * @param serverId - Target server ID
 * @param encryptionPubkeyB64 - Encryption public key (base64url)
 * @param signingPubkeyB64 - Signing public key (base64url)
 * @param meta - Optional user metadata
 * @returns Envelope - USER_HELLO message
 */
export function buildLoginHello(
  userId: string,
  serverId: string,
  encryptionPubkeyB64: string,
  signingPubkeyB64: string,
  meta?: Record<string, any>
): Envelope {
  // Use buildUserHello from protocol.ts
  // Backend expects "pubkey" (signing) and "enc_pubkey" (encryption)
  return buildUserHello(
    userId,
    serverId,
    signingPubkeyB64,    // pubkey - for signature verification
    encryptionPubkeyB64,  // enc_pubkey - for encryption
    meta
  );
}

/**
 * Complete login flow (with pre-fetched user data)
 * 
 * This function assumes user data has already been fetched from backend.
 * In a full implementation, this would be called after successful password
 * verification with the backend.
 * 
 * @param userData - User data from backend
 * @param password - User's password
 * @param serverId - Target server ID
 * @returns Promise<LoginRequest> - Ready to send USER_HELLO
 */
export async function loginUser(
  userData: UserData,
  password: string,
  serverId: string
): Promise<LoginRequest> {
  // Step 1: Decrypt private keys
  const keypairs = await decryptUserKeys(userData.privkeyStore, password);
  
  // Step 2: Export public keys to SPKI format (same as registration)
  const encryptionPubkeyB64 = await exportPublicKeySPKI(keypairs.encryption.publicKey);
  const signingPubkeyB64 = await exportPublicKeySPKI(keypairs.signing.publicKey);
  
  // Step 3: Build USER_HELLO message
  const message = buildLoginHello(
    userData.userId,
    serverId,
    encryptionPubkeyB64,
    signingPubkeyB64,
    userData.meta
  );
  
  return {
    userId: userData.userId,
    message,
    encryptionKeypair: keypairs.encryption,
    signingKeypair: keypairs.signing,
    encryptionPubkeyB64,
    signingPubkeyB64,
  };
}

/**
 * Parse USER_WELCOME response from backend
 * 
 * @param envelope - Response envelope
 * @returns LoginResponse - Parsed response
 */
export function parseLoginResponse(envelope: Envelope): LoginResponse {
  const payload = envelope.payload;
  
  if (envelope.type === "USER_WELCOME") {
    return {
      success: true,
      serverId: envelope.from,
      message: "Login successful",
    };
  } else if (envelope.type === "ERROR") {
    return {
      success: false,
      error: payload.detail || payload.message || "Login failed",
    };
  } else {
    return {
      success: false,
      error: `Unexpected response type: ${envelope.type}`,
    };
  }
}

/**
 * Login with progress tracking
 * 
 * @param userData - User data from backend
 * @param password - User's password
 * @param serverId - Target server ID
 * @param onProgress - Progress callback
 * @returns Promise<LoginRequest> - Login request
 */
export async function loginUserWithProgress(
  userData: UserData,
  password: string,
  serverId: string,
  onProgress: RegistrationProgressCallback
): Promise<LoginRequest> {
  onProgress("Validating password", 0);
  
  onProgress("Decrypting private keys", 20);
  const keypairs = await decryptUserKeys(userData.privkeyStore, password);
  
  onProgress("Preparing public keys", 60);
  const encPubJWK = await exportPublicKeyJWK(keypairs.encryption.publicKey);
  const signPubJWK = await exportPublicKeyJWK(keypairs.signing.publicKey);
  
  const encPubJSON = JSON.stringify(encPubJWK);
  const signPubJSON = JSON.stringify(signPubJWK);
  
  const encryptionPubkeyB64 = base64urlEncode(new TextEncoder().encode(encPubJSON));
  const signingPubkeyB64 = base64urlEncode(new TextEncoder().encode(signPubJSON));
  
  onProgress("Building USER_HELLO message", 80);
  const message = buildLoginHello(
    userData.userId,
    serverId,
    encryptionPubkeyB64,
    signingPubkeyB64,
    userData.meta
  );
  
  onProgress("Login ready", 100);
  
  return {
    userId: userData.userId,
    message,
    encryptionKeypair: keypairs.encryption,
    signingKeypair: keypairs.signing,
    encryptionPubkeyB64,
    signingPubkeyB64,
  };
}

// ============================================================================
// Login Utilities
// ============================================================================

/**
 * Verify decrypted keys work correctly
 * 
 * @param keypairs - Decrypted keypairs
 * @returns Promise<boolean> - True if keys work
 */
export async function verifyDecryptedKeys(keypairs: {
  encryption: KeyPair;
  signing: KeyPair;
}): Promise<boolean> {
  try {
    // Test encryption keypair
    const testData = new TextEncoder().encode("Test message");
    const ciphertext = await rsaOaepEncrypt(keypairs.encryption.publicKey, testData);
    const decrypted = await rsaOaepDecrypt(keypairs.encryption.privateKey, ciphertext);
    const decryptedText = new TextDecoder().decode(decrypted);
    
    if (decryptedText !== "Test message") {
      return false;
    }
    
    // Test signing keypair
    const testSignData = new TextEncoder().encode("Sign this");
    const signature = await rsaPssSign(keypairs.signing.privateKey, testSignData);
    const verified = await rsaPssVerify(
      keypairs.signing.publicKey,
      signature,
      testSignData
    );
    
    return verified;
  } catch (error) {
    return false;
  }
}

/**
 * Get login info for debugging
 */
export function getLoginInfo(): {
  decryptionTime: string;
  authenticationMethod: string;
} {
  return {
    decryptionTime: "~100ms (PBKDF2 + AES-256-GCM decryption)",
    authenticationMethod: "Password-based private key decryption",
  };
}

/**
 * Fetch user data from backend via WebSocket
 * 
 * @param userId - User ID
 * @param wsClient - WebSocket client instance
 * @param serverId - Server ID (default: "*")
 * @returns Promise<UserData> - User data from backend
 */
export async function fetchUserData(
  userId: string,
  wsClient: any,
  serverId: string = "*"
): Promise<UserData> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      wsClient.off("USER_DATA_RESPONSE", handler);
      reject(new Error("Timeout waiting for user data"));
    }, 10000); // 10 second timeout
    
    // Set up one-time handler for USER_DATA_RESPONSE
    const handler = (envelope: any) => {
      if (envelope.type === "USER_DATA_RESPONSE" && envelope.to === userId) {
        clearTimeout(timeout);
        wsClient.off("USER_DATA_RESPONSE", handler);
        
        const payload = envelope.payload;
        resolve({
          userId: payload.user_id,
          pubkey: payload.pubkey,
          privkeyStore: payload.privkey_store,
          meta: payload.meta || {}
        });
      }
    };
    
    // Register handler
    wsClient.on("USER_DATA_RESPONSE", handler);
    
    // Send GET_USER_DATA request
    const message = buildGetUserData(userId, serverId);
    wsClient.send(message);
  });
}
