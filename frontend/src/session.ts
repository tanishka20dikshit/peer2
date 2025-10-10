/**
 * Phase 6.2: Session State Management
 * 
 * Manages user session state including:
 * - User identity (user_id, server_id)
 * - Cryptographic keys (encryption + signing keypairs)
 * - Public channel key (for /all broadcasts)
 * - Connection status
 * 
 * Storage: sessionStorage (cleared on browser close, not localStorage)
 */

import type { KeyPair } from './crypto';
import { 
  exportPublicKeyJWK, 
  exportPrivateKeyJWK,
  importPublicKeyJWK,
  importPrivateKeyJWK 
} from './crypto';

// ============================================================================
// Session Data Interface
// ============================================================================

export interface SessionData {
  userId: string;                    // UUID v4
  serverId: string;                  // Connected server ID
  
  // User's public keys (base64url for protocol messages)
  encryptionPubkeyB64: string;       // For receiving encrypted messages
  signingPubkeyB64: string;          // For signature verification
  
  // Metadata
  displayName?: string;
  meta?: Record<string, any>;
  
  // Connection state
  connected: boolean;
  connectedAt?: number;              // Timestamp
  
  // Public channel
  hasPublicChannelKey: boolean;      // True when channel key received
  publicChannelKeyReceived?: number; // Timestamp when received
}

export interface KeyPairStorage {
  encryption: KeyPair;  // RSA-OAEP for encryption/decryption
  signing: KeyPair;     // RSA-PSS for signing/verification
}

// ============================================================================
// Session Manager
// ============================================================================

export class SessionManager {
  private sessionData: SessionData | null = null;
  private keypairs: KeyPairStorage | null = null;
  private publicChannelKey: CryptoKey | null = null;
  
  // Storage keys
  private readonly SESSION_DATA_KEY = 'socp_session_data';
  private readonly SESSION_ACTIVE_KEY = 'socp_session_active';
  
  constructor() {
    // Note: CryptoKeys cannot be stored directly in sessionStorage
    // They must be kept in memory during the session
  }
  
  // ==========================================================================
  // Session Initialization
  // ==========================================================================
  
  /**
   * Initialize a new session after successful login/registration
   * 
   * @param userId - User's UUID
   * @param serverId - Connected server ID
   * @param keypairs - User's encryption and signing keypairs
   * @param encryptionPubkeyB64 - Public encryption key (base64url)
   * @param signingPubkeyB64 - Public signing key (base64url)
   * @param meta - Optional user metadata
   */
  initSession(
    userId: string,
    serverId: string,
    keypairs: KeyPairStorage,
    encryptionPubkeyB64: string,
    signingPubkeyB64: string,
    meta?: Record<string, any>
  ): void {
    this.sessionData = {
      userId,
      serverId,
      encryptionPubkeyB64,
      signingPubkeyB64,
      displayName: meta?.display_name,
      meta,
      connected: true,
      connectedAt: Date.now(),
      hasPublicChannelKey: false,
    };
    
    this.keypairs = keypairs;
    
    // Store session data (excluding keys)
    this.persistSessionData();
    
    // Mark session as active
    sessionStorage.setItem(this.SESSION_ACTIVE_KEY, 'true');
  }
  
  /**
   * Restore session from sessionStorage (on page reload)
   * Note: Keypairs must be re-provided as they cannot be serialized
   * 
   * @returns SessionData if exists, null otherwise
   */
  restoreSessionData(): SessionData | null {
    const stored = sessionStorage.getItem(this.SESSION_DATA_KEY);
    const isActive = sessionStorage.getItem(this.SESSION_ACTIVE_KEY);
    
    if (!stored || isActive !== 'true') {
      return null;
    }
    
    try {
      this.sessionData = JSON.parse(stored);
      return this.sessionData;
    } catch (error) {
      console.error('Failed to restore session:', error);
      return null;
    }
  }
  
  /**
   * Set keypairs (used when restoring session after page reload)
   * User must decrypt private keys again with password
   */
  setKeypairs(keypairs: KeyPairStorage): void {
    this.keypairs = keypairs;
  }
  
  // ==========================================================================
  // Session State Access
  // ==========================================================================
  
  /**
   * Check if user is logged in
   */
  isLoggedIn(): boolean {
    return this.sessionData !== null && this.sessionData.connected;
  }
  
  /**
   * Get current session data
   */
  getSession(): SessionData | null {
    return this.sessionData;
  }
  
  /**
   * Get user ID
   */
  getUserId(): string | null {
    return this.sessionData?.userId || null;
  }
  
  /**
   * Get server ID
   */
  getServerId(): string | null {
    return this.sessionData?.serverId || null;
  }
  
  /**
   * Get display name (fallback to user ID)
   */
  getDisplayName(): string {
    if (this.sessionData?.displayName) {
      return this.sessionData.displayName;
    }
    return this.sessionData?.userId || 'Unknown User';
  }
  
  /**
   * Get encryption keypair
   */
  getEncryptionKeypair(): KeyPair | null {
    return this.keypairs?.encryption || null;
  }
  
  /**
   * Get signing keypair
   */
  getSigningKeypair(): KeyPair | null {
    return this.keypairs?.signing || null;
  }
  
  /**
   * Get encryption public key (base64url)
   */
  getEncryptionPubkeyB64(): string | null {
    return this.sessionData?.encryptionPubkeyB64 || null;
  }
  
  /**
   * Get signing public key (base64url)
   */
  getSigningPubkeyB64(): string | null {
    return this.sessionData?.signingPubkeyB64 || null;
  }
  
  // ==========================================================================
  // Public Channel Key Management
  // ==========================================================================
  
  /**
   * Set public channel key (received from server via PUBLIC_CHANNEL_KEY_SHARE)
   * 
   * @param channelKey - Decrypted public channel key
   */
  setPublicChannelKey(channelKey: CryptoKey): void {
    this.publicChannelKey = channelKey;
    
    if (this.sessionData) {
      this.sessionData.hasPublicChannelKey = true;
      this.sessionData.publicChannelKeyReceived = Date.now();
      this.persistSessionData();
    }
  }
  
  /**
   * Get public channel key
   */
  getPublicChannelKey(): CryptoKey | null {
    return this.publicChannelKey;
  }
  
  /**
   * Check if public channel key is available
   */
  hasPublicChannelKey(): boolean {
    return this.publicChannelKey !== null;
  }
  
  // ==========================================================================
  // Connection State
  // ==========================================================================
  
  /**
   * Update connection status
   */
  setConnected(connected: boolean): void {
    if (this.sessionData) {
      this.sessionData.connected = connected;
      this.persistSessionData();
    }
  }
  
  /**
   * Check if currently connected
   */
  isConnected(): boolean {
    return this.sessionData?.connected || false;
  }
  
  // ==========================================================================
  // Session Persistence
  // ==========================================================================
  
  /**
   * Save session data to sessionStorage
   * (Does not store CryptoKeys - those remain in memory only)
   */
  private persistSessionData(): void {
    if (this.sessionData) {
      sessionStorage.setItem(
        this.SESSION_DATA_KEY,
        JSON.stringify(this.sessionData)
      );
    }
  }
  
  /**
   * Clear session (logout)
   */
  clearSession(): void {
    this.sessionData = null;
    this.keypairs = null;
    this.publicChannelKey = null;
    
    sessionStorage.removeItem(this.SESSION_DATA_KEY);
    sessionStorage.removeItem(this.SESSION_ACTIVE_KEY);
  }
  
  // ==========================================================================
  // Session Info (for debugging)
  // ==========================================================================
  
  /**
   * Get session statistics
   */
  getSessionStats(): {
    isLoggedIn: boolean;
    userId: string | null;
    serverId: string | null;
    connected: boolean;
    hasKeys: boolean;
    hasChannelKey: boolean;
    sessionDuration?: number;
  } {
    return {
      isLoggedIn: this.isLoggedIn(),
      userId: this.getUserId(),
      serverId: this.getServerId(),
      connected: this.isConnected(),
      hasKeys: this.keypairs !== null,
      hasChannelKey: this.hasPublicChannelKey(),
      sessionDuration: this.sessionData?.connectedAt 
        ? Date.now() - this.sessionData.connectedAt 
        : undefined,
    };
  }
  
  /**
   * Export session info as JSON (for debugging)
   */
  toJSON(): any {
    return {
      session: this.sessionData,
      stats: this.getSessionStats(),
    };
  }
}

// Export singleton instance
export const sessionManager = new SessionManager();