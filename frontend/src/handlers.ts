/**
 * Phase 6.2 Subtask 5: Message Handler Integration
 *
 * Central message handlers that wire WebSocket responses to application state.
 * This is the "glue" layer connecting:
 * - WebSocket client (websocket.ts) - receives messages
 * - Auth functions (auth.ts) - registration/login logic
 * - Session manager (session.ts) - state storage
 * - Protocol (protocol.ts) - message builders
 */

import { Envelope, parseError } from "./protocol";
import { SessionManager } from "./session";
import { parseRegistrationResponse, parseLoginResponse } from "./auth";
import { rsaOaepDecrypt, importPublicKeyJWK } from "./crypto";
import { base64urlDecode, base64urlEncode } from "./utils";

// ============================================================================
// Handler Callback Types
// ============================================================================

/**
 * Callback invoked when registration completes successfully
 */
export type RegistrationSuccessCallback = (
  userId: string,
  serverId: string
) => void;

/**
 * Callback invoked when registration fails
 */
export type RegistrationErrorCallback = (error: string) => void;

/**
 * Callback invoked when login completes successfully
 */
export type LoginSuccessCallback = (userId: string, serverId: string) => void;

/**
 * Callback invoked when login fails
 */
export type LoginErrorCallback = (error: string) => void;

/**
 * Callback invoked when public channel key is received
 */
export type PublicChannelKeyCallback = (channelKey: CryptoKey) => void;

/**
 * Callback invoked on general errors
 */
export type ErrorCallback = (code: string, detail: string) => void;

// ============================================================================
// Message Handler Registry
// ============================================================================

export class MessageHandlerRegistry {
  private sessionManager: SessionManager;
  private getEncryptionKeypairFn?: () => {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null;
  private getSigningKeypairFn?: () => {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null;

  // Callback storage
  private registrationSuccessCallbacks: RegistrationSuccessCallback[] = [];
  private registrationErrorCallbacks: RegistrationErrorCallback[] = [];
  private loginSuccessCallbacks: LoginSuccessCallback[] = [];
  private loginErrorCallbacks: LoginErrorCallback[] = [];
  private publicChannelKeyCallbacks: PublicChannelKeyCallback[] = [];
  private errorCallbacks: ErrorCallback[] = [];

  constructor(
    sessionManager: SessionManager,
    getEncryptionKeypair?: () => {
      publicKey: CryptoKey;
      privateKey: CryptoKey;
    } | null,
    getSigningKeypair?: () => {
      publicKey: CryptoKey;
      privateKey: CryptoKey;
    } | null
  ) {
    this.sessionManager = sessionManager;
    this.getEncryptionKeypairFn = getEncryptionKeypair;
    this.getSigningKeypairFn = getSigningKeypair;
  }

  // ==========================================================================
  // Callback Registration
  // ==========================================================================

  /**
   * Register callback for successful registration
   */
  onRegistrationSuccess(callback: RegistrationSuccessCallback): void {
    this.registrationSuccessCallbacks.push(callback);
  }

  /**
   * Register callback for registration errors
   */
  onRegistrationError(callback: RegistrationErrorCallback): void {
    this.registrationErrorCallbacks.push(callback);
  }

  /**
   * Register callback for successful login
   */
  onLoginSuccess(callback: LoginSuccessCallback): void {
    this.loginSuccessCallbacks.push(callback);
  }

  /**
   * Register callback for login errors
   */
  onLoginError(callback: LoginErrorCallback): void {
    this.loginErrorCallbacks.push(callback);
  }

  /**
   * Register callback for public channel key received
   */
  onPublicChannelKey(callback: PublicChannelKeyCallback): void {
    this.publicChannelKeyCallbacks.push(callback);
  }

  /**
   * Register callback for general errors
   */
  onError(callback: ErrorCallback): void {
    this.errorCallbacks.push(callback);
  }

  // ==========================================================================
  // Message Handlers
  // ==========================================================================

  /**
   * Handle USER_REGISTERED response (after registration)
   * Protocol: Custom backend message
   */
  async handleUserRegistered(envelope: Envelope): Promise<void> {
    console.log("[Handlers] ===== USER_REGISTERED RECEIVED =====");
    console.log("[Handlers] Full envelope:", JSON.stringify(envelope, null, 2));
    console.log("[Handlers] Envelope type:", envelope.type);
    console.log("[Handlers] From:", envelope.from);
    console.log("[Handlers] To:", envelope.to);
    console.log("[Handlers] Payload:", envelope.payload);

    try {
      const response = parseRegistrationResponse(envelope);
      console.log("[Handlers] Parsed response:", response);

      if (response.success) {
        const serverId = envelope.from;
        const userId = envelope.to;

        console.log(`[Handlers] ✅ Registration successful for user ${userId}`);
        console.log(
          "[Handlers] Calling",
          this.registrationSuccessCallbacks.length,
          "success callbacks"
        );

        // Trigger success callbacks
        this.registrationSuccessCallbacks.forEach((cb, index) => {
          try {
            console.log(`[Handlers] Calling success callback ${index + 1}`);
            cb(userId, serverId);
          } catch (error) {
            console.error(
              "[Handlers] Registration success callback error:",
              error
            );
          }
        });
      } else {
        console.error("[Handlers] ❌ Registration failed:", response.error);
        console.log(
          "[Handlers] Calling",
          this.registrationErrorCallbacks.length,
          "error callbacks"
        );

        // Trigger error callbacks
        this.registrationErrorCallbacks.forEach((cb, index) => {
          try {
            console.log(`[Handlers] Calling error callback ${index + 1}`);
            cb(response.error || "Registration failed");
          } catch (error) {
            console.error(
              "[Handlers] Registration error callback error:",
              error
            );
          }
        });
      }
    } catch (error) {
      console.error("[Handlers] ❌ Error handling USER_REGISTERED:", error);
      this.registrationErrorCallbacks.forEach((cb) =>
        cb("Failed to process registration response")
      );
    }
  }

  /**
   * Handle USER_WELCOME response (after login/hello)
   * Protocol §9.1: Server response to USER_HELLO
   */
  async handleUserWelcome(envelope: Envelope): Promise<void> {
    console.log("[Handlers] USER_WELCOME received:", envelope);

    try {
      const response = parseLoginResponse(envelope);

      if (response.success && response.serverId) {
        const userId = envelope.to;
        const serverId = response.serverId;

        console.log(
          `[Handlers] Login successful for user ${userId} on server ${serverId}`
        );

        // Update session connection status
        this.sessionManager.setConnected(true);

        // Trigger success callbacks
        this.loginSuccessCallbacks.forEach((cb) => {
          try {
            cb(userId, serverId);
          } catch (error) {
            console.error("[Handlers] Login success callback error:", error);
          }
        });
      } else {
        console.error("[Handlers] Login failed:", response.error);

        // Trigger error callbacks
        this.loginErrorCallbacks.forEach((cb) => {
          try {
            cb(response.error || "Login failed");
          } catch (error) {
            console.error("[Handlers] Login error callback error:", error);
          }
        });
      }
    } catch (error) {
      console.error("[Handlers] Error handling USER_WELCOME:", error);
      this.loginErrorCallbacks.forEach((cb) =>
        cb("Failed to process login response")
      );
    }
  }

  /**
   * Handle PUBLIC_CHANNEL_KEY_DELIVERY message
   * Backend sends this after USER_HELLO (Protocol §9.3)
   *
   * Message format from backend (public_channel.py:353):
   * {
   *   "type": "PUBLIC_CHANNEL_KEY_DELIVERY",
   *   "from": "server_id",
   *   "to": "user_id",
   *   "payload": {
   *     "shares": [
   *       {
   *         "member": "user_id",
   *         "wrapped_public_channel_key": "<base64url RSA-OAEP encrypted channel key>"
   *       }
   *     ],
   *     "creator_pub": "<base64url server public key>",
   *     "content_sig": "<base64url signature>"
   *   }
   * }
   */
  async handlePublicChannelKeyDelivery(envelope: Envelope): Promise<void> {
    console.log("[Handlers] PUBLIC_CHANNEL_KEY_DELIVERY received");
    console.log("[Handlers] Full envelope:", JSON.stringify(envelope, null, 2));

    try {
      const payload = envelope.payload;
      const shares = payload.shares;
      const creatorPub = payload.creator_pub;
      const contentSig = payload.content_sig;

      if (!shares || !Array.isArray(shares) || shares.length === 0) {
        throw new Error("Missing or empty shares array in payload");
      }

      // Find the share for this user
      const userId = this.sessionManager.getUserId();
      const userShare = shares.find((share: any) => share.member === userId);

      if (!userShare) {
        throw new Error(`No share found for user ${userId}`);
      }

      const wrappedKey = userShare.wrapped_public_channel_key;

      if (!wrappedKey) {
        throw new Error("Missing wrapped_public_channel_key in share");
      }

      console.log("[Handlers] Found wrapped key for user:", userId);

      // Get user's encryption private key - try callback first, then session
      let encryptionKeypair = this.getEncryptionKeypairFn?.();

      if (!encryptionKeypair) {
        // Fallback to session manager
        encryptionKeypair = this.sessionManager.getEncryptionKeypair();
      }

      if (!encryptionKeypair) {
        throw new Error(
          "No encryption keypair available - cannot decrypt channel key"
        );
      }

      // Decrypt wrapped channel key with user's RSA private key
      console.log("[Handlers] Decrypting public channel key...");
      const wrappedKeyBytes = base64urlDecode(wrappedKey);
      const channelKeyBytes = await rsaOaepDecrypt(
        encryptionKeypair.privateKey,
        wrappedKeyBytes
      );

      // The channel key is a 32-byte AES-256 symmetric key (not an RSA key!)
      // Import it as an AES-GCM key for encrypting/decrypting public channel messages
      if (channelKeyBytes.byteLength !== 32) {
        throw new Error(
          `Expected 32-byte AES key, got ${channelKeyBytes.byteLength} bytes`
        );
      }

      const channelKey = await window.crypto.subtle.importKey(
        "raw",
        channelKeyBytes,
        { name: "AES-GCM" },
        false, // not extractable
        ["encrypt", "decrypt"]
      );

      console.log("[Handlers] Public channel AES key decrypted successfully");

      // Store in session manager
      this.sessionManager.setPublicChannelKey(channelKey);

      // Trigger callbacks
      this.publicChannelKeyCallbacks.forEach((cb) => {
        try {
          cb(channelKey);
        } catch (error) {
          console.error("[Handlers] Public channel key callback error:", error);
        }
      });

      console.log(
        "[Handlers] ✅ Public channel key ready - /all command enabled"
      );
    } catch (error) {
      console.error(
        "[Handlers] Error handling PUBLIC_CHANNEL_KEY_DELIVERY:",
        error
      );
      throw error;
    }
  }

  /**
   * Handle ERROR messages from server
   * Protocol §9.5: Standardized error responses
   */
  async handleError(envelope: Envelope): Promise<void> {
    console.error("[Handlers] ERROR received:", envelope);

    try {
      const error = parseError(envelope);
      console.error(
        `[Handlers] Error code: ${error.code}, detail: ${error.detail}`
      );

      // Trigger error callbacks
      this.errorCallbacks.forEach((cb) => {
        try {
          cb(error.code, error.detail);
        } catch (err) {
          console.error("[Handlers] Error callback error:", err);
        }
      });

      // Handle specific error codes
      switch (error.code) {
        case "NAME_IN_USE":
          this.registrationErrorCallbacks.forEach((cb) =>
            cb("Username already in use")
          );
          break;
        case "BAD_KEY":
          this.loginErrorCallbacks.forEach((cb) =>
            cb("Invalid encryption key")
          );
          break;
        case "INVALID_SIG":
          this.loginErrorCallbacks.forEach((cb) =>
            cb("Signature verification failed")
          );
          break;
      }
    } catch (err) {
      console.error("[Handlers] Error parsing ERROR message:", err);
    }
  }

  /**
   * Handle USER_ADVERTISE (presence notification)
   * Protocol §8.2: User joined network
   */
  async handleUserAdvertise(envelope: Envelope): Promise<void> {
    console.log("[Handlers] USER_ADVERTISE received:", envelope.payload);
    // TODO: Update user list in UI (Phase 6.3)
    // For now, just log it
  }

  /**
   * Handle USER_REMOVE (presence notification)
   * Protocol §8.2: User left network
   */
  async handleUserRemove(envelope: Envelope): Promise<void> {
    console.log("[Handlers] USER_REMOVE received:", envelope.payload);
    // TODO: Update user list in UI (Phase 6.3)
    // For now, just log it
  }

  // ==========================================================================
  // Handler Routing
  // ==========================================================================

  /**
   * Route incoming message to appropriate handler
   *
   * @param envelope - Incoming message envelope
   */
  async routeMessage(envelope: Envelope): Promise<void> {
    console.log(`[Handlers] ===== ROUTING MESSAGE =====`);
    console.log(`[Handlers] Message type: ${envelope.type}`);
    console.log(`[Handlers] From: ${envelope.from}`);
    console.log(`[Handlers] To: ${envelope.to}`);

    try {
      switch (envelope.type) {
        case "USER_REGISTERED":
          console.log("[Handlers] → Calling handleUserRegistered");
          await this.handleUserRegistered(envelope);
          break;

        case "USER_WELCOME":
          console.log("[Handlers] → Calling handleUserWelcome");
          await this.handleUserWelcome(envelope);
          break;

        case "USER_DATA_RESPONSE":
          // Pass through to WebSocket client's event system
          // (handled by fetchUserData promise in auth.ts)
          break;

        case "PUBLIC_CHANNEL_KEY_DELIVERY":
          console.log("[Handlers] → Calling handlePublicChannelKeyDelivery");
          await this.handlePublicChannelKeyDelivery(envelope);
          break;

        case "ERROR":
          console.log("[Handlers] → Calling handleError");
          await this.handleError(envelope);
          break;

        case "USER_ADVERTISE":
          console.log("[Handlers] → Calling handleUserAdvertise");
          await this.handleUserAdvertise(envelope);
          break;

        case "USER_REMOVE":
          console.log("[Handlers] → Calling handleUserRemove");
          await this.handleUserRemove(envelope);
          break;

        // Phase 6.3 message types (handled by messaging.ts)
        case "USER_LIST_RESPONSE":
          // Handled by MessagingManager in messaging.ts
          break;

        case "PUBKEY_RESPONSE":
          // Handled by MessagingManager in messaging.ts
          break;

        case "USER_DELIVER":
          // Handled by MessagingManager in messaging.ts
          break;

        case "MSG_PUBLIC_CHANNEL":
          // Handled by MessagingManager in messaging.ts
          break;

        default:
          console.warn(
            `[Handlers] ⚠️ No handler for message type: ${envelope.type}`
          );
      }
    } catch (error) {
      console.error(
        `[Handlers] ❌ Error routing message ${envelope.type}:`,
        error
      );
      this.errorCallbacks.forEach((cb) =>
        cb("HANDLER_ERROR", (error as Error).message)
      );
    }
  }
}

// ============================================================================
// Convenience Exports
// ============================================================================

/**
 * Create and configure a message handler registry
 *
 * @param sessionManager - Session manager instance
 * @returns MessageHandlerRegistry - Configured registry
 */
export function createMessageHandlers(
  sessionManager: SessionManager,
  getEncryptionKeypair?: () => {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null,
  getSigningKeypair?: () => {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null
): MessageHandlerRegistry {
  return new MessageHandlerRegistry(
    sessionManager,
    getEncryptionKeypair,
    getSigningKeypair
  );
}
