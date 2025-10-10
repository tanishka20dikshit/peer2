/**
 * Phase 6.3: Core Messaging Commands
 *
 * Implements /list, /tell, /all commands per SOCP requirements (Protocol §14).
 * Handles:
 * - Command parsing
 * - User list management with real-time updates
 * - Public key fetching and caching
 * - Message encryption/decryption
 * - Content signature generation/verification
 * - Message display formatting
 */

import { WebSocketClient } from "./websocket";
import { SessionManager } from "./session";
import {
  rsaOaepEncrypt,
  rsaOaepDecrypt,
  rsaPssSign,
  rsaPssVerify,
  importPublicKeySPKI,
  publicKeyCache,
  sha256,
  RSA_OAEP_MAX_PLAINTEXT,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from "./crypto";
import {
  buildUserListRequest,
  buildGetPubkeyRequest,
  buildMsgDirect,
  buildMsgPublicChannel,
  type Envelope,
} from "./protocol";
import {
  base64urlEncode,
  base64urlDecode,
  stringToBytes,
  bytesToString,
  formatTimestamp,
} from "./utils";

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface User {
  userId: string;
  location: string; // server_id or "local"
  meta?: Record<string, any>;
  displayName?: string;
  pubkey?: string; // Cached public key (base64url)
}

export interface Message {
  id: string;
  type: "dm" | "public" | "system";
  from: string;
  to?: string;
  sender: string; // Display name or user_id
  content: string;
  timestamp: number;
  verified: boolean; // Signature verification result
  encrypted: boolean;
}

export interface Command {
  type: "list" | "tell" | "all" | "file" | "unknown";
  recipient?: string;
  message?: string;
  filePath?: string; // ← Add file path for /file command (Protocol §14)
  raw: string;
}

// ============================================================================
// Command Parser
// ============================================================================

export function parseCommand(input: string): Command {
  const trimmed = input.trim();

  // /list command
  if (trimmed === "/list") {
    return { type: "list", raw: trimmed };
  }

  // /tell <user> <message> command
  if (trimmed.startsWith("/tell ")) {
    const parts = trimmed.substring(6).trim().split(" ");
    if (parts.length < 2) {
      return { type: "unknown", raw: trimmed };
    }
    const recipient = parts[0];
    const message = parts.slice(1).join(" ");
    return { type: "tell", recipient, message, raw: trimmed };
  }

  // /all <message> command
  if (trimmed.startsWith("/all ")) {
    const message = trimmed.substring(5).trim();
    if (!message) {
      return { type: "unknown", raw: trimmed };
    }
    return { type: "all", message, raw: trimmed };
  }

  // /file <user> <path> command (Protocol §14)
  // Note: In browser context, <path> is informational only.
  // Browser security prevents direct file system access,
  // so we use a file picker regardless.
  if (trimmed.startsWith("/file ")) {
    const args = trimmed.substring(6).trim().split(" ");
    if (args.length === 0 || !args[0]) {
      return { type: "unknown", raw: trimmed };
    }
    const recipient = args[0];
    const filePath = args.slice(1).join(" "); // Optional path (browser will use picker)
    return { type: "file", recipient, filePath: filePath || undefined, raw: trimmed };
  }

  return { type: "unknown", raw: trimmed };
}

// ============================================================================
// Messaging Manager
// ============================================================================

export class MessagingManager {
  private wsClient: WebSocketClient;
  private sessionManager: SessionManager;

  // State
  private users: Map<string, User> = new Map();
  private messages: Message[] = [];

  // Callbacks
  private userListCallbacks: Array<(users: User[]) => void> = [];
  private messageCallbacks: Array<(message: Message) => void> = [];
  private errorCallbacks: Array<(error: string) => void> = [];
  private fileCommandCallbacks: ((recipient: string) => void)[] = [];

  // Getter functions for keypairs (from app.ts memory storage)
  private getEncryptionKeypair: () => {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null;
  private getSigningKeypair: () => {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null;

  constructor(
    wsClient: WebSocketClient,
    sessionManager: SessionManager,
    getEncryptionKeypair: () => {
      publicKey: CryptoKey;
      privateKey: CryptoKey;
    } | null,
    getSigningKeypair: () => {
      publicKey: CryptoKey;
      privateKey: CryptoKey;
    } | null
  ) {
    this.wsClient = wsClient;
    this.sessionManager = sessionManager;
    this.getEncryptionKeypair = getEncryptionKeypair;
    this.getSigningKeypair = getSigningKeypair;

    // Set up message handlers
    this.setupMessageHandlers();
  }

  // ==========================================================================
  // Setup
  // ==========================================================================

  private setupMessageHandlers(): void {
    // User list response
    this.wsClient.on("USER_LIST_RESPONSE", (envelope) => {
      this.handleUserListResponse(envelope);
    });

    // Public key response
    this.wsClient.on("PUBKEY_RESPONSE", (envelope) => {
      this.handlePubkeyResponse(envelope);
    });

    // Incoming direct messages
    this.wsClient.on("USER_DELIVER", (envelope) => {
      this.handleUserDeliver(envelope);
    });

    // Incoming public channel messages
    this.wsClient.on("MSG_PUBLIC_CHANNEL", (envelope) => {
      this.handleMsgPublicChannel(envelope);
    });

    // User presence updates
    this.wsClient.on("USER_ADVERTISE", (envelope) => {
      this.handleUserAdvertise(envelope);
    });

    this.wsClient.on("USER_REMOVE", (envelope) => {
      this.handleUserRemove(envelope);
    });
  }

  // ==========================================================================
  // Callback Registration
  // ==========================================================================

  onUserListUpdate(callback: (users: User[]) => void): void {
    this.userListCallbacks.push(callback);
  }

  onMessage(callback: (message: Message) => void): void {
    this.messageCallbacks.push(callback);
  }

  onError(callback: (error: string) => void): void {
    this.errorCallbacks.push(callback);
  }

  onFileCommand(callback: (recipient: string) => void): void {
    this.fileCommandCallbacks.push(callback);
  }

  // ==========================================================================
  // Command Execution
  // ==========================================================================

  /**
   * Execute a command
   */
  async executeCommand(input: string): Promise<void> {
    const command = parseCommand(input);

    console.log(`[Messaging] Executing command:`, command);

    switch (command.type) {
      case "list":
        this.executeList();
        break;
      case "tell":
        if (command.recipient && command.message) {
          await this.executeTell(command.recipient, command.message);
        } else {
          this.notifyError("Usage: /tell <user> <message>");
        }
        break;
      case "all":
        if (command.message) {
          await this.executeAll(command.message);
        } else {
          this.notifyError("Usage: /all <message>");
        }
        break;
      case "file":
        if (command.recipient) {
          this.executeFile(command.recipient, command.filePath);
        } else {
          this.notifyError("Usage: /file <user> [path]");
        }
        break;
      default:
        this.notifyError(
          "Unknown command. Available: /list, /tell <user> <msg>, /all <msg>, /file <user> [path]"
        );
    }
  }

  /**
   * Execute /list command (Protocol §14)
   */
  private async executeList(): Promise<void> {
    console.log("[Messaging] Executing /list command");

    const userId = this.sessionManager.getUserId();
    const serverId = this.sessionManager.getServerId();

    if (!userId || !serverId) {
      this.notifyError("Not logged in");
      return;
    }

    // Send USER_LIST request
    const request = buildUserListRequest(userId, serverId);
    this.wsClient.send(request);

    console.log("[Messaging] Sent USER_LIST request");
  }

  /**
   * Execute /tell command (Protocol §9.2)
   */
  private async executeTell(
    recipientId: string,
    message: string
  ): Promise<void> {
    console.log(`[Messaging] Executing /tell to ${recipientId}: ${message}`);

    const userId = this.sessionManager.getUserId();
    const encryptionKeypair = this.getEncryptionKeypair();
    const signingKeypair = this.getSigningKeypair();

    if (!userId || !encryptionKeypair || !signingKeypair) {
      this.notifyError("Not logged in or keys not available");
      return;
    }

    try {
      // Check message size
      const messageBytes = stringToBytes(message);
      if (messageBytes.length > RSA_OAEP_MAX_PLAINTEXT) {
        this.notifyError(
          `Message too long (max ${RSA_OAEP_MAX_PLAINTEXT} bytes)`
        );
        return;
      }

      // Get recipient's public key
      const recipientPubkey = await this.getRecipientPublicKey(recipientId);
      if (!recipientPubkey) {
        this.notifyError(`Could not fetch public key for ${recipientId}`);
        return;
      }

      // Encrypt message
      const ciphertext = await rsaOaepEncrypt(recipientPubkey, messageBytes);
      const ciphertextB64 = base64urlEncode(ciphertext);

      // Get sender's public key (for recipient to verify)
      const senderPubB64 = this.sessionManager.getSigningPubkeyB64() || "";

      // Generate content signature: SHA256(ciphertext || from || to || ts)
      const ts = Date.now();
      const contentSig = await this.generateContentSignatureDM(
        ciphertextB64,
        userId,
        recipientId,
        ts,
        signingKeypair.privateKey
      );

      // Build and send MSG_DIRECT
      const envelope = buildMsgDirect(
        userId,
        recipientId,
        ciphertextB64,
        senderPubB64,
        contentSig
      );

      // Override timestamp to match signature
      envelope.ts = ts;

      this.wsClient.send(envelope);

      // Display sent message
      const displayName =
        this.sessionManager.getSession()?.displayName || userId;
      this.notifyMessage({
        id: `${userId}-${ts}`,
        type: "dm",
        from: userId,
        to: recipientId,
        sender: `You → ${recipientId.substring(0, 8)}`,
        content: message,
        timestamp: ts,
        verified: true,
        encrypted: true,
      });

      console.log("[Messaging] Sent direct message to", recipientId);
    } catch (error) {
      console.error("[Messaging] Error sending direct message:", error);
      this.notifyError("Failed to send message: " + (error as Error).message);
    }
  }

  /**
   * Execute /all command (Protocol §9.3)
   */
  private async executeAll(message: string): Promise<void> {
    console.log(`[Messaging] Executing /all: ${message}`);

    const userId = this.sessionManager.getUserId();
    const signingKeypair = this.getSigningKeypair();
    const publicChannelKey = this.sessionManager.getPublicChannelKey();

    if (!userId || !signingKeypair) {
      this.notifyError("Not logged in or keys not available");
      return;
    }

    if (!publicChannelKey) {
      this.notifyError("Public channel key not available - please wait");
      return;
    }

    try {
      // Check message size - AES can handle larger messages
      const messageBytes = stringToBytes(message);
      // No size limit for AES (removed RSA_OAEP_MAX_PLAINTEXT check)

      // Encrypt with AES-GCM (not RSA!)
      const ciphertext = await aesGcmEncrypt(publicChannelKey, messageBytes);
      const ciphertextB64 = base64urlEncode(ciphertext);

      // Get sender's public key
      const senderPubB64 = this.sessionManager.getSigningPubkeyB64() || "";

      // Generate content signature: SHA256(ciphertext || from || ts)
      const ts = Date.now();
      const contentSig = await this.generateContentSignaturePublic(
        ciphertextB64,
        userId,
        ts,
        signingKeypair.privateKey
      );

      // Build and send MSG_PUBLIC_CHANNEL
      const envelope = buildMsgPublicChannel(
        userId,
        ciphertextB64,
        senderPubB64,
        contentSig
      );

      // Override timestamp to match signature
      envelope.ts = ts;

      this.wsClient.send(envelope);

      // Display sent message
      const displayName =
        this.sessionManager.getSession()?.displayName || userId.substring(0, 8);
      this.notifyMessage({
        id: `${userId}-${ts}`,
        type: "public",
        from: userId,
        sender: displayName,
        content: message,
        timestamp: ts,
        verified: true,
        encrypted: true,
      });

      console.log("[Messaging] Sent public channel message");
    } catch (error) {
      console.error("[Messaging] Error sending public message:", error);
      this.notifyError("Failed to send message: " + (error as Error).message);
    }
  }

  /**
   * Execute /file command (Protocol §14)
   * Triggers file picker (browser security prevents direct file access)
   * 
   * @param recipientId - Target user ID
   * @param filePath - Optional file path (informational, browser can't use it)
   */
  private executeFile(recipientId: string, filePath?: string): void {
    console.log(
      `[Messaging] Executing /file to ${recipientId}${
        filePath ? ` (suggested path: ${filePath})` : ""
      }`
    );

    // Note: Browser security model prevents direct file system access
    // We trigger the file picker and pass the recipient to callbacks
    this.fileCommandCallbacks.forEach((cb) => {
      try {
        cb(recipientId);
      } catch (error) {
        console.error("[Messaging] File command callback error:", error);
      }
    });
  }

  // ==========================================================================
  // Message Handlers
  // ==========================================================================

  /**
   * Handle USER_LIST_RESPONSE (Protocol §14)
   */
  private async handleUserListResponse(envelope: Envelope): Promise<void> {
    console.log("[Messaging] Received USER_LIST_RESPONSE:", envelope.payload);

    try {
      const users = envelope.payload.users || [];

      // Update user list
      this.users.clear();
      for (const user of users) {
        this.users.set(user.user_id, {
          userId: user.user_id,
          location: user.location,
          meta: user.meta,
          displayName: user.meta?.display_name || user.user_id.substring(0, 8),
        });
      }

      // Notify listeners
      this.notifyUserListUpdate();

      // Display system message
      this.notifyMessage({
        id: `system-${Date.now()}`,
        type: "system",
        from: "system",
        sender: "System",
        content: `Online users: ${users.length}`,
        timestamp: Date.now(),
        verified: true,
        encrypted: false,
      });
    } catch (error) {
      console.error("[Messaging] Error handling USER_LIST_RESPONSE:", error);
      this.notifyError("Failed to process user list");
    }
  }

  /**
   * Handle PUBKEY_RESPONSE (Phase 6.0)
   */
  private async handlePubkeyResponse(envelope: Envelope): Promise<void> {
    console.log("[Messaging] Received PUBKEY_RESPONSE:", envelope.payload);

    try {
      const payload = envelope.payload;
      const userId = payload.user_id;
      const pubkeyB64 = payload.pubkey;

      // Import and cache public key
      const pubkey = await importPublicKeySPKI(pubkeyB64, ["encrypt"]);

      // Export to JWK for caching
      const jwk = await crypto.subtle.exportKey("jwk", pubkey);
      publicKeyCache.set(userId, pubkey, jwk, true);

      console.log(`[Messaging] Cached public key for ${userId}`);
    } catch (error) {
      console.error("[Messaging] Error handling PUBKEY_RESPONSE:", error);
    }
  }

  /**
   * Handle USER_DELIVER (incoming direct messages) (Protocol §9.2)
   */
  private async handleUserDeliver(envelope: Envelope): Promise<void> {
    console.log("[Messaging] Received USER_DELIVER:", envelope);

    try {
      const payload = envelope.payload;
      const ciphertextB64 = payload.ciphertext;
      const senderId = payload.sender;
      const senderPubB64 = payload.sender_pub;
      const contentSig = payload.content_sig;
      const ts = envelope.ts;

      const userId = this.sessionManager.getUserId();
      const encryptionKeypair = this.getEncryptionKeypair();

      if (!userId || !encryptionKeypair) {
        console.error("[Messaging] Cannot decrypt - not logged in");
        return;
      }

      // Decrypt message
      const ciphertextBytes = base64urlDecode(ciphertextB64);
      const plaintextBytes = await rsaOaepDecrypt(
        encryptionKeypair.privateKey,
        ciphertextBytes
      );
      const plaintext = bytesToString(new Uint8Array(plaintextBytes));

      // Verify content signature
      let verified = false;
      try {
        const senderPubkey = await importPublicKeySPKI(senderPubB64, [
          "verify",
        ]);
        
        // Use original_ts if available, otherwise fall back to envelope.ts
        const signatureTs = payload.original_ts || ts;
        
        verified = await this.verifyContentSignatureDM(
          ciphertextB64,
          senderId,
          userId,
          signatureTs,  // Use the original timestamp from content signature
          contentSig,
          senderPubkey
        );
      } catch (error) {
        console.error("[Messaging] Signature verification failed:", error);
      }

      // Display message
      const displayName =
        this.users.get(senderId)?.displayName || senderId.substring(0, 8);
      this.notifyMessage({
        id: `${senderId}-${ts}`,
        type: "dm",
        from: senderId,
        to: userId,
        sender: displayName,
        content: plaintext,
        timestamp: ts,
        verified,
        encrypted: true,
      });

      console.log(
        "[Messaging] Received direct message from",
        senderId,
        "verified:",
        verified
      );
    } catch (error) {
      console.error("[Messaging] Error handling USER_DELIVER:", error);
      this.notifyError("Failed to receive message");
    }
  }

  /**
   * Handle MSG_PUBLIC_CHANNEL (incoming public messages) (Protocol §9.3)
   */
  private async handleMsgPublicChannel(envelope: Envelope): Promise<void> {
    console.log("[Messaging] Received MSG_PUBLIC_CHANNEL:", envelope);

    try {
      const payload = envelope.payload;
      const ciphertextB64 = payload.ciphertext;
      const senderId = envelope.from;
      const senderPubB64 = payload.sender_pub;
      const contentSig = payload.content_sig;
      const ts = envelope.ts;

      const publicChannelKey = this.sessionManager.getPublicChannelKey();

      if (!publicChannelKey) {
        console.error("[Messaging] Cannot decrypt - no public channel key");
        return;
      }

      // Decrypt with AES-GCM (not RSA!)
      const ciphertextBytes = base64urlDecode(ciphertextB64);
      const plaintextBytes = await aesGcmDecrypt(
        publicChannelKey,
        ciphertextBytes
      );
      const plaintext = bytesToString(new Uint8Array(plaintextBytes));

      // Verify content signature
      let verified = false;
      try {
        const senderPubkey = await importPublicKeySPKI(senderPubB64, [
          "verify",
        ]);
        verified = await this.verifyContentSignaturePublic(
          ciphertextB64,
          senderId,
          ts,
          contentSig,
          senderPubkey
        );
      } catch (error) {
        console.error("[Messaging] Signature verification failed:", error);
      }

      // Display message
      const displayName =
        this.users.get(senderId)?.displayName || senderId.substring(0, 8);
      this.notifyMessage({
        id: `${senderId}-${ts}`,
        type: "public",
        from: senderId,
        sender: displayName,
        content: plaintext,
        timestamp: ts,
        verified,
        encrypted: true,
      });

      console.log(
        "[Messaging] Received public message from",
        senderId,
        "verified:",
        verified
      );
    } catch (error) {
      console.error("[Messaging] Error handling MSG_PUBLIC_CHANNEL:", error);
      this.notifyError("Failed to receive public message");
    }
  }

  /**
   * Handle USER_ADVERTISE (Protocol §8.2)
   */
  private handleUserAdvertise(envelope: Envelope): void {
    console.log("[Messaging] Received USER_ADVERTISE:", envelope.payload);

    const userId = envelope.payload.user_id;
    const serverId = envelope.payload.server_id;
    const meta = envelope.payload.meta || {};

    this.users.set(userId, {
      userId,
      location: serverId,
      meta,
      displayName: meta.display_name || userId.substring(0, 8),
    });

    this.notifyUserListUpdate();
  }

  /**
   * Handle USER_REMOVE (Protocol §8.2)
   */
  private handleUserRemove(envelope: Envelope): void {
    console.log("[Messaging] Received USER_REMOVE:", envelope.payload);

    const userId = envelope.payload.user_id;
    this.users.delete(userId);

    this.notifyUserListUpdate();
  }

  // ==========================================================================
  // Helper Methods
  // ==========================================================================

  /**
   * Get recipient's public key (for external use, e.g., file transfer)
   * Fetches from cache or requests from server
   */
  async getRecipientPublicKey(recipientId: string): Promise<CryptoKey | null> {
    // Check cache first
    const cached = publicKeyCache.get(recipientId);
    if (cached) {
      console.log(`[Messaging] Using cached public key for ${recipientId}`);
      return cached.publicKey;
    }

    // Fetch from server
    console.log(`[Messaging] Fetching public key for ${recipientId}...`);

    const userId = this.sessionManager.getUserId();
    const serverId = this.sessionManager.getServerId();

    if (!userId || !serverId) {
      return null;
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Timeout fetching public key"));
      }, 5000);

      // Set up one-time listener for PUBKEY_RESPONSE
      const handler = async (envelope: Envelope) => {
        if (envelope.payload.user_id === recipientId) {
          clearTimeout(timeout);
          this.wsClient.off("PUBKEY_RESPONSE", handler);

          try {
            const pubkeyB64 = envelope.payload.pubkey;
            const pubkey = await importPublicKeySPKI(pubkeyB64, ["encrypt"]);
            const jwk = await crypto.subtle.exportKey("jwk", pubkey);
            publicKeyCache.set(recipientId, pubkey, jwk, true);
            resolve(pubkey);
          } catch (error) {
            reject(error);
          }
        }
      };

      this.wsClient.on("PUBKEY_RESPONSE", handler);

      // Send request
      const request = buildGetPubkeyRequest(userId, serverId, recipientId);
      this.wsClient.send(request);
    });
  }

  /**
   * Generate content signature for direct message (Protocol §12)
   * SHA256(ciphertext || from || to || ts)
   */
  private async generateContentSignatureDM(
    ciphertext: string,
    from: string,
    to: string,
    ts: number,
    signingKey: CryptoKey
  ): Promise<string> {
    // Concatenate as strings (matches backend implementation)
    const data = `${ciphertext}${from}${to}${ts}`;
    const dataBytes = stringToBytes(data);
    
    // Debug logging
    console.log("[Messaging] Generating signature:");
    console.log("  ciphertext length:", ciphertext.length);
    console.log("  from:", from);
    console.log("  to:", to);
    console.log("  ts:", ts);
    console.log("  data:", data.substring(0, 100) + "...");

    // Hash with SHA-256
    const hash = await sha256(dataBytes);

    // Sign hash with RSA-PSS
    const signature = await rsaPssSign(signingKey, hash);
    return base64urlEncode(signature);
  }

  /**
   * Verify content signature for direct message (Protocol §12)
   */
  private async verifyContentSignatureDM(
    ciphertext: string,
    from: string,
    to: string,
    ts: number,
    signatureB64: string,
    senderPubkey: CryptoKey
  ): Promise<boolean> {
    try {
      // Reconstruct signed data
      const data = `${ciphertext}${from}${to}${ts}`;
      const dataBytes = stringToBytes(data);
      
      // Debug logging
      console.log("[Messaging] Verifying signature:");
      console.log("  ciphertext length:", ciphertext.length);
      console.log("  from:", from);
      console.log("  to:", to);
      console.log("  ts:", ts);
      console.log("  data:", data.substring(0, 100) + "...");

      // Hash with SHA-256
      const hash = await sha256(dataBytes);

      // Verify signature
      const signatureBytes = base64urlDecode(signatureB64);
      const result = await rsaPssVerify(senderPubkey, signatureBytes, hash);
      console.log("  verification result:", result);
      return result;
    } catch (error) {
      console.error("[Messaging] Signature verification error:", error);
      return false;
    }
  }

  /**
   * Generate content signature for public channel message (Protocol §12)
   * SHA256(ciphertext || from || ts)
   */
  private async generateContentSignaturePublic(
    ciphertext: string,
    from: string,
    ts: number,
    signingKey: CryptoKey
  ): Promise<string> {
    // Concatenate as strings (matches backend implementation)
    const data = `${ciphertext}${from}${ts}`;
    const dataBytes = stringToBytes(data);

    // Hash with SHA-256
    const hash = await sha256(dataBytes);

    // Sign hash with RSA-PSS
    const signature = await rsaPssSign(signingKey, hash);
    return base64urlEncode(signature);
  }

  /**
   * Verify content signature for public channel message (Protocol §12)
   */
  private async verifyContentSignaturePublic(
    ciphertext: string,
    from: string,
    ts: number,
    signatureB64: string,
    senderPubkey: CryptoKey
  ): Promise<boolean> {
    try {
      // Reconstruct signed data
      const data = `${ciphertext}${from}${ts}`;
      const dataBytes = stringToBytes(data);

      // Hash with SHA-256
      const hash = await sha256(dataBytes);

      // Verify signature
      const signatureBytes = base64urlDecode(signatureB64);
      return await rsaPssVerify(senderPubkey, signatureBytes, hash);
    } catch (error) {
      console.error("[Messaging] Signature verification error:", error);
      return false;
    }
  }

  // ==========================================================================
  // Notification Helpers
  // ==========================================================================

  private notifyUserListUpdate(): void {
    const userArray = Array.from(this.users.values());
    this.userListCallbacks.forEach((cb) => {
      try {
        cb(userArray);
      } catch (error) {
        console.error("[Messaging] User list callback error:", error);
      }
    });
  }

  private notifyMessage(message: Message): void {
    this.messages.push(message);
    this.messageCallbacks.forEach((cb) => {
      try {
        cb(message);
      } catch (error) {
        console.error("[Messaging] Message callback error:", error);
      }
    });
  }

  private notifyError(error: string): void {
    this.errorCallbacks.forEach((cb) => {
      try {
        cb(error);
      } catch (error) {
        console.error("[Messaging] Error callback error:", error);
      }
    });
  }

  // ==========================================================================
  // Public Getters
  // ==========================================================================

  getUsers(): User[] {
    return Array.from(this.users.values());
  }

  getMessages(): Message[] {
    return [...this.messages];
  }
}
