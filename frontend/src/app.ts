/**
 * Phase 6.2-6.3: Authentication & Messaging Orchestration
 *
 * High-level orchestration layer that connects:
 * - auth.ts (message building logic)
 * - websocket.ts (network communication)
 * - handlers.ts (response processing)
 * - session.ts (state management)
 * - messaging.ts (Phase 6.3 - messaging commands)
 *
 * Provides simple async/await API for UI:
 * - registerNewUser(password, serverId, meta)
 * - loginExistingUser(userId, password, serverId)
 * - getMessagingManager() - Phase 6.3
 */

import { WebSocketClient } from "./websocket";
import { SessionManager } from "./session";
import { MessageHandlerRegistry, createMessageHandlers } from "./handlers";
import { MessagingManager } from "./messaging"; // ← ADD THIS
import {
  registerUser,
  loginUser,
  fetchUserData,
  type RegistrationRequest,
  type LoginRequest,
  type UserData,
} from "./auth";
import { buildUserHello } from "./protocol";
import type { Envelope } from "./protocol";
import { FileTransferManager } from "./fileTransfer";
import type { FileProgress, FileComplete } from "./fileTransfer";

// ============================================================================
// Application State
// ============================================================================

export enum ConnectionState {
  DISCONNECTED = "disconnected",
  CONNECTING = "connecting",
  CONNECTED = "connected",
  RECONNECTING = "reconnecting",
  ERROR = "error",
}

export interface AppState {
  connectionState: ConnectionState;
  isRegistered: boolean;
  isLoggedIn: boolean;
  hasPublicChannelKey: boolean;
  lastError: string | null;
}

// ============================================================================
// Application Manager
// ============================================================================

export class AppManager {
  private wsClient: WebSocketClient;
  private sessionManager: SessionManager;
  private handlers: MessageHandlerRegistry;
  private messagingManager: MessagingManager | null = null; // ← ADD THIS
  private state: AppState;
  private fileTransferManager: FileTransferManager | null = null;

  // Store keypairs in memory (CryptoKey objects can't go in sessionStorage)
  private encryptionKeypair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null = null;
  private signingKeypair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  } | null = null;

  // Callback for state changes
  private stateChangeCallbacks: Array<(state: AppState) => void> = [];

  constructor(websocketUrl: string) {
    // Initialize components
    this.sessionManager = new SessionManager();

    // IMPORTANT: Pass a callback to get keypairs from memory
    this.handlers = createMessageHandlers(
      this.sessionManager,
      () => this.encryptionKeypair,
      () => this.signingKeypair
    );

    this.wsClient = new WebSocketClient({
      url: websocketUrl,
      debug: true,
    });

    // Initialize state
    this.state = {
      connectionState: ConnectionState.DISCONNECTED,
      isRegistered: false,
      isLoggedIn: false,
      hasPublicChannelKey: false,
      lastError: null,
    };

    // Wire up WebSocket event handlers
    this.setupWebSocketHandlers();

    // Wire up message handlers to WebSocket
    this.setupMessageRouting();
  }

  // ==========================================================================
  // Setup
  // ==========================================================================

  private setupWebSocketHandlers(): void {
    // Connection events
    this.wsClient.onConnect(() => {
      console.log("[App] WebSocket connected");
      this.updateState({ connectionState: ConnectionState.CONNECTED });
    });

    this.wsClient.onDisconnect(() => {
      console.log("[App] WebSocket disconnected");
      this.updateState({
        connectionState: ConnectionState.DISCONNECTED,
        isLoggedIn: false,
      });
    });

    this.wsClient.onError((error) => {
      console.error("[App] WebSocket error:", error);
      this.updateState({
        connectionState: ConnectionState.ERROR,
        lastError: error.message,
      });
    });
  }

  private setupMessageRouting(): void {
    // Route all incoming messages through the handler registry
    // This is done by registering handlers for each message type
    const messageTypes = [
      "USER_REGISTERED",
      "USER_WELCOME",
      "PUBLIC_CHANNEL_KEY_DELIVERY",
      "ERROR",
      "USER_ADVERTISE",
      "USER_REMOVE",
      "USER_LIST_RESPONSE",
      "USER_DELIVER",
      "MSG_PUBLIC_CHANNEL",
    ] as const;

    console.log(
      "[App] Setting up message routing for",
      messageTypes.length,
      "message types"
    );

    messageTypes.forEach((type) => {
      this.wsClient.on(type, (envelope) => {
        console.log(`[App] <<<< RECEIVED ${type} message from WebSocket`);
        console.log("[App] Envelope:", envelope);
        this.handlers.routeMessage(envelope);
      });
    });

    console.log("[App] Message routing setup complete");
  }

  // ==========================================================================
  // Public API: Connection Management
  // ==========================================================================

  /**
   * Connect to WebSocket server
   */
  async connect(): Promise<void> {
    if (this.wsClient.connected()) {
      console.log("[App] Already connected");
      return;
    }

    console.log("[App] Connecting to server...");
    this.updateState({ connectionState: ConnectionState.CONNECTING });

    this.wsClient.connect();

    // Wait for connection with timeout
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Connection timeout"));
      }, 10000); // 10 second timeout

      const checkConnection = () => {
        if (this.wsClient.connected()) {
          clearTimeout(timeout);
          resolve();
        }
      };

      this.wsClient.onConnect(() => {
        clearTimeout(timeout);
        resolve();
      });

      // Check immediately in case already connected
      checkConnection();
    });
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    console.log("[App] Disconnecting...");
    this.wsClient.disconnect();
    this.sessionManager.clearSession();
    this.updateState({
      connectionState: ConnectionState.DISCONNECTED,
      isRegistered: false,
      isLoggedIn: false,
      hasPublicChannelKey: false,
    });
  }

  // ==========================================================================
  // Public API: Registration
  // ==========================================================================

  /**
   * Register a new user
   *
   * Flow:
   * 1. Generate RSA-4096 keypairs (encryption + signing)
   * 2. Encrypt private keys with password
   * 3. Send USER_REGISTER message
   * 4. Wait for USER_REGISTERED response
   * 5. Initialize session
   *
   * @param password - User's password
   * @param serverId - Target server ID
   * @param meta - Optional user metadata
   * @param onProgress - Progress callback (optional)
   * @returns Promise<string> - User ID
   */
  async registerNewUser(
    password: string,
    serverId: string,
    meta?: Record<string, any>,
    userId?: string, // ← ADD: Optional userId parameter
    onProgress?: (stage: string, progress: number) => void
  ): Promise<string> {
    console.log("[App] Starting registration...");

    // Ensure connected
    if (!this.wsClient.connected()) {
      throw new Error("Not connected to server");
    }

    try {
      // Step 1: Generate keys (passing userId if provided)
      if (onProgress) onProgress("Generating encryption keys...", 0);
      const regRequest = await registerUser(password, serverId, meta, userId); // ← PASS userId

      console.log("[App] Registration request prepared:", {
        userId: regRequest.userId,
        messageType: regRequest.message.type,
        from: regRequest.message.from,
        to: regRequest.message.to,
        hasPayload: !!regRequest.message.payload,
        payloadKeys: Object.keys(regRequest.message.payload),
      });

      if (onProgress) onProgress("Sending registration request...", 80);

      // Step 2: Set up response handler
      const registrationPromise = new Promise<{
        userId: string;
        serverId: string;
      }>((resolve, reject) => {
        const timeout = setTimeout(() => {
          console.error(
            "[App] ❌ Registration timeout - no response received after 30s"
          );
          console.error("[App] WebSocket state:", this.wsClient.readyState());
          console.error("[App] Connected:", this.wsClient.connected());
          reject(new Error("Registration timeout"));
        }, 30000); // 30 second timeout

        // Success handler
        this.handlers.onRegistrationSuccess((userId, serverId) => {
          console.log("[App] ✅ Registration success handler called:", {
            userId,
            serverId,
          });
          clearTimeout(timeout);
          resolve({ userId, serverId });
        });

        // Error handler
        this.handlers.onRegistrationError((error) => {
          console.error("[App] ❌ Registration error handler called:", error);
          clearTimeout(timeout);
          reject(new Error(error));
        });
      });

      // Step 3: Send USER_REGISTER message
      console.log("[App] Sending USER_REGISTER message...");
      console.log(
        "[App] Message envelope:",
        JSON.stringify(regRequest.message, null, 2)
      );
      this.wsClient.send(regRequest.message);
      console.log("[App] Message sent, waiting for response...");

      if (onProgress) onProgress("Waiting for server response...", 90);

      // Step 4: Wait for response
      console.log("[App] Awaiting registration promise...");
      const result = await registrationPromise;
      console.log("[App] Registration promise resolved:", result);

      // Step 5: Initialize session
      this.sessionManager.initSession(
        result.userId,
        result.serverId,
        {
          encryption: regRequest.encryptionKeypair,
          signing: regRequest.signingKeypair,
        },
        regRequest.encryptionPubkeyB64,
        regRequest.signingPubkeyB64,
        meta
      );

      // Store keypairs in memory for immediate access
      this.encryptionKeypair = regRequest.encryptionKeypair;
      this.signingKeypair = regRequest.signingKeypair;

      if (onProgress) onProgress("Registration complete!", 100);

      console.log("[App] Registration successful:", result.userId);

      // Step 6: Register PUBLIC_CHANNEL_KEY_DELIVERY handler BEFORE sending USER_HELLO
      const channelKeyPromise = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          console.warn(
            "[App] Channel key delivery timeout during registration - continuing anyway"
          );
          resolve(); // Don't fail registration if channel key doesn't arrive
        }, 10000); // 10 second timeout

        this.handlers.onPublicChannelKey(() => {
          clearTimeout(timeout);
          console.log("[App] Public channel key received during registration!");
          this.updateState({ hasPublicChannelKey: true }); // ← ADD THIS
          resolve();
        });
      });

      // Step 7: Send USER_HELLO to establish connection (triggers USER_WELCOME + PUBLIC_CHANNEL_KEY_DELIVERY)
      console.log("[App] Sending USER_HELLO to establish connection...");
      const helloMessage = buildUserHello(
        result.userId,
        result.serverId,
        regRequest.signingPubkeyB64, // pubkey - signing key for verification
        regRequest.encryptionPubkeyB64, // enc_pubkey - encryption key
        meta || {} // metadata
      );

      this.wsClient.send(helloMessage);
      console.log(
        "[App] USER_HELLO sent, waiting for USER_WELCOME and PUBLIC_CHANNEL_KEY_DELIVERY..."
      );

      // Step 8: Wait for PUBLIC_CHANNEL_KEY_DELIVERY (handler already registered!)
      await channelKeyPromise;
      console.log("[App] Registration flow complete - channel key received!");

      // Update state to mark as logged in
      this.updateState({ isLoggedIn: true, isRegistered: true });

      return result.userId;
    } catch (error) {
      console.error("[App] Registration failed:", error);
      throw error;
    }
  }

  // ==========================================================================
  // Public API: Login
  // ==========================================================================

  /**
   * Login existing user
   *
   * Flow:
   * 1. Fetch user data from backend via GET_USER_DATA
   * 2. Decrypt private keys with password
   * 3. Send USER_HELLO message
   * 4. Wait for USER_WELCOME response
   * 5. Wait for PUBLIC_CHANNEL_KEY_DELIVERY
   * 6. Initialize session
   *
   * @param userId - User ID (UUID)
   * @param password - User's password
   * @param onProgress - Progress callback (optional)
   * @returns Promise<{ userId: string; serverId: string }>
   */
  async loginExistingUser(
    userId: string,
    password: string,
    onProgress?: (stage: string, progress: number) => void
  ): Promise<{ userId: string; serverId: string }> {
    console.log("[App] Starting login for user:", userId);

    // Ensure connected
    if (!this.wsClient.connected()) {
      throw new Error("Not connected to server");
    }

    try {
      // Step 1: Fetch user data from backend
      if (onProgress) onProgress("Fetching user data from backend...", 10);
      console.log("[App] Fetching user data from backend...");

      const serverId = this.sessionManager.getServerId() || "*";
      const userData = await fetchUserData(userId, this.wsClient, serverId);

      console.log("[App] User data fetched:", {
        userId: userData.userId,
        hasPubkey: !!userData.pubkey,
        hasPrivkeyStore: !!userData.privkeyStore,
      });

      // Step 2: Decrypt keys and build USER_HELLO
      if (onProgress) onProgress("Decrypting private keys...", 30);
      console.log("[App] Decrypting private keys...");

      const loginRequest = await loginUser(userData, password, serverId);

      console.log("[App] Login request prepared:", {
        userId: loginRequest.userId,
        messageType: loginRequest.message.type,
      });

      if (onProgress) onProgress("Sending login request...", 50);

      // Step 3: Set up ALL response handlers FIRST (before sending message)
      const loginPromise = new Promise<{ userId: string; serverId: string }>(
        (resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error("Login timeout"));
          }, 15000);

          // Success handler
          this.handlers.onLoginSuccess((userId, serverId) => {
            clearTimeout(timeout);
            console.log("[App] ✅ Login success handler called:", {
              userId,
              serverId,
            });
            resolve({ userId, serverId });
          });

          // Error handler
          this.handlers.onLoginError((error) => {
            clearTimeout(timeout);
            console.error("[App] ❌ Login error handler called:", error);
            reject(new Error(error));
          });
        }
      );

      // Step 3b: Register PUBLIC_CHANNEL_KEY_DELIVERY handler BEFORE sending USER_HELLO
      const channelKeyPromise = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          console.warn(
            "[App] Channel key delivery timeout - continuing anyway"
          );
          resolve(); // Don't fail login if channel key doesn't arrive
        }, 10000);

        this.handlers.onPublicChannelKey(() => {
          clearTimeout(timeout);
          console.log("[App] Public channel key received during login!");
          this.updateState({ hasPublicChannelKey: true }); // ← ADD THIS
          resolve();
        });
      });

      // Step 4: Initialize session BEFORE sending (so handlers can access keys)
      console.log("[App] Initializing session with keys...");
      this.sessionManager.initSession(
        loginRequest.userId,
        serverId,
        {
          encryption: loginRequest.encryptionKeypair,
          signing: loginRequest.signingKeypair,
        },
        loginRequest.encryptionPubkeyB64,
        loginRequest.signingPubkeyB64,
        userData.meta
      );

      // Store keypairs in memory for immediate access (MISSING - ADD THIS!)
      this.encryptionKeypair = loginRequest.encryptionKeypair;
      this.signingKeypair = loginRequest.signingKeypair;

      // Step 5: Send USER_HELLO message (NOW both handlers are registered)
      console.log("[App] Sending USER_HELLO message...");
      this.wsClient.send(loginRequest.message);

      if (onProgress) onProgress("Waiting for server response...", 60);

      // Step 6: Wait for USER_WELCOME
      const result = await loginPromise;

      // Step 7: Update session with actual server ID
      if (result.serverId && result.serverId !== "*") {
        console.log(
          "[App] Updating session with actual server ID:",
          result.serverId
        );
        const currentSession = this.sessionManager.getSession();
        if (currentSession) {
          this.sessionManager.initSession(
            currentSession.userId,
            result.serverId,
            {
              encryption: this.encryptionKeypair!,
              signing: this.signingKeypair!,
            },
            currentSession.encryptionPubkeyB64,
            currentSession.signingPubkeyB64,
            currentSession.meta
          );
        }
      }

      console.log("[App] Login successful:", result.userId);

      if (onProgress) onProgress("Waiting for channel key...", 80);

      // Step 8: Wait for PUBLIC_CHANNEL_KEY_DELIVERY (handler already registered!)
      await channelKeyPromise;

      if (onProgress) onProgress("Login complete!", 100);

      console.log("[App] Login flow complete");

      // Update state to mark as logged in
      this.updateState({ isLoggedIn: true });

      return result;
    } catch (error) {
      console.error("[App] Login failed:", error);
      throw error;
    }
  }

  // ==========================================================================
  // State Management
  // ==========================================================================

  /**
   * Get current application state
   */
  getState(): AppState {
    return { ...this.state };
  }

  /**
   * Subscribe to state changes
   */
  onStateChange(callback: (state: AppState) => void): void {
    this.stateChangeCallbacks.push(callback);
  }

  /**
   * Update application state and notify listeners
   */
  private updateState(updates: Partial<AppState>): void {
    this.state = { ...this.state, ...updates };

    // Notify all listeners
    this.stateChangeCallbacks.forEach((callback) => {
      try {
        callback(this.state);
      } catch (error) {
        console.error("[App] State change callback error:", error);
      }
    });
  }

  // ==========================================================================
  // Getters
  // ==========================================================================

  /**
   * Get session manager (for advanced usage)
   */
  getSessionManager(): SessionManager {
    return this.sessionManager;
  }

  /**
   * Get WebSocket client (for advanced usage)
   */
  getWebSocketClient(): WebSocketClient {
    return this.wsClient;
  }

  /**
   * Get message handlers (for advanced usage)
   */
  getHandlers(): MessageHandlerRegistry {
    return this.handlers;
  }

  /**
   * Check if logged in
   */
  isLoggedIn(): boolean {
    return this.state.isLoggedIn && this.sessionManager.isLoggedIn();
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.wsClient.connected();
  }

  // ==========================================================================
  // Public API: Messaging (Phase 6.3)
  // ==========================================================================

  /**
   * Get messaging manager (Phase 6.3)
   * Creates it on first access after login
   */
  getMessagingManager(): MessagingManager | null {
    if (!this.messagingManager && this.isLoggedIn()) {
      console.log("[App] Creating MessagingManager...");
      this.messagingManager = new MessagingManager(
        this.wsClient,
        this.sessionManager,
        () => this.encryptionKeypair,
        () => this.signingKeypair
      );
    }
    return this.messagingManager;
  }

  /**
   * Execute a messaging command (Phase 6.3)
   */
  async executeCommand(command: string): Promise<void> {
    const messaging = this.getMessagingManager();
    if (!messaging) {
      throw new Error("Not logged in - messaging not available");
    }
    await messaging.executeCommand(command);
  }

  /**
   * Get file transfer manager (Phase 6.4)
   * Creates it on first access after login
   */
  getFileTransferManager(): FileTransferManager | null {
    console.log("[App] getFileTransferManager() called");
    console.log("[App] - fileTransferManager exists:", !!this.fileTransferManager);
    console.log("[App] - isLoggedIn():", this.isLoggedIn());
    
    if (!this.fileTransferManager && this.isLoggedIn()) {
      // Ensure MessagingManager exists first
      const messaging = this.getMessagingManager();
      console.log("[App] - MessagingManager from getMessagingManager():", !!messaging);
      
      if (!messaging) {
        console.warn("[App] Cannot create FileTransferManager: MessagingManager not available");
        return null;
      }
      
      console.log("[App] Creating FileTransferManager...");
      try {
        this.fileTransferManager = new FileTransferManager(
          this.wsClient,
          this.sessionManager,
          messaging
        );
        console.log("[App] ✓ FileTransferManager created successfully");
      } catch (error) {
        console.error("[App] ✗ Failed to create FileTransferManager:", error);
        return null;
      }
    }
    
    console.log("[App] Returning fileTransferManager:", !!this.fileTransferManager);
    return this.fileTransferManager;
  }

  /**
   * Initialize file transfer manager (Phase 6.4)
   * Should be called after MessagingManager is initialized
   */
  private initializeFileTransfer(): void {
    if (!this.messagingManager) {
      console.warn("[App] Cannot initialize FileTransferManager without MessagingManager");
      return;
    }

    if (this.fileTransferManager) {
      console.log("[App] FileTransferManager already initialized");
      return;
    }

    console.log("[App] Initializing FileTransferManager (Phase 6.4)");
    this.fileTransferManager = new FileTransferManager(
      this.wsClient,
      this.sessionManager,
      this.messagingManager
    );

    console.log("[App] FileTransferManager initialized successfully");
  }

  /**
   * Get session manager (for FileTransferManager)
   */
  getSessionManager(): SessionManager {
    return this.sessionManager;
  }
}

// ============================================================================
// Convenience Factory
// ============================================================================

/**
 * Create and initialize application manager
 *
 * @param websocketUrl - WebSocket server URL (e.g., "ws://localhost:8765")
 * @returns AppManager - Configured application manager
 */
export function createApp(websocketUrl: string): AppManager {
  return new AppManager(websocketUrl);
}
