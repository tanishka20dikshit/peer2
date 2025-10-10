/**
 * Phase 6.2 Subtask 7: UI Application Shell
 *
 * Main application entry point that wires together:
 * - WebSocket connection
 * - Registration/Login forms
 * - UI state management
 * - User interactions
 */

import { createApp, AppManager, ConnectionState } from "./app";
import { generateUUID } from "./utils";

// ============================================================================
// DOM Elements
// ============================================================================

// Views
const connectionView = document.getElementById("connectionView") as HTMLElement;
const registrationView = document.getElementById(
  "registrationView"
) as HTMLElement;
const loginView = document.getElementById("loginView") as HTMLElement;
const connectedView = document.getElementById("connectedView") as HTMLElement;

// Status bar
const statusDot = document.getElementById("statusDot") as HTMLElement;
const statusText = document.getElementById("statusText") as HTMLElement;
const serverConfig = document.getElementById("serverConfig") as HTMLElement;

// Connection form
const serverUrlInput = document.getElementById("serverUrl") as HTMLInputElement;
const connectBtn = document.getElementById("connectBtn") as HTMLButtonElement;
const connectionError = document.getElementById(
  "connectionError"
) as HTMLElement;

// Registration form
const registrationUserId = document.getElementById(
  "registrationUserId"
) as HTMLElement;
const registerPassword = document.getElementById(
  "registerPassword"
) as HTMLInputElement;
const registerDisplayName = document.getElementById(
  "registerDisplayName"
) as HTMLInputElement;
const registerBtn = document.getElementById("registerBtn") as HTMLButtonElement;
const backToConnectFromRegister = document.getElementById(
  "backToConnectFromRegister"
) as HTMLButtonElement;
const registerProgress = document.getElementById(
  "registerProgress"
) as HTMLElement;
const registerProgressText = document.getElementById(
  "registerProgressText"
) as HTMLElement;
const registerProgressFill = document.getElementById(
  "registerProgressFill"
) as HTMLElement;
const registerError = document.getElementById("registerError") as HTMLElement;
const registerSuccess = document.getElementById(
  "registerSuccess"
) as HTMLElement;
const switchToLogin = document.getElementById("switchToLogin") as HTMLElement;

// Login form
const loginUserId = document.getElementById("loginUserId") as HTMLInputElement;
const loginPassword = document.getElementById(
  "loginPassword"
) as HTMLInputElement;
const loginBtn = document.getElementById("loginBtn") as HTMLButtonElement;
const backToConnectFromLogin = document.getElementById(
  "backToConnectFromLogin"
) as HTMLButtonElement;
const loginProgress = document.getElementById("loginProgress") as HTMLElement;
const loginProgressText = document.getElementById(
  "loginProgressText"
) as HTMLElement;
const loginProgressFill = document.getElementById(
  "loginProgressFill"
) as HTMLElement;
const loginError = document.getElementById("loginError") as HTMLElement;
const loginSuccess = document.getElementById("loginSuccess") as HTMLElement;
const switchToRegister = document.getElementById(
  "switchToRegister"
) as HTMLElement;

// Connected view
const connectedUserId = document.getElementById(
  "connectedUserId"
) as HTMLElement;
const connectedServer = document.getElementById(
  "connectedServer"
) as HTMLElement;
const connectedDisplayName = document.getElementById(
  "connectedDisplayName"
) as HTMLElement;
const channelKeyStatus = document.getElementById(
  "channelKeyStatus"
) as HTMLElement;
const disconnectBtn = document.getElementById(
  "disconnectBtn"
) as HTMLButtonElement;

// ============================================================================
// Application State
// ============================================================================

let app: AppManager | null = null;
let currentUserId: string = "";
let registrationUserData: any = null; // Store data for after registration

// ============================================================================
// View Management
// ============================================================================

function showView(viewToShow: HTMLElement) {
  [connectionView, registrationView, loginView, connectedView].forEach(
    (view) => {
      view.classList.remove("active");
    }
  );
  viewToShow.classList.add("active");
}

function updateConnectionStatus(state: ConnectionState) {
  statusDot.className = "status-dot " + state;

  switch (state) {
    case ConnectionState.DISCONNECTED:
      statusText.textContent = "Disconnected";
      break;
    case ConnectionState.CONNECTING:
      statusText.textContent = "Connecting...";
      break;
    case ConnectionState.CONNECTED:
      statusText.textContent = "Connected";
      break;
    case ConnectionState.RECONNECTING:
      statusText.textContent = "Reconnecting...";
      break;
    case ConnectionState.ERROR:
      statusText.textContent = "Connection Error";
      break;
  }
}

function showError(element: HTMLElement, message: string) {
  element.textContent = message;
  element.classList.add("active");
}

function hideError(element: HTMLElement) {
  element.classList.remove("active");
}

function showSuccess(element: HTMLElement, message: string) {
  element.textContent = message;
  element.classList.add("active");
}

function hideSuccess(element: HTMLElement) {
  element.classList.remove("active");
}

function showProgress(
  container: HTMLElement,
  textElement: HTMLElement,
  fillElement: HTMLElement
) {
  container.classList.add("active");
  fillElement.style.width = "0%";
  textElement.textContent = "Starting...";
}

function hideProgress(container: HTMLElement) {
  container.classList.remove("active");
}

function updateProgress(
  textElement: HTMLElement,
  fillElement: HTMLElement,
  text: string,
  percent: number
) {
  textElement.textContent = text;
  fillElement.style.width = percent + "%";
}

// ============================================================================
// Connection Handling
// ============================================================================

async function handleConnect() {
  const url = serverUrlInput.value.trim();

  if (!url) {
    showError(connectionError, "Please enter a WebSocket URL");
    return;
  }

  hideError(connectionError);
  connectBtn.disabled = true;
  connectBtn.textContent = "Connecting...";

  try {
    // Create app manager
    app = createApp(url);

    // Subscribe to state changes
    app.onStateChange((state) => {
      updateConnectionStatus(state.connectionState);

      if (state.hasPublicChannelKey) {
        channelKeyStatus.className = "channel-key-status ready";
        channelKeyStatus.innerHTML =
          "✅ Public channel key received - /all command ready!";
      }
    });

    // Connect to server
    console.log("[Main] Connecting to", url);
    await app.connect();

    console.log("[Main] Connected successfully");
    serverConfig.textContent = url.replace("ws://", "").replace("wss://", "");

    // Show registration view after successful connection
    showView(registrationView);

    // Generate UUID for registration
    currentUserId = generateUUID();
    registrationUserId.textContent = currentUserId;
  } catch (error) {
    console.error("[Main] Connection failed:", error);
    showError(
      connectionError,
      "Connection failed: " + (error as Error).message
    );
    connectBtn.disabled = false;
    connectBtn.textContent = "Connect to Server";
  }
}

// ============================================================================
// Registration Handling
// ============================================================================

async function handleRegister() {
  const password = registerPassword.value;
  const displayName = registerDisplayName.value.trim();

  // Validation
  if (!password || password.length < 8) {
    showError(registerError, "Password must be at least 8 characters");
    return;
  }

  if (!/[A-Z]/.test(password)) {
    showError(
      registerError,
      "Password must contain at least one uppercase letter"
    );
    return;
  }

  if (!/[a-z]/.test(password)) {
    showError(
      registerError,
      "Password must contain at least one lowercase letter"
    );
    return;
  }

  if (!/[0-9]/.test(password)) {
    showError(registerError, "Password must contain at least one number");
    return;
  }

  if (!app) {
    showError(registerError, "Not connected to server");
    return;
  }

  hideError(registerError);
  hideSuccess(registerSuccess);
  registerBtn.disabled = true;
  backToConnectFromRegister.disabled = true;

  showProgress(registerProgress, registerProgressText, registerProgressFill);

  try {
    const meta = displayName ? { display_name: displayName } : {};
    const serverId = app.getSessionManager().getServerId() || "*"; // ← CHANGE 'unknown' to '*'

    console.log("[Main] Starting registration for", currentUserId);

    const userId = await app.registerNewUser(
      password,
      serverId,
      meta,
      currentUserId, // ← ADD: Pass the displayed UUID
      (stage, progress) => {
        console.log("[Main] Registration progress:", stage, progress + "%");
        updateProgress(
          registerProgressText,
          registerProgressFill,
          stage,
          progress
        );
      }
    );

    // Registration successful!
    console.log("[Main] Registration successful:", userId);

    // Set up listener for public channel key
    app.getHandlers().onPublicChannelKey(() => {
      console.log("[Main] Public channel key received! Updating UI...");

      // Update the channel key status in the UI
      const channelKeyStatus = document.getElementById(
        "channel-key-status"
      ) as HTMLDivElement;
      if (channelKeyStatus) {
        channelKeyStatus.className = "channel-key-status ready";
        channelKeyStatus.innerHTML =
          "✅ Public channel key received - /all command ready!";
      }
    });

    // Show success briefly, then show connected view
    setTimeout(() => {
      showConnectedView();
    }, 1000);
  } catch (error) {
    console.error("[Main] Registration failed:", error);
    hideProgress(registerProgress);
    showError(
      registerError,
      "Registration failed: " + (error as Error).message
    );
    registerBtn.disabled = false;
    backToConnectFromRegister.disabled = false;
  }
}

// ============================================================================
// Login Handling
// ============================================================================

async function handleLogin(event: Event) {
  event.preventDefault();

  if (!app) return;

  const userId = loginUserId.value.trim();
  const password = loginPassword.value;

  if (!userId || !password) {
    showError(loginError, "Please enter user ID and password");
    return;
  }

  loginBtn.disabled = true;
  backToConnectFromLogin.disabled = true;
  hideError(loginError);
  showProgress(loginProgress, loginProgressText, loginProgressFill);

  try {
    console.log("[Main] Starting login for", userId);

    // Register public channel key listener BEFORE login (so UI updates when key arrives)
    let channelKeyReceived = false;
    app.getHandlers().onPublicChannelKey(() => {
      console.log("[Main] ✅ Public channel key received! Setting flag...");
      channelKeyReceived = true;

      // Update the channel key status in the UI immediately if we're already in connected view
      const channelKeyStatusEl = document.getElementById(
        "channelKeyStatus"
      ) as HTMLDivElement;
      if (channelKeyStatusEl && channelKeyStatusEl.offsetParent !== null) {
        // Check if visible
        console.log("[Main] Updating channel key status in UI...");
        channelKeyStatusEl.className = "channel-key-status ready";
        channelKeyStatusEl.innerHTML =
          "✅ Public channel key received - /all command ready!";
      }
    });

    await app.loginExistingUser(userId, password, (stage, progress) => {
      console.log("[Main] Login progress:", stage, progress + "%");
      updateProgress(loginProgressText, loginProgressFill, stage, progress);
    });

    console.log("[Main] Login successful");
    console.log("[Main] Channel key received flag:", channelKeyReceived);
    console.log(
      "[Main] Session hasPublicChannelKey:",
      app.getSessionManager().getSession()?.hasPublicChannelKey
    );

    hideProgress(loginProgress);
    showSuccess(loginSuccess, "✅ Login successful!");

    setTimeout(() => {
      console.log("[Main] Transitioning to connected view...");
      console.log("[Main] Final channel key check:", {
        flag: channelKeyReceived,
        sessionHasKey: app.getSessionManager().getSession()
          ?.hasPublicChannelKey,
        sessionManagerHasKey: app.getSessionManager().hasPublicChannelKey(),
      });
      showConnectedView();
    }, 1000);
  } catch (error) {
    console.error("[Main] Login failed:", error);
    hideProgress(loginProgress);
    showError(loginError, "Login failed: " + (error as Error).message);
    loginBtn.disabled = false;
    backToConnectFromLogin.disabled = false;
  }
}

// ============================================================================
// Connected View
// ============================================================================

function showConnectedView() {
  if (!app) return;

  const session = app.getSessionManager().getSession();
  if (!session) return;

  console.log("[Main] showConnectedView() called");
  console.log("[Main] Session data:", {
    userId: session.userId,
    serverId: session.serverId,
    hasPublicChannelKey: session.hasPublicChannelKey,
    sessionManagerHasKey: app.getSessionManager().hasPublicChannelKey(),
  });

  connectedUserId.textContent = session.userId;
  connectedServer.textContent = session.serverId;
  connectedDisplayName.textContent =
    session.displayName || session.userId.substring(0, 8);

  // Check BOTH session flag AND sessionManager method
  const hasChannelKey =
    session.hasPublicChannelKey ||
    app.getSessionManager().hasPublicChannelKey();

  console.log("[Main] Final hasChannelKey decision:", hasChannelKey);

  if (hasChannelKey) {
    console.log("[Main] ✅ Showing channel key ready status");
    channelKeyStatus.className = "channel-key-status ready";
    channelKeyStatus.innerHTML =
      "✅ Public channel key received - /all command ready!";
  } else {
    console.log("[Main] ⏳ Showing waiting for channel key status");
    channelKeyStatus.className = "channel-key-status";
    channelKeyStatus.innerHTML =
      '<div class="spinner"></div> Waiting for public channel key...';

    // Set up a poller to check for channel key arrival
    console.log("[Main] Setting up channel key poller...");
    const pollInterval = setInterval(() => {
      const currentSession = app.getSessionManager().getSession();
      const hasKey =
        currentSession?.hasPublicChannelKey ||
        app.getSessionManager().hasPublicChannelKey();

      console.log("[Main] Polling channel key status:", hasKey);

      if (hasKey) {
        console.log("[Main] ✅ Channel key detected by poller! Updating UI...");
        clearInterval(pollInterval);
        channelKeyStatus.className = "channel-key-status ready";
        channelKeyStatus.innerHTML =
          "✅ Public channel key received - /all command ready!";
      }
    }, 500); // Check every 500ms

    // Stop polling after 15 seconds
    setTimeout(() => {
      clearInterval(pollInterval);
      console.log("[Main] Channel key poller timeout");
    }, 15000);
  }

  showView(connectedView);
}

// ============================================================================
// Disconnect Handling
// ============================================================================

function handleDisconnect(): void {
  if (app) {
    app.disconnect();
    app = null;
  }

  // Navigate back to main page
  console.log("[Main] Navigating back to main page...");
  window.location.href = "/index.html";
}

// ============================================================================
// Event Listeners
// ============================================================================

// Connection
connectBtn.addEventListener("click", handleConnect);
serverUrlInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") handleConnect();
});

// Registration
registerBtn.addEventListener("click", handleRegister);
registerPassword.addEventListener("keypress", (e) => {
  if (e.key === "Enter") handleRegister();
});
backToConnectFromRegister.addEventListener("click", handleDisconnect);

// Login
loginBtn.addEventListener("click", handleLogin);
loginPassword.addEventListener("keypress", (e) => {
  if (e.key === "Enter") handleLogin();
});
backToConnectFromLogin.addEventListener("click", handleDisconnect);

// View switching
switchToLogin.addEventListener("click", () => {
  showView(loginView);
  hideError(registerError);
  hideSuccess(registerSuccess);
});

switchToRegister.addEventListener("click", () => {
  showView(registrationView);
  currentUserId = generateUUID();
  registrationUserId.textContent = currentUserId;
  hideError(loginError);
  hideSuccess(loginSuccess);
});

// Disconnect
disconnectBtn.addEventListener("click", handleDisconnect);

// Chat Room Navigation
const enterChatRoomBtn = document.getElementById(
  "enterChatRoomBtn"
) as HTMLButtonElement;
if (enterChatRoomBtn) {
  enterChatRoomBtn.addEventListener("click", () => {
    console.log("[Main] Navigating to chat room...");
    // Session data is stored in sessionStorage and will be available in the chat room
    window.location.href = "/index-phase6-3.html";
  });
}

// ============================================================================
// Page Load
// ============================================================================

console.log("[Main] Secure Chat System UI loaded");
console.log("[Main] Phase 6.2: Authentication & Registration");
console.log("[Main] Ready to connect to backend");
