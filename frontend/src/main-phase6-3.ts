/**
 * Phase 6.3-6.4: Main Application Entry Point
 *
 * Wires together all Phase 6.3-6.4 messaging and file transfer functionality with the UI
 */

import { createApp, AppManager, ConnectionState } from "./app";
import type { User, Message } from "./messaging";
import { FileTransferManager } from "./fileTransfer";
import type { FileProgress, FileComplete } from "./fileTransfer";
import { formatTimestamp } from "./utils";

// ============================================================================
// DOM Elements
// ============================================================================

// Header
const statusDot = document.getElementById("statusDot") as HTMLElement;
const statusText = document.getElementById("statusText") as HTMLElement;
const userIdDisplay = document.getElementById("userIdDisplay") as HTMLElement;
const disconnectBtn = document.getElementById(
  "disconnectBtn"
) as HTMLButtonElement;

// Error banner
const errorBanner = document.getElementById("errorBanner") as HTMLElement;

// Sidebar
const userList = document.getElementById("userList") as HTMLElement;
const userCount = document.getElementById("userCount") as HTMLElement;
const refreshUsersBtn = document.getElementById(
  "refreshUsersBtn"
) as HTMLButtonElement;

// Chat
const channelKeyNotice = document.getElementById(
  "channelKeyNotice"
) as HTMLElement;
const messagesContainer = document.getElementById(
  "messagesContainer"
) as HTMLElement;
const commandInput = document.getElementById(
  "commandInput"
) as HTMLInputElement;
const sendBtn = document.getElementById("sendBtn") as HTMLButtonElement;

// File transfer
const fileTransferSection = document.getElementById(
  "fileTransferSection"
) as HTMLElement;
const fileInput = document.getElementById("fileInput") as HTMLInputElement;

// Auth overlay
const authOverlay = document.getElementById("authOverlay") as HTMLElement;
const serverUrl = document.getElementById("serverUrl") as HTMLInputElement;
const loginUserId = document.getElementById("loginUserId") as HTMLInputElement;
const loginPassword = document.getElementById(
  "loginPassword"
) as HTMLInputElement;
const quickLoginBtn = document.getElementById(
  "quickLoginBtn"
) as HTMLButtonElement;

// ============================================================================
// Application State
// ============================================================================

let app: AppManager | null = null;
let fileTransferManager: FileTransferManager | null = null;
let pendingFileRecipient: string | null = null;

// Track active transfers
const activeTransfers = new Map<
  string,
  {
    element: HTMLElement;
    isComplete: boolean;
    data?: Uint8Array;
    fileName?: string;
  }
>();

// ============================================================================
// UI Helper Functions
// ============================================================================

function showError(message: string): void {
  errorBanner.textContent = message;
  errorBanner.classList.add("show");
  setTimeout(() => {
    errorBanner.classList.remove("show");
  }, 5000);
}

function updateConnectionStatus(state: ConnectionState): void {
  const dot = statusDot;
  dot.className = "status-dot";

  switch (state) {
    case ConnectionState.CONNECTED:
      dot.style.background = "#28a745";
      statusText.textContent = "Connected";
      break;
    case ConnectionState.DISCONNECTED:
      dot.style.background = "#dc3545";
      statusText.textContent = "Disconnected";
      break;
    case ConnectionState.CONNECTING:
      dot.style.background = "#ffc107";
      statusText.textContent = "Connecting...";
      break;
    default:
      dot.style.background = "#6c757d";
      statusText.textContent = "Unknown";
  }
}

function renderUserList(users: User[]): void {
  if (users.length === 0) {
    userList.innerHTML = `
      <div style="padding: 20px; text-align: center; color: #6c757d; font-size: 13px;">
        No users online
      </div>
    `;
    userCount.textContent = "0";
    return;
  }

  userCount.textContent = users.length.toString();

  userList.innerHTML = users
    .map(
      (user) => `
    <div class="user-item" data-user-id="${user.userId}">
      <div class="user-id">${
        user.displayName || user.userId.substring(0, 12)
      }...</div>
      <div class="user-location">📍 ${user.location}</div>
    </div>
  `
    )
    .join("");

  // Add click handlers for quick /tell
  userList.querySelectorAll(".user-item").forEach((item) => {
    item.addEventListener("click", () => {
      const userId = (item as HTMLElement).dataset.userId;
      if (userId) {
        commandInput.value = `/tell ${userId} `;
        commandInput.focus();
      }
    });
  });
}

function renderMessage(message: Message): void {
  const messageEl = document.createElement("div");

  let className = "message ";
  if (message.type === "system") {
    className += "message-system";
  } else if (message.type === "dm") {
    if (message.sender.startsWith("You →")) {
      className += "message-dm-sent";
    } else {
      className += "message-dm-received";
    }
  } else if (message.type === "public") {
    className += "message-public";
  }

  messageEl.className = className;

  let html = "";

  // Header (for non-system messages)
  if (message.type !== "system") {
    html += `<div class="message-header">
      ${message.sender}
      ${
        message.verified
          ? '<span class="message-verified">✓ Verified</span>'
          : ""
      }
    </div>`;
  }

  // Content
  html += `<div class="message-content">${escapeHtml(message.content)}</div>`;

  // Time
  if (message.type !== "system") {
    html += `<div class="message-time">${formatTimestamp(
      message.timestamp
    )}</div>`;
  }

  messageEl.innerHTML = html;
  messagesContainer.appendChild(messageEl);

  // Auto-scroll to bottom
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function updateChannelKeyStatus(hasKey: boolean): void {
  if (hasKey) {
    channelKeyNotice.textContent =
      "✅ Public channel key ready - /all command available";
    channelKeyNotice.classList.add("ready");
    channelKeyNotice.classList.add("show");
  } else {
    channelKeyNotice.textContent = "⏳ Waiting for public channel key...";
    channelKeyNotice.classList.remove("ready");
    channelKeyNotice.classList.add("show");
  }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function createFileTransferUI(
  fileId: string,
  fileName: string,
  fileSize: number,
  direction: "send" | "receive",  // ← Note: uses "send" and "receive"
  peer: string
): HTMLElement {
  const element = document.createElement("div");
  element.className = "file-transfer-item";
  element.id = `transfer-${fileId}`;

  element.innerHTML = `
    <div class="file-transfer-header">
      <div>
        <span class="file-transfer-name">📎 ${escapeHtml(fileName)}</span>
        <span class="file-transfer-size">(${formatFileSize(fileSize)})</span>
      </div>
      <span class="file-transfer-direction ${direction}ing">
        ${direction === "send" ? "↑ Sending to " + peer.substring(0, 8) : "↓ Receiving from " + peer.substring(0, 8)}
      </span>
    </div>
    <div class="file-transfer-progress">
      <div class="progress-bar-container">
        <div class="progress-bar-fill" style="width: 0%"></div>
      </div>
      <span class="progress-text">0%</span>
    </div>
    <div class="file-transfer-status">Starting transfer...</div>
  `;

  fileTransferSection.appendChild(element);
  fileTransferSection.classList.add("show");

  return element;
}

function updateFileTransferProgress(
  fileId: string,
  progress: number,
  status: string
): void {
  const element = document.getElementById(`transfer-${fileId}`);
  if (!element) return;

  const progressBar = element.querySelector(
    ".progress-bar-fill"
  ) as HTMLElement;
  const progressText = element.querySelector(".progress-text") as HTMLElement;
  const statusText = element.querySelector(
    ".file-transfer-status"
  ) as HTMLElement;

  if (progressBar) {
    progressBar.style.width = `${progress}%`;
  }
  if (progressText) {
    progressText.textContent = `${progress}%`;
  }
  if (statusText) {
    statusText.textContent = status;
  }
}

function markFileTransferComplete(
  fileId: string,
  fileName: string,
  data?: Uint8Array
): void {
  const element = document.getElementById(`transfer-${fileId}`);
  if (!element) return;

  const progressBar = element.querySelector(
    ".progress-bar-fill"
  ) as HTMLElement;
  const statusText = element.querySelector(
    ".file-transfer-status"
  ) as HTMLElement;

  if (progressBar) {
    progressBar.style.width = "100%";
    progressBar.classList.add("complete");
  }

  if (statusText) {
    statusText.textContent = "✓ Transfer complete";
    statusText.classList.add("complete");
  }

  // If receiving, add download button
  if (data) {
    const downloadBtn = document.createElement("button");
    downloadBtn.className = "download-btn";
    downloadBtn.textContent = "💾 Download";
    downloadBtn.onclick = () => {
      triggerDownload(data, fileName);
      renderMessage({
        type: "system",
        sender: "System",
        content: `Downloaded: ${fileName}`,
        timestamp: Date.now(),
        verified: true,
      });
    };
    element.appendChild(downloadBtn);
  }

  // Store completion
  const transfer = activeTransfers.get(fileId);
  if (transfer) {
    transfer.isComplete = true;
    if (data) {
      transfer.data = data;
      transfer.fileName = fileName;
    }
  }
}

function markFileTransferError(fileId: string, error: string): void {
  const element = document.getElementById(`transfer-${fileId}`);
  if (!element) return;

  const statusText = element.querySelector(
    ".file-transfer-status"
  ) as HTMLElement;
  if (statusText) {
    statusText.textContent = `✗ Error: ${error}`;
    statusText.classList.add("error");
  }
}

function triggerDownload(data: Uint8Array, fileName: string): void {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================================================
// File Transfer Handlers
// ============================================================================

function handleFileCommand(recipientId: string): void {
  console.log(`[Main] File command triggered for recipient: ${recipientId}`);
  pendingFileRecipient = recipientId;
  fileInput.click();
}

async function handleFileSelection(event: Event): Promise<void> {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];

  if (!file || !pendingFileRecipient || !fileTransferManager) {
    console.error("[Main] File selection failed - missing file or recipient");
    return;
  }

  const recipientId = pendingFileRecipient;
  pendingFileRecipient = null;

  // Reset file input
  target.value = "";

  console.log(
    `[Main] Starting file transfer: ${file.name} (${file.size} bytes) to ${recipientId}`
  );

  try {
    await fileTransferManager.sendFile(recipientId, file);
    console.log(`[Main] File transfer initiated successfully`);
  } catch (error) {
    console.error("[Main] File transfer failed:", error);
    showError("File transfer failed: " + (error as Error).message);
  }
}

function handleFileProgress(progress: FileProgress): void {
  console.log(
    `[Main] File progress:`,
    progress.fileId,
    `${progress.progress}%`,
    progress.status
  );

  // Create UI if doesn't exist
  if (!activeTransfers.has(progress.fileId)) {
    const element = createFileTransferUI(
      progress.fileId,
      progress.fileName,
      progress.totalSize,
      progress.direction,
      progress.peer
    );
    activeTransfers.set(progress.fileId, {
      element,
      isComplete: false,
    });
  }

  // Update progress
  updateFileTransferProgress(
    progress.fileId,
    progress.progress,
    progress.status
  );
}

function handleFileComplete(complete: FileComplete): void {
  console.log(
    `[Main] File transfer complete:`,
    complete.fileId,
    complete.fileName
  );

  markFileTransferComplete(
    complete.fileId,
    complete.fileName,
    complete.data
  );

  // Add message to chat
  const direction = complete.data ? "from" : "to";
  const peer = complete.peer.substring(0, 12);
  renderMessage({
    type: "system",
    sender: "System",
    content: `File transfer complete: ${complete.fileName} ${direction} ${peer}...`,
    timestamp: Date.now(),
    verified: true,
  });
}

function handleFileError(error: string): void {
  console.error(`[Main] File transfer error:`, error);
  showError(`File transfer error: ${error}`);
}

// ============================================================================
// Event Handlers
// ============================================================================

async function handleQuickLogin(): Promise<void> {
  const url = serverUrl.value.trim();
  const userId = loginUserId.value.trim();
  const password = loginPassword.value;

  if (!url || !userId || !password) {
    showError("Please fill in all fields");
    return;
  }

  quickLoginBtn.disabled = true;
  quickLoginBtn.textContent = "Logging in...";

  try {
    // Create app
    app = createApp(url);

    // Subscribe to state changes
    app.onStateChange((state) => {
      updateConnectionStatus(state.connectionState);
      updateChannelKeyStatus(state.hasPublicChannelKey);
    });

    // Connect
    await app.connect();

    // Login
    await app.loginExistingUser(userId, password);

    // Get managers
    const messaging = app.getMessagingManager();
    const wsClient = app.getWebSocketClient();
    const sessionManager = app.getSessionManager();
    
    // Get FileTransferManager (initialized by AppManager during login)
    fileTransferManager = app.getFileTransferManager();

    if (messaging && wsClient && sessionManager) {
      // Wire up FILE_* messages to FileTransferManager (if available)
      if (fileTransferManager) {
        // Register handlers for file transfer messages
        wsClient.on("FILE_START", (envelope) => {
          if (!fileTransferManager) return;
          console.log("[Main] Routing FILE_START to FileTransferManager");
          fileTransferManager.handleFileStart(envelope);
        });

        wsClient.on("FILE_CHUNK", async (envelope) => {
          if (!fileTransferManager) return;
          console.log("[Main] Routing FILE_CHUNK to FileTransferManager");
          await fileTransferManager.handleFileChunk(envelope);
        });

        wsClient.on("FILE_END", async (envelope) => {
          if (!fileTransferManager) return;
          console.log("[Main] Routing FILE_END to FileTransferManager");
          await fileTransferManager.handleFileEnd(envelope);
        });

        // Set up file transfer callbacks
        fileTransferManager.onProgress(handleFileProgress);
        fileTransferManager.onComplete(handleFileComplete);
        fileTransferManager.onError(handleFileError);

        // Set up file command callback
        messaging.onFileCommand(handleFileCommand);
        
        console.log("[Main] FileTransferManager initialized and wired up");
      } else {
        console.warn("[Main] FileTransferManager not available - file transfer disabled");
      }

      // User list updates
      messaging.onUserListUpdate((users) => {
        renderUserList(users);
      });

      // Message reception
      messaging.onMessage((message) => {
        renderMessage(message);
      });

      // Errors
      messaging.onError((error) => {
        showError(error);
      });

      console.log("[Main] All managers and handlers initialized");
    } else {
      const missing = [];
      if (!messaging) missing.push("MessagingManager");
      if (!wsClient) missing.push("WebSocketClient");
      if (!sessionManager) missing.push("SessionManager");
      throw new Error(`Failed to initialize managers: missing ${missing.join(", ")}`);
    }

    // Update UI
    const session = sessionManager.getSession();
    if (session) {
      userIdDisplay.textContent = `User: ${
        session.displayName || session.userId.substring(0, 12)
      }...`;
    }

    // Hide auth overlay
    authOverlay.classList.add("hidden");

    // Auto-execute /list
    setTimeout(() => {
      commandInput.value = "/list";
      handleSendCommand();
    }, 500);
  } catch (error) {
    console.error("[Main] Login failed:", error);
    showError("Login failed: " + (error as Error).message);
    quickLoginBtn.disabled = false;
    quickLoginBtn.textContent = "Quick Login";
  }
}

async function handleSendCommand(): Promise<void> {
  const command = commandInput.value.trim();

  if (!command) {
    return;
  }

  if (!app) {
    showError("Not connected");
    return;
  }

  sendBtn.disabled = true;

  try {
    await app.executeCommand(command);
    commandInput.value = "";
  } catch (error) {
    console.error("[Main] Command failed:", error);
    showError("Command failed: " + (error as Error).message);
  } finally {
    sendBtn.disabled = false;
    commandInput.focus();
  }
}

function handleDisconnect(): void {
  if (app) {
    app.disconnect();
    app = null;
  }

  fileTransferManager = null;
  pendingFileRecipient = null;
  activeTransfers.clear();

  // Reset UI
  authOverlay.classList.remove("hidden");
  userList.innerHTML =
    '<div style="padding: 20px; text-align: center; color: #6c757d; font-size: 13px;">Click "/list" to load users</div>';
  messagesContainer.innerHTML =
    '<div class="message message-system">Welcome! Use /list to see users, /tell &lt;user&gt; &lt;msg&gt; for DM, /all &lt;msg&gt; for broadcast, /file &lt;user&gt; [path] for file transfer</div>';
  commandInput.value = "";
  userCount.textContent = "0";
  userIdDisplay.textContent = "User: -";
  fileTransferSection.innerHTML = "";
  fileTransferSection.classList.remove("show");

  loginPassword.value = "";
  quickLoginBtn.disabled = false;
  quickLoginBtn.textContent = "Quick Login";
}

// ============================================================================
// Event Listeners
// ============================================================================

quickLoginBtn.addEventListener("click", handleQuickLogin);
sendBtn.addEventListener("click", handleSendCommand);
disconnectBtn.addEventListener("click", handleDisconnect);
refreshUsersBtn.addEventListener("click", () => {
  commandInput.value = "/list";
  handleSendCommand();
});

commandInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    handleSendCommand();
  }
});

loginPassword.addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    handleQuickLogin();
  }
});

fileInput.addEventListener("change", handleFileSelection);

// ============================================================================
// Initialization
// ============================================================================

console.log("[Main] Phase 6.3-6.4 Messaging + File Transfer UI loaded");
console.log("[Main] Commands: /list, /tell <user> <msg>, /all <msg>, /file <user> [path]");

// Try to restore session if exists
const existingSession = sessionStorage.getItem("socp_session_active");
if (existingSession) {
  console.log(
    "[Main] Found existing session - you may need to login again for Phase 6.3-6.4"
  );
}
