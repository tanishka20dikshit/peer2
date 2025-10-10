/**
 * Phase 6.4: File Transfer Manager
 * 
 * Handles encrypted file transfer using RSA-OAEP per Protocol §9.4
 * - 446-byte chunks (RSA-4096 OAEP max plaintext)
 * - SHA-256 integrity verification
 * - Progress tracking
 * - Multiple concurrent transfers
 */

import { WebSocketClient } from "./websocket";
import { SessionManager } from "./session";
import { MessagingManager } from "./messaging";
import {
  rsaOaepEncrypt,
  rsaOaepDecrypt,
  RSA_OAEP_MAX_PLAINTEXT,
  hashFile,
  hashBytes,
} from "./crypto";
import {
  buildFileStart,
  buildFileChunk,
  buildFileEnd,
  type Envelope,
} from "./protocol";
import { base64urlEncode, base64urlDecode } from "./utils";

// ============================================================================
// Constants
// ============================================================================

const CHUNK_SIZE = RSA_OAEP_MAX_PLAINTEXT; // 446 bytes
const CHUNK_DELAY_MS = 10; // Delay between chunk sends

// ============================================================================
// Types
// ============================================================================

export interface SendTransfer {
  fileId: string;
  fileName: string;
  fileSize: number;
  recipientId: string;
  chunks: Uint8Array[];
  chunksSent: number;
  totalChunks: number;
  sha256: string;
  startTime: number;
  status: "preparing" | "sending" | "complete" | "failed";
}

export interface ReceiveTransfer {
  fileId: string;
  fileName: string;
  fileSize: number;
  senderId: string;
  chunks: (Uint8Array | null)[]; // Null for missing chunks
  chunksReceived: number;
  totalChunks: number;
  expectedSha256: string;
  startTime: number;
  status: "receiving" | "complete" | "failed";
}

export interface FileProgress {
  fileId: string;
  fileName: string;
  direction: "send" | "receive";
  progress: number; // 0-100
  status: string;
  chunksSent?: number;
  chunksReceived?: number;
  totalChunks: number;
  totalSize: number; // ← Add this
  peer: string; // ← Add this (recipient ID for send, sender ID for receive)
}

export interface FileComplete {
  fileId: string;
  fileName: string;
  data?: Uint8Array; // File data for receiver
  peer: string; // Recipient ID for sender, sender ID for receiver
}

// ============================================================================
// FileTransferManager
// ============================================================================

export class FileTransferManager {
  private wsClient: WebSocketClient;
  private sessionManager: SessionManager;
  private messaging: MessagingManager;

  // State
  private activeSends: Map<string, SendTransfer> = new Map();
  private activeReceives: Map<string, ReceiveTransfer> = new Map();

  // Callbacks
  private progressCallbacks: ((progress: FileProgress) => void)[] = [];
  private completeCallbacks: ((complete: FileComplete) => void)[] = [];
  private errorCallbacks: ((error: string) => void)[] = [];

  constructor(
    wsClient: WebSocketClient,
    sessionManager: SessionManager,
    messaging: MessagingManager
  ) {
    this.wsClient = wsClient;
    this.sessionManager = sessionManager;
    this.messaging = messaging;

    console.log("[FileTransfer] Manager initialized");
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  /**
   * Send a file to a recipient
   * Protocol §9.4: FILE_START → FILE_CHUNK(s) → FILE_END
   */
  async sendFile(recipientId: string, file: File): Promise<void> {
    console.log(`[FileTransfer] Starting file transfer to ${recipientId}`);
    console.log(`[FileTransfer] File: ${file.name} (${file.size} bytes)`);

    try {
      // Generate file ID
      const fileId = crypto.randomUUID();

      // Calculate SHA-256 hash
      const sha256 = await hashFile(file);
      console.log(`[FileTransfer] SHA-256: ${sha256}`);

      // Read file data
      const fileData = new Uint8Array(await file.arrayBuffer());

      // Split into chunks
      const chunks = this.splitIntoChunks(fileData);
      console.log(`[FileTransfer] Split into ${chunks.length} chunks`);

      // Create transfer state
      const transfer: SendTransfer = {
        fileId,
        fileName: file.name,
        fileSize: file.size,
        recipientId,
        chunks,
        chunksSent: 0,
        totalChunks: chunks.length,
        sha256,
        startTime: Date.now(),
        status: "preparing",
      };

      this.activeSends.set(fileId, transfer);

      // Get recipient's public key
      const recipientPubkey = await this.messaging.getRecipientPublicKey(
        recipientId
      );
      if (!recipientPubkey) {
        throw new Error(`Could not fetch public key for ${recipientId}`);
      }

      // Send FILE_START
      await this.sendFileStart(transfer);

      // Update status
      transfer.status = "sending";

      // Send chunks with encryption
      await this.sendChunks(transfer, recipientPubkey);

      // Send FILE_END
      await this.sendFileEnd(transfer);

      // Mark complete
      transfer.status = "complete";
      
      // Notify final progress
      this.notifyProgress({
        fileId: transfer.fileId,
        fileName: transfer.fileName,
        direction: "send",
        progress: 100,
        status: "complete",
        chunksSent: transfer.chunksSent,
        totalChunks: transfer.totalChunks,
        totalSize: transfer.fileSize,
        peer: transfer.recipientId,
      });
      
      // Notify completion
      this.notifyComplete({
        fileId,
        fileName: file.name,
        peer: recipientId,  // ← Add this field
      });

      console.log(`[FileTransfer] Transfer complete: ${fileId}`);
    } catch (error) {
      console.error("[FileTransfer] Send error:", error);
      this.notifyError(`Failed to send file: ${(error as Error).message}`);
      throw error;
    }
  }

  /**
   * Handle incoming FILE_START message
   */
  handleFileStart(envelope: Envelope): void {
    console.log("[FileTransfer] Received FILE_START");

    try {
      const payload = envelope.payload;
      const fileId = payload.file_id;
      const fileName = payload.name;
      const fileSize = payload.size;
      const expectedSha256 = payload.sha256;
      const senderId = envelope.from;

      // Calculate expected chunks
      const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);

      // Create receive transfer state
      const transfer: ReceiveTransfer = {
        fileId,
        fileName,
        fileSize,
        senderId,
        chunks: new Array(totalChunks).fill(null),
        chunksReceived: 0,
        totalChunks,
        expectedSha256,
        startTime: Date.now(),
        status: "receiving",
      };

      this.activeReceives.set(fileId, transfer);

      console.log(
        `[FileTransfer] Receiving ${fileName} (${fileSize} bytes, ${totalChunks} chunks)`
      );

      this.notifyProgress({
        fileId,
        fileName,
        direction: "receive",
        progress: 0,
        status: "receiving",
        chunksReceived: 0,
        totalChunks,
        totalSize: fileSize,
        peer: senderId,
      });
    } catch (error) {
      console.error("[FileTransfer] FILE_START error:", error);
      this.notifyError(`Failed to start receiving file: ${(error as Error).message}`);
    }
  }

  /**
   * Handle incoming FILE_CHUNK message
   */
  async handleFileChunk(envelope: Envelope): Promise<void> {
    try {
      const payload = envelope.payload;
      const fileId = payload.file_id;
      const index = payload.index;
      const ciphertextB64 = payload.ciphertext;

      const transfer = this.activeReceives.get(fileId);
      if (!transfer) {
        console.error(`[FileTransfer] No active receive for ${fileId}`);
        return;
      }

      // Decrypt chunk
      const encryptionKeypair = this.sessionManager.getEncryptionKeypair();
      if (!encryptionKeypair) {
        throw new Error("No encryption keypair available");
      }

      const ciphertextBytes = base64urlDecode(ciphertextB64);
      const plaintextBytes = await rsaOaepDecrypt(
        encryptionKeypair.privateKey,
        ciphertextBytes
      );
      const chunk = new Uint8Array(plaintextBytes);

      // Store chunk at correct index
      transfer.chunks[index] = chunk;
      transfer.chunksReceived++;

      // Update progress
      const progress = Math.round(
        (transfer.chunksReceived / transfer.totalChunks) * 100
      );

      console.log(
        `[FileTransfer] Chunk ${index + 1}/${transfer.totalChunks} received (${progress}%)`
      );

      this.notifyProgress({
        fileId,
        fileName: transfer.fileName,
        direction: "receive",
        progress,
        status: `Receiving chunk ${index + 1}/${transfer.totalChunks}`,
        chunksReceived: transfer.chunksReceived,
        totalChunks: transfer.totalChunks,
        totalSize: transfer.fileSize,
        peer: transfer.senderId,
      });
    } catch (error) {
      console.error("[FileTransfer] FILE_CHUNK error:", error);
      this.notifyError(`Failed to receive chunk: ${(error as Error).message}`);
    }
  }

  /**
   * Handle incoming FILE_END message
   */
  async handleFileEnd(envelope: Envelope): Promise<void> {
    console.log("[FileTransfer] Received FILE_END");

    try {
      const payload = envelope.payload;
      const fileId = payload.file_id;

      const transfer = this.activeReceives.get(fileId);
      if (!transfer) {
        console.error(`[FileTransfer] No active receive for ${fileId}`);
        return;
      }

      // Add a small delay to ensure all chunks are processed
      // This handles the race condition where FILE_END arrives before FILE_CHUNK is decrypted
      await new Promise(resolve => setTimeout(resolve, 50));

      // Check if all chunks received
      const missingChunks: number[] = [];
      for (let i = 0; i < transfer.totalChunks; i++) {
        if (transfer.chunks[i] === null) {
          missingChunks.push(i);
        }
      }

      if (missingChunks.length > 0) {
        throw new Error(`Missing ${missingChunks.length} chunks: ${missingChunks.join(", ")}`);
      }

      // Reassemble file
      const fileData = this.reassembleFile(transfer.chunks as Uint8Array[]);

      // Verify SHA-256 hash
      const actualHash = await hashBytes(fileData);
      if (actualHash !== transfer.expectedSha256) {
        throw new Error(
          `Hash mismatch! Expected: ${transfer.expectedSha256}, Got: ${actualHash}`
        );
      }

      console.log("[FileTransfer] SHA-256 verified ✓");

      // Mark complete
      transfer.status = "complete";

      // DON'T trigger download automatically - let UI handle it
      // this.triggerDownload(fileData, transfer.fileName);  // ← REMOVE THIS LINE

      // Notify with file data so UI can show download button
      this.notifyComplete({
        fileId,
        fileName: transfer.fileName,
        data: fileData,  // ← Add this
        peer: transfer.senderId,
      });

      // Cleanup
      this.activeReceives.delete(fileId);

      console.log(`[FileTransfer] File received successfully: ${transfer.fileName}`);
    } catch (error) {
      console.error("[FileTransfer] FILE_END error:", error);
      this.notifyError(`Failed to complete file transfer: ${(error as Error).message}`);

      const payload = envelope.payload;
      const fileId = payload.file_id;
      const transfer = this.activeReceives.get(fileId);

      if (transfer) {
        transfer.status = "failed";
        this.notifyComplete({
          fileId,
          fileName: transfer.fileName,
          direction: "receive",
          success: false,
          error: (error as Error).message,
        });
        this.activeReceives.delete(fileId);
      }
    }
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  /**
   * Split file data into 446-byte chunks
   */
  private splitIntoChunks(data: Uint8Array): Uint8Array[] {
    const chunks: Uint8Array[] = [];

    for (let i = 0; i < data.length; i += CHUNK_SIZE) {
      const chunk = data.slice(i, i + CHUNK_SIZE);
      chunks.push(chunk);
    }

    return chunks;
  }

  /**
   * Send FILE_START message
   */
  private async sendFileStart(transfer: SendTransfer): Promise<void> {
    const userId = this.sessionManager.getUserId();
    if (!userId) throw new Error("Not logged in");

    const envelope = buildFileStart(
      userId,
      transfer.recipientId,
      transfer.fileId,
      transfer.fileName,
      transfer.fileSize,
      transfer.sha256,
      "dm"
    );

    this.wsClient.send(envelope);
    console.log("[FileTransfer] Sent FILE_START");
  }

  /**
   * Send encrypted file chunks with delay
   */
  private async sendChunks(
    transfer: SendTransfer,
    recipientPubkey: CryptoKey
  ): Promise<void> {
    const userId = this.sessionManager.getUserId();
    if (!userId) throw new Error("Not logged in");

    for (let i = 0; i < transfer.chunks.length; i++) {
      const chunk = transfer.chunks[i];

      // Encrypt chunk
      const ciphertext = await rsaOaepEncrypt(recipientPubkey, chunk);
      const ciphertextB64 = base64urlEncode(ciphertext);

      // Build and send FILE_CHUNK
      const envelope = buildFileChunk(
        userId,
        transfer.recipientId,
        transfer.fileId,
        i,
        ciphertextB64
      );

      this.wsClient.send(envelope);

      transfer.chunksSent = i + 1;

      // Update progress
      const progress = Math.round(
        (transfer.chunksSent / transfer.totalChunks) * 100
      );
      this.notifyProgress({
        fileId: transfer.fileId,
        fileName: transfer.fileName,
        direction: "send",
        progress,
        status: `sending`,
        chunksSent: transfer.chunksSent,
        totalChunks: transfer.totalChunks,
        totalSize: transfer.fileSize,
        peer: transfer.recipientId,
      });

      // Delay between chunks to avoid overwhelming backend
      if (i < transfer.chunks.length - 1) {
        await this.delay(CHUNK_DELAY_MS);
      }
    }

    console.log(`[FileTransfer] Sent ${transfer.chunks.length} chunks`);
  }

  /**
   * Send FILE_END message
   */
  private async sendFileEnd(transfer: SendTransfer): Promise<void> {
    const userId = this.sessionManager.getUserId();
    if (!userId) throw new Error("Not logged in");

    const envelope = buildFileEnd(
      userId,
      transfer.recipientId,
      transfer.fileId
    );

    this.wsClient.send(envelope);
    console.log("[FileTransfer] Sent FILE_END");
  }

  /**
   * Reassemble file from chunks
   */
  private reassembleFile(chunks: Uint8Array[]): Uint8Array {
    const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const fileData = new Uint8Array(totalSize);

    let offset = 0;
    for (const chunk of chunks) {
      fileData.set(chunk, offset);
      offset += chunk.length;
    }

    return fileData;
  }

  /**
   * Trigger browser download
   */
  private triggerDownload(data: Uint8Array, fileName: string): void {
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();

    // Cleanup
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);

    console.log(`[FileTransfer] Download triggered: ${fileName}`);
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ==========================================================================
  // Callbacks
  // ==========================================================================

  onProgress(callback: (progress: FileProgress) => void): void {
    this.progressCallbacks.push(callback);
  }

  onComplete(callback: (complete: FileComplete) => void): void {
    this.completeCallbacks.push(callback);
  }

  onError(callback: (error: string) => void): void {
    this.errorCallbacks.push(callback);
  }

  private notifyProgress(progress: FileProgress): void {
    this.progressCallbacks.forEach((cb) => {
      try {
        cb(progress);
      } catch (error) {
        console.error("[FileTransfer] Progress callback error:", error);
      }
    });
  }

  private notifyComplete(complete: FileComplete): void {
    this.completeCallbacks.forEach((cb) => {
      try {
        cb(complete);
      } catch (error) {
        console.error("[FileTransfer] Complete callback error:", error);
      }
    });
  }

  private notifyError(error: string): void {
    this.errorCallbacks.forEach((cb) => {
      try {
        cb(error);
      } catch (error) {
        console.error("[FileTransfer] Error callback error:", error);
      }
    });
  }
}
