/**
 * Phase 6.1: WebSocket Client
 * 
 * - WebSocket connection management
 * - Message sending/receiving
 * - Reconnection logic
 * - Event handling
 */

import { Envelope, MessageType } from './protocol';

// ============================================================================
// WebSocket Client
// ============================================================================

export type MessageHandler = (envelope: Envelope) => void;
export type ConnectionHandler = () => void;
export type ErrorHandler = (error: Error) => void;

export interface WebSocketClientOptions {
  url: string;
  reconnectInterval?: number;  // milliseconds
  maxReconnectAttempts?: number;
  debug?: boolean;
}

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectInterval: number;
  private maxReconnectAttempts: number;
  private reconnectAttempts: number = 0;
  private reconnectTimeout: number | null = null;
  private debug: boolean;
  
  // Event handlers
  private messageHandlers: Map<MessageType, MessageHandler[]> = new Map();
  private onConnectHandlers: ConnectionHandler[] = [];
  private onDisconnectHandlers: ConnectionHandler[] = [];
  private onErrorHandlers: ErrorHandler[] = [];
  
  // Connection state
  private isConnected: boolean = false;
  private shouldReconnect: boolean = true;
  
  // Message queue (for offline buffering)
  private messageQueue: string[] = [];
  private maxQueueSize: number = 100;

  constructor(options: WebSocketClientOptions) {
    this.url = options.url;
    this.reconnectInterval = options.reconnectInterval || 3000;
    this.maxReconnectAttempts = options.maxReconnectAttempts || 5;
    this.debug = options.debug || false;
  }

  /**
   * Connect to WebSocket server
   */
  connect(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      if (this.debug) console.log("[WS] Already connected");
      return;
    }

    if (this.debug) console.log(`[WS] Connecting to ${this.url}...`);

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        if (this.debug) console.log("[WS] Connected");
        this.isConnected = true;
        this.reconnectAttempts = 0;
        
        // Flush message queue
        this.flushMessageQueue();
        
        // Trigger connect handlers
        this.onConnectHandlers.forEach(handler => handler());
      };

      this.ws.onclose = (event) => {
        if (this.debug) console.log(`[WS] Disconnected (code: ${event.code})`);
        this.isConnected = false;
        this.ws = null;
        
        // Trigger disconnect handlers
        this.onDisconnectHandlers.forEach(handler => handler());
        
        // Attempt reconnection
        if (this.shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = (event) => {
        if (this.debug) console.error("[WS] Error:", event);
        const error = new Error("WebSocket error");
        this.onErrorHandlers.forEach(handler => handler(error));
      };

      this.ws.onmessage = (event) => {
        this.handleMessage(event.data);
      };

    } catch (error) {
      if (this.debug) console.error("[WS] Connection error:", error);
      this.onErrorHandlers.forEach(handler => handler(error as Error));
      
      if (this.shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.scheduleReconnect();
      }
    }
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    this.shouldReconnect = false;
    
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    if (this.ws) {
      if (this.debug) console.log("[WS] Disconnecting...");
      this.ws.close(1000, "Client disconnect");
      this.ws = null;
    }
    
    this.isConnected = false;
  }

  /**
   * Send a message envelope
   * 
   * @param envelope - Message to send
   */
  send(envelope: Envelope): void {
    const message = JSON.stringify(envelope);
    
    if (!this.isConnected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      if (this.debug) console.log("[WS] Not connected, queueing message");
      this.queueMessage(message);
      return;
    }

    try {
      this.ws.send(message);
      if (this.debug) console.log(`[WS] Sent: ${envelope.type}`);
    } catch (error) {
      if (this.debug) console.error("[WS] Send error:", error);
      this.queueMessage(message);
    }
  }

  /**
   * Register a message handler for a specific message type
   * 
   * @param type - Message type
   * @param handler - Handler function
   */
  on(type: MessageType, handler: MessageHandler): void {
    if (!this.messageHandlers.has(type)) {
      this.messageHandlers.set(type, []);
    }
    this.messageHandlers.get(type)!.push(handler);
  }

  /**
   * Remove a message handler
   * 
   * @param type - Message type
   * @param handler - Handler function to remove
   */
  off(type: MessageType, handler: MessageHandler): void {
    const handlers = this.messageHandlers.get(type);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  /**
   * Register a connection handler
   */
  onConnect(handler: ConnectionHandler): void {
    this.onConnectHandlers.push(handler);
  }

  /**
   * Register a disconnection handler
   */
  onDisconnect(handler: ConnectionHandler): void {
    this.onDisconnectHandlers.push(handler);
  }

  /**
   * Register an error handler
   */
  onError(handler: ErrorHandler): void {
    this.onErrorHandlers.push(handler);
  }

  /**
   * Get connection state
   */
  connected(): boolean {
    return this.isConnected;
  }

  /**
   * Get ready state
   */
  readyState(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private handleMessage(data: string): void {
    try {
      const envelope: Envelope = JSON.parse(data);
      
      console.log(`[WS] <<<< RECEIVED MESSAGE ====`);
      console.log(`[WS] Type: ${envelope.type}`);
      console.log(`[WS] From: ${envelope.from}`);
      console.log(`[WS] To: ${envelope.to}`);
      console.log(`[WS] Full data:`, envelope);

      // Call registered handlers
      const handlers = this.messageHandlers.get(envelope.type as MessageType);
      if (handlers) {
        console.log(`[WS] Found ${handlers.length} handler(s) for ${envelope.type}`);
        handlers.forEach((handler, index) => {
          try {
            console.log(`[WS] Calling handler ${index + 1} for ${envelope.type}`);
            handler(envelope);
          } catch (error) {
            console.error(`[WS] Handler error for ${envelope.type}:`, error);
          }
        });
      } else {
        console.warn(`[WS] ⚠️ No handler registered for ${envelope.type}`);
        console.warn(`[WS] Registered types:`, Array.from(this.messageHandlers.keys()));
      }
    } catch (error) {
      console.error("[WS] Message parse error:", error, data);
    }
  }

  private scheduleReconnect(): void {
    this.reconnectAttempts++;
    const delay = this.reconnectInterval * Math.pow(2, this.reconnectAttempts - 1);
    
    if (this.debug) {
      console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    }

    this.reconnectTimeout = window.setTimeout(() => {
      this.connect();
    }, delay);
  }

  private queueMessage(message: string): void {
    if (this.messageQueue.length >= this.maxQueueSize) {
      if (this.debug) console.warn("[WS] Message queue full, dropping oldest message");
      this.messageQueue.shift();
    }
    this.messageQueue.push(message);
  }

  private flushMessageQueue(): void {
    if (this.messageQueue.length === 0) return;
    
    if (this.debug) {
      console.log(`[WS] Flushing ${this.messageQueue.length} queued messages`);
    }

    while (this.messageQueue.length > 0 && this.isConnected) {
      const message = this.messageQueue.shift();
      if (message && this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(message);
      }
    }
  }
}
