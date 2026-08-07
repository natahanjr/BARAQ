import { useEffect, useRef, useState } from "react";
import { authStore } from "./api.js";

const WS_PATH = `${window.location.protocol === "https:" ? "wss" : "ws"}://${
  window.location.host
}/api/realtime/ws`;

let globalListeners = new Set();
let socket = null;
let reconnectDelay = 2000;
let retryTimer = null;

function connect() {
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const token = authStore.token;
  const url = token ? `${WS_PATH}?token=${encodeURIComponent(token)}` : WS_PATH;
  try {
    socket = new WebSocket(url);
  } catch {
    scheduleReconnect();
    return;
  }
  socket.onopen = () => {
    reconnectDelay = 2000;
  };
  socket.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }
    globalListeners.forEach((fn) => fn(msg));
  };
  socket.onclose = () => {
    socket = null;
    if (globalListeners.size > 0) scheduleReconnect();
  };
  socket.onerror = () => {
    try {
      socket.close();
    } catch {
      /* ignore */
    }
  };
}

function scheduleReconnect() {
  if (retryTimer || globalListeners.size === 0) return;
  retryTimer = setTimeout(() => {
    retryTimer = null;
    if (globalListeners.size > 0) {
      reconnectDelay = Math.min(reconnectDelay * 1.5, 30000);
      connect();
    }
  }, reconnectDelay);
}

/**
 * Subscribe to real-time backend events. Returns a boolean `connected`.
 * Reconnects automatically while any subscriber is active; the connection
 * drops when the user logs out (no token) and resumes after login.
 */
export function useRealtime(onMessage) {
  const [connected, setConnected] = useState(false);
  const listenerRef = useRef(onMessage);
  listenerRef.current = onMessage;

  useEffect(() => {
    const listener = (msg) => {
      if (msg.type === "hello") setConnected(true);
      else listenerRef.current?.(msg);
    };
    globalListeners.add(listener);
    connect();
    setConnected(Boolean(socket && socket.readyState === WebSocket.OPEN));
    return () => {
      globalListeners.delete(listener);
      if (globalListeners.size === 0 && socket) {
        try {
          socket.close();
        } catch {
          /* ignore */
        }
        socket = null;
        setConnected(false);
      }
    };
  }, []);

  return connected;
}
