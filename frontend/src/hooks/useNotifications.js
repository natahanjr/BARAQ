import { useEffect, useRef } from "react";
import { useToast } from "../components/ui/Toast.jsx";

export function useNotifications(token) {
  const wsRef = useRef(null);
  const { toast } = useToast();

  useEffect(() => {
    if (!token) return;

    const connect = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/api/realtime/ws?token=${token}`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          console.log("WebSocket connected");
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "hello") {
              console.log("WebSocket hello:", data.payload);
              return;
            }
            if (data.type === "alert") {
              toast.warning(`New alert: ${data.message || "Security event detected"}`);
            } else if (data.type === "incident") {
              toast.info(`Incident update: ${data.message || "Incident status changed"}`);
            } else if (data.type === "notification") {
              toast.info(data.message || "Notification received");
            }
          } catch (err) {
            console.error("WebSocket message parse error:", err);
          }
        };

        ws.onerror = (error) => {
          console.error("WebSocket error:", error);
        };

        ws.onclose = (event) => {
          console.log("WebSocket closed:", event.code);
          if (event.code !== 1000) {
            setTimeout(connect, 5000);
          }
        };
      } catch (err) {
        console.error("WebSocket connection error:", err);
        setTimeout(connect, 5000);
      }
    };

    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close(1000);
        wsRef.current = null;
      }
    };
  }, [token, toast]);

  return wsRef;
}
