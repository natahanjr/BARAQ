import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App.jsx";
import "./index.css";

class ErrorBoundary extends React.Component {
  state = { error: null, stack: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("SentinelSOC render error:", error, errorInfo?.componentStack);
    const stack = errorInfo?.componentStack || "";
    if (stack) this.setState({ stack });
    try {
      window.dispatchEvent(
        new CustomEvent("sentinel:render-error", {
          detail: String(error) + "\n" + stack,
        })
      );
    } catch {
      /* ignore */
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div
          style={{
            minHeight: "100vh",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "#0f172a",
            fontFamily: "system-ui, sans-serif",
            color: "#e2e8f0",
            padding: "24px",
          }}
        >
          <div style={{ maxWidth: "760px", width: "100%" }}>
            <div style={{ fontSize: "22px", fontWeight: 700, color: "#22d3ee", marginBottom: "8px" }}>
              SentinelSOC hit a rendering error
            </div>
            <pre
              style={{
                fontSize: "12px",
                color: "#fca5a5",
                background: "#1e293b",
                border: "1px solid #334155",
                borderRadius: "8px",
                padding: "12px",
                overflow: "auto",
                textAlign: "left",
                whiteSpace: "pre-wrap",
                maxHeight: "60vh",
              }}
            >
              {String(this.state.error)}
              {this.state.stack && "\n\nComponent stack:\n" + this.state.stack}
            </pre>
            <button
              type="button"
              onClick={() => window.location.reload()}
              style={{
                background: "#0e7490",
                color: "#fff",
                border: "0",
                borderRadius: "8px",
                padding: "10px 18px",
                fontSize: "14px",
                fontWeight: 600,
                cursor: "pointer",
                marginTop: "12px",
              }}
            >
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </BrowserRouter>
  </React.StrictMode>
);