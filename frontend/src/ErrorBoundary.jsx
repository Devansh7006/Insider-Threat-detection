import React from "react";

export default class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError && this.state.error) {
      return (
        <div style={{
          padding: 24,
          maxWidth: 600,
          margin: "40px auto",
          background: "rgba(255,255,255,0.05)",
          borderRadius: 12,
          fontFamily: "system-ui, sans-serif",
          color: "#eaf5f4",
        }}>
          <h2 style={{ margin: "0 0 12px 0", color: "#f87171" }}>Something went wrong</h2>
          <pre style={{
            margin: 0,
            padding: 12,
            background: "rgba(0,0,0,0.3)",
            borderRadius: 8,
            fontSize: 13,
            overflow: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}>
            {this.state.error.message}
          </pre>
          <p style={{ marginTop: 12, fontSize: 14, color: "#9fb4b9" }}>
            Check the browser console for details. Ensure the backend is running on port 8000.
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}
