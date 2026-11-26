/**
 * AI Sentinel - Content Script (Manifest V3)
 * Renders real-time security alerts directly in the active webpage view:
 * 1. Prominent Threat Warning Banner for High Risk / Malicious websites.
 * 2. Non-Disruptive Caution Banner for Medium Risk websites.
 * 
 * Strict Privacy & Transparency Guarantees:
 * - NEVER inspects, reads, or transmits passwords, form fields, cookies, or personal data.
 * - NEVER automatically blocks or forces unwanted redirections; empowers users with informed choices.
 */

(() => {
  // Prevent duplicate script execution
  if (window.__AI_SENTINEL_INJECTED__) return;
  window.__AI_SENTINEL_INJECTED__ = true;

  // Listen for real-time security alerts from background service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "DISPLAY_MALICIOUS_WARNING") {
      renderHighRiskBanner(message.data);
      sendResponse({ received: true });
    } else if (message.action === "DISPLAY_CAUTION_WARNING") {
      renderMediumRiskCaution(message.data);
      sendResponse({ received: true });
    }
  });

  /**
   * Renders prominent red warning overlay for High Risk / Malicious pages.
   */
  function renderHighRiskBanner(data) {
    if (!data) return;

    // Remove any existing banners
    removeExistingOverlays();

    const hostDiv = document.createElement("div");
    hostDiv.id = "ai-sentinel-threat-overlay";
    hostDiv.style.all = "initial";
    hostDiv.style.position = "fixed";
    hostDiv.style.top = "0";
    hostDiv.style.left = "0";
    hostDiv.style.width = "100%";
    hostDiv.style.zIndex = "2147483647";
    hostDiv.style.fontFamily = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";

    // Encapsulate styles with Shadow DOM to prevent host page collisions
    const shadow = hostDiv.attachShadow({ mode: "open" });

    const riskScore = data.risk_score !== null && data.risk_score !== undefined ? data.risk_score : 100;
    const category = data.category || (riskScore <= 30 ? "Low Risk" : (riskScore <= 60 ? "Medium Risk" : "High Risk"));
    const urlDisplay = data.url || window.location.href;
    const reason = data.ai_generated_explanation || data.explanation || data.detection_reason || "Identified as a high-risk phishing website.";
    const recommendation = data.safety_recommendation || data.recommendation || "Do not enter passwords, credit cards, or personal credentials.";

    const style = document.createElement("style");
    style.textContent = `
      :host {
        display: block;
        width: 100%;
        box-sizing: border-box;
      }
      .banner {
        background: linear-gradient(135deg, #18080a 0%, #2e090f 50%, #150508 100%);
        border-bottom: 3px solid #ef4444;
        box-shadow: 0 4px 30px rgba(239, 68, 68, 0.45), 0 0 16px rgba(239, 68, 68, 0.25);
        color: #f8fafc;
        padding: 16px 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 18px;
        flex-wrap: wrap;
        box-sizing: border-box;
        animation: slideDown 0.3s ease-out;
      }
      @keyframes slideDown {
        from { transform: translateY(-100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      .threat-info {
        display: flex;
        align-items: flex-start;
        gap: 16px;
        flex: 1 1 560px;
      }
      .threat-icon {
        width: 48px;
        height: 48px;
        border-radius: 10px;
        background: rgba(239, 68, 68, 0.2);
        border: 1px solid rgba(239, 68, 68, 0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        flex-shrink: 0;
        animation: pulse 1.6s infinite;
      }
      @keyframes pulse {
        0%, 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); }
        50% { transform: scale(1.05); box-shadow: 0 0 16px 4px rgba(239, 68, 68, 0.35); }
      }
      .threat-text {
        display: flex;
        flex-direction: column;
        gap: 5px;
      }
      .title-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
      }
      .title {
        font-size: 15px;
        font-weight: 800;
        letter-spacing: 0.6px;
        color: #fca5a5;
        text-transform: uppercase;
      }
      .badge-score {
        background: #ef4444;
        color: #ffffff;
        font-size: 11px;
        font-weight: 800;
        padding: 3px 9px;
        border-radius: 9999px;
        letter-spacing: 0.5px;
      }
      .url-bar {
        font-size: 11px;
        font-family: monospace;
        color: #fecaca;
        background: rgba(0, 0, 0, 0.35);
        padding: 2px 6px;
        border-radius: 4px;
        max-width: 500px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .desc {
        font-size: 12.5px;
        line-height: 1.45;
        color: #e2e8f0;
      }
      .recommendation {
        font-size: 12px;
        color: #f87171;
        font-weight: 700;
      }
      .actions {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-shrink: 0;
      }
      .btn {
        cursor: pointer;
        font-size: 12px;
        font-weight: 700;
        border-radius: 6px;
        padding: 9px 18px;
        transition: all 0.2s ease;
        border: none;
        outline: none;
      }
      .btn-exit {
        background: #ef4444;
        color: #ffffff;
        box-shadow: 0 2px 10px rgba(239, 68, 68, 0.4);
      }
      .btn-exit:hover {
        background: #dc2626;
        box-shadow: 0 4px 14px rgba(239, 68, 68, 0.6);
      }
      .btn-dismiss {
        background: transparent;
        color: #94a3b8;
        border: 1px solid #475569;
      }
      .btn-dismiss:hover {
        color: #f1f5f9;
        border-color: #64748b;
        background: rgba(255, 255, 255, 0.05);
      }
    `;

    const banner = document.createElement("div");
    banner.className = "banner";
    banner.innerHTML = `
      <div class="threat-info">
        <div class="threat-icon">⚠️</div>
        <div class="threat-text">
          <div class="title-row">
            <span class="title">AI Sentinel Security Alert — ${escapeHtml(category)}</span>
            <span class="badge-score">Risk: ${escapeHtml(String(riskScore))}/100</span>
            <span class="url-bar" title="${escapeHtml(urlDisplay)}">${escapeHtml(urlDisplay)}</span>
          </div>
          <div class="desc">${escapeHtml(reason)}</div>
          <div class="recommendation">Safety Recommendation: ${escapeHtml(recommendation)}</div>
        </div>
      </div>
      <div class="actions">
        <button id="ai-sentinel-exit-btn" class="btn btn-exit" title="Navigate away to safety">Safety Exit</button>
        <button id="ai-sentinel-dismiss-btn" class="btn btn-dismiss" title="Dismiss warning and continue at own risk">Dismiss</button>
      </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(banner);
    document.documentElement.appendChild(hostDiv);

    // Event Listeners (User-Controlled Action)
    shadow.getElementById("ai-sentinel-exit-btn").addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "https://www.google.com";
      }
    });

    shadow.getElementById("ai-sentinel-dismiss-btn").addEventListener("click", () => {
      hostDiv.remove();
    });
  }

  /**
   * Renders subtle amber caution banner for Medium Risk pages without disrupting normal browsing.
   */
  function renderMediumRiskCaution(data) {
    if (!data) return;

    removeExistingOverlays();

    const hostDiv = document.createElement("div");
    hostDiv.id = "ai-sentinel-caution-overlay";
    hostDiv.style.all = "initial";
    hostDiv.style.position = "fixed";
    hostDiv.style.top = "12px";
    hostDiv.style.right = "16px";
    hostDiv.style.maxWidth = "440px";
    hostDiv.style.zIndex = "2147483646";
    hostDiv.style.fontFamily = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";

    const shadow = hostDiv.attachShadow({ mode: "open" });

    const riskScore = data.risk_score || 45;
    const urlDisplay = data.url || window.location.href;
    const reason = data.ai_generated_explanation || data.explanation || "Anomalous indicators detected. Exercise caution.";
    const recommendation = data.safety_recommendation || data.recommendation || "Verify domain before submitting data.";

    const style = document.createElement("style");
    style.textContent = `
      .toast {
        background: linear-gradient(135deg, #1c1507 0%, #2b1f09 100%);
        border: 1px solid #f59e0b;
        border-left: 4px solid #f59e0b;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(245, 158, 11, 0.3);
        color: #f8fafc;
        padding: 12px 16px;
        display: flex;
        flex-direction: column;
        gap: 6px;
        animation: fadeIn 0.3s ease-out;
      }
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .toast-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .toast-title {
        font-size: 12px;
        font-weight: 800;
        color: #fde68a;
        text-transform: uppercase;
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .toast-badge {
        background: #f59e0b;
        color: #1c1917;
        font-size: 10px;
        font-weight: 800;
        padding: 2px 6px;
        border-radius: 4px;
      }
      .toast-close {
        cursor: pointer;
        background: transparent;
        border: none;
        color: #94a3b8;
        font-size: 14px;
        line-height: 1;
      }
      .toast-close:hover {
        color: #ffffff;
      }
      .toast-body {
        font-size: 11.5px;
        line-height: 1.4;
        color: #e2e8f0;
      }
      .toast-url {
        font-family: monospace;
        font-size: 10px;
        color: #fde68a;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .toast-rec {
        font-size: 11px;
        color: #fbbf24;
        font-weight: 600;
      }
    `;

    const toast = document.createElement("div");
    toast.className = "toast";
    toast.innerHTML = `
      <div class="toast-header">
        <span class="toast-title">
          <span>⚡</span> AI Sentinel Caution
        </span>
        <span class="toast-badge">Score: ${escapeHtml(String(riskScore))}/100</span>
        <button id="ai-sentinel-toast-close" class="toast-close" title="Dismiss notice">✕</button>
      </div>
      <div class="toast-url" title="${escapeHtml(urlDisplay)}">${escapeHtml(urlDisplay)}</div>
      <div class="toast-body">${escapeHtml(reason)}</div>
      <div class="toast-rec">${escapeHtml(recommendation)}</div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(toast);
    document.documentElement.appendChild(hostDiv);

    shadow.getElementById("ai-sentinel-toast-close").addEventListener("click", () => {
      hostDiv.remove();
    });
  }

  function removeExistingOverlays() {
    const existingThreat = document.getElementById("ai-sentinel-threat-overlay");
    if (existingThreat) existingThreat.remove();

    const existingCaution = document.getElementById("ai-sentinel-caution-overlay");
    if (existingCaution) existingCaution.remove();
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
})();
