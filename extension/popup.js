/**
 * AI Sentinel - Popup Dashboard Controller
 * Connects the extension popup interface to the Python Flask backend,
 * displaying real-time AI security assessments, risk scores, heuristics,
 * and safety recommendations.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // UI State Containers
  const stateLoading = document.getElementById("state-loading");
  const stateError = document.getElementById("state-error");
  const stateInternal = document.getElementById("state-internal");
  const stateResult = document.getElementById("state-result");

  // Elements
  const currentUrlEl = document.getElementById("current-url");
  const copyUrlBtn = document.getElementById("copy-url-btn");
  const rescanBtn = document.getElementById("rescan-btn");
  const retryBtn = document.getElementById("retry-scan-btn");
  const warningBanner = document.getElementById("prominent-warning-banner");

  const backendPill = document.getElementById("backend-status-pill");
  const backendPillText = document.getElementById("backend-status-text");

  // HUD & Metrics
  const riskScoreValueEl = document.getElementById("risk-score-value");
  const gaugeProgressEl = document.getElementById("gauge-progress");
  const statusPillEl = document.getElementById("status-pill");
  const statusTextEl = document.getElementById("status-text");
  const threatSummaryEl = document.getElementById("threat-summary");

  const metricSslEl = document.getElementById("metric-ssl");
  const metricKeywordsEl = document.getElementById("metric-keywords");
  const metricSafebrowsingEl = document.getElementById("metric-safebrowsing");
  const metricDomainEl = document.getElementById("metric-domain");

  const reasonsListEl = document.getElementById("detection-reasons-list");
  const recommendationTextEl = document.getElementById("recommendation-text");
  const errorMessageEl = document.getElementById("error-message");

  let activeTab = null;

  // ---------------------------------------------------------------------------
  // Helper: Switch View State
  // ---------------------------------------------------------------------------
  function showState(state) {
    stateLoading.classList.add("hidden");
    stateError.classList.add("hidden");
    stateInternal.classList.add("hidden");
    stateResult.classList.add("hidden");

    if (state === "loading") {
      stateLoading.classList.remove("hidden");
      warningBanner.classList.add("hidden");
    } else if (state === "error") {
      stateError.classList.remove("hidden");
      warningBanner.classList.add("hidden");
    } else if (state === "internal") {
      stateInternal.classList.remove("hidden");
      warningBanner.classList.add("hidden");
    } else if (state === "result") {
      stateResult.classList.remove("hidden");
    }
  }

  // ---------------------------------------------------------------------------
  // Helper: URL Validation & Scheme Check
  // ---------------------------------------------------------------------------
  function isInternalUrl(url) {
    if (!url) return true;
    const internalPrefixes = [
      "chrome://",
      "chrome-extension://",
      "edge://",
      "about:",
      "devtools://",
      "view-source:",
      "file://"
    ];
    return internalPrefixes.some(prefix => url.startsWith(prefix));
  }

  // ---------------------------------------------------------------------------
  // Backend Connectivity Check
  // ---------------------------------------------------------------------------
  async function checkBackendHealth() {
    try {
      chrome.runtime.sendMessage({ action: "CHECK_BACKEND_HEALTH" }, (res) => {
        if (chrome.runtime.lastError || !res || !res.online) {
          backendPill.className = "status-pill status-offline";
          backendPillText.textContent = "Offline";
        } else {
          backendPill.className = "status-pill status-online";
          backendPillText.textContent = "Online";
        }
      });
    } catch (_) {
      backendPill.className = "status-pill status-offline";
      backendPillText.textContent = "Offline";
    }
  }

  // ---------------------------------------------------------------------------
  // Render Scan Results
  // ---------------------------------------------------------------------------
  function renderScanResult(data) {
    if (!data) {
      showState("error");
      errorMessageEl.textContent = "No scan data available for this page.";
      return;
    }

    if (data.isInternal) {
      showState("internal");
      return;
    }

    if (data.error) {
      showState("error");
      errorMessageEl.textContent = data.errorMessage || "Detection backend unreachable.";
      backendPill.className = "status-pill status-offline";
      backendPillText.textContent = "Offline";
      return;
    }

    showState("result");
    backendPill.className = "status-pill status-online";
    backendPillText.textContent = "Online";

    const riskScore = typeof data.risk_score === "number" ? data.risk_score : 0;
    const category = data.category || (riskScore <= 30 ? "Low Risk" : (riskScore <= 60 ? "Medium Risk" : "High Risk"));
    const status = (data.safety_status || "Safe").toUpperCase();

    // 1. Update Gauge & Score
    riskScoreValueEl.textContent = riskScore;
    const circumference = 314.16; // 2 * pi * 50
    const offset = circumference - (circumference * (riskScore / 100));
    gaugeProgressEl.style.strokeDashoffset = offset;

    // 2. Status Badge & Colors (Visual Risk Indicator)
    // 0–30: Low Risk (Green), 31–60: Medium Risk (Yellow), 61–100: High Risk (Red)
    statusPillEl.className = "assessment-badge";
    if (category === "High Risk" || riskScore >= 61) {
      statusPillEl.classList.add("status-malicious");
      statusTextEl.textContent = "HIGH RISK";
      gaugeProgressEl.style.stroke = "var(--color-malicious)"; // Red (#EF4444)
      threatSummaryEl.textContent = data.ai_generated_explanation || data.explanation || "Severe security threat detected. High phishing probability.";
      warningBanner.classList.remove("hidden");
    } else if (category === "Medium Risk" || riskScore >= 31) {
      statusPillEl.classList.add("status-suspicious");
      statusTextEl.textContent = "MEDIUM RISK";
      gaugeProgressEl.style.stroke = "var(--color-suspicious)"; // Yellow (#F59E0B)
      threatSummaryEl.textContent = data.ai_generated_explanation || data.explanation || "Anomalous indicators found. Proceed with caution.";
      warningBanner.classList.add("hidden");
    } else {
      statusPillEl.classList.add("status-safe");
      statusTextEl.textContent = "LOW RISK";
      gaugeProgressEl.style.stroke = "var(--color-safe)"; // Green (#10B981)
      threatSummaryEl.textContent = data.ai_generated_explanation || data.explanation || "No phishing indicators detected. Connection verified.";
      warningBanner.classList.add("hidden");
    }

    // 3. Heuristics Grid
    if (data.features) {
      // SSL
      if (data.features.is_https === 1) {
        metricSslEl.textContent = "HTTPS (Secure)";
        metricSslEl.style.color = "var(--color-safe)";
      } else {
        metricSslEl.textContent = "HTTP (Insecure)";
        metricSslEl.style.color = "var(--color-malicious)";
      }

      // Keywords
      const kwCount = data.features.suspicious_keyword_count || 0;
      metricKeywordsEl.textContent = `${kwCount} Found`;
      metricKeywordsEl.style.color = kwCount > 0 ? "var(--color-suspicious)" : "var(--color-safe)";

      // Domain Length
      const domLen = data.features.domain_length || 0;
      metricDomainEl.textContent = `${domLen} chars`;
    }

    // Safe Browsing
    if (data.safe_browsing) {
      if (data.safe_browsing.is_threat) {
        metricSafebrowsingEl.textContent = "Flagged Threat";
        metricSafebrowsingEl.style.color = "var(--color-malicious)";
      } else if (data.safe_browsing.checked) {
        metricSafebrowsingEl.textContent = "Verified Safe";
        metricSafebrowsingEl.style.color = "var(--color-safe)";
      } else {
        metricSafebrowsingEl.textContent = "AI Analysis Only";
        metricSafebrowsingEl.style.color = "var(--text-secondary)";
      }
    }

    // 4. Detected Phishing Indicators
    reasonsListEl.innerHTML = "";
    const indicators = data.detected_indicators || (data.threat_explanation && data.threat_explanation.detected_indicators) || [];
    if (indicators.length > 0) {
      indicators.forEach(ind => {
        const li = document.createElement("li");
        li.className = "reason-item";
        if (category === "High Risk" || riskScore >= 61) {
          li.classList.add("danger-indicator");
        }
        li.textContent = ind;
        reasonsListEl.appendChild(li);
      });
    } else {
      const rawReason = data.detection_reason || data.explanation || "";
      const reasons = rawReason.split(";").map(r => r.trim()).filter(Boolean);
      if (reasons.length === 0) {
        const li = document.createElement("li");
        li.className = "reason-item";
        li.textContent = "No suspicious indicators identified by AI Sentinel.";
        reasonsListEl.appendChild(li);
      } else {
        reasons.forEach(r => {
          const li = document.createElement("li");
          li.className = "reason-item";
          if (category === "High Risk" || riskScore >= 61) {
            li.classList.add("danger-indicator");
          }
          li.textContent = r;
          reasonsListEl.appendChild(li);
        });
      }
    }

    // 5. Potential Risks to Users
    const userRisksListEl = document.getElementById("user-risks-list");
    if (userRisksListEl) {
      userRisksListEl.innerHTML = "";
      const risks = data.user_risks || (data.threat_explanation && data.threat_explanation.user_risks) || [];
      if (risks.length === 0) {
        const li = document.createElement("li");
        li.className = "reason-item";
        li.textContent = "No severe risk exposure identified.";
        userRisksListEl.appendChild(li);
      } else {
        risks.forEach(risk => {
          const li = document.createElement("li");
          li.className = "reason-item";
          if (category === "High Risk" || riskScore >= 61) {
            li.classList.add("danger-indicator");
          }
          li.textContent = risk;
          userRisksListEl.appendChild(li);
        });
      }
    }

    // 6. RAG Cybersecurity Knowledge Base Insights
    const ragContextListEl = document.getElementById("rag-context-list");
    if (ragContextListEl) {
      ragContextListEl.innerHTML = "";
      const retrieved = data.retrieved_security_info || [];
      if (retrieved.length === 0) {
        const item = document.createElement("div");
        item.className = "rag-item";
        item.textContent = data.rag_summary || "Cybersecurity baseline verified against safe navigation standards.";
        ragContextListEl.appendChild(item);
      } else {
        retrieved.forEach(chunk => {
          const item = document.createElement("div");
          item.className = "rag-item";

          const meta = document.createElement("div");
          meta.className = "rag-meta";

          const badge = document.createElement("span");
          badge.className = "rag-topic-badge";
          badge.textContent = chunk.topic || "Threat Intelligence";

          const score = document.createElement("span");
          score.className = "rag-score-pill";
          const pct = Math.round((chunk.similarity_score || 0) * 100);
          score.textContent = `Match: ${pct}%`;

          meta.appendChild(badge);
          meta.appendChild(score);

          const snippet = document.createElement("div");
          snippet.className = "rag-snippet";
          snippet.textContent = chunk.content;

          item.appendChild(meta);
          item.appendChild(snippet);
          ragContextListEl.appendChild(item);
        });
      }
    }

    // 7. Safety Recommendations
    const recommendations = (data.threat_explanation && data.threat_explanation.recommendations) || data.recommendations || [];
    if (recommendations.length > 0) {
      recommendationTextEl.innerHTML = "";
      recommendations.forEach(rec => {
        const div = document.createElement("div");
        div.style.marginBottom = "4px";
        div.textContent = `• ${rec}`;
        recommendationTextEl.appendChild(div);
      });
    } else {
      recommendationTextEl.textContent = data.safety_recommendation || data.recommendation || "Maintain caution when browsing untrusted links.";
    }
  }

  // ---------------------------------------------------------------------------
  // Load Active Tab & Initiate Scan
  // ---------------------------------------------------------------------------
  async function init() {
    showState("loading");
    checkBackendHealth();

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      activeTab = tab;

      if (!activeTab || !activeTab.url) {
        currentUrlEl.textContent = "No active tab detected";
        showState("internal");
        return;
      }

      currentUrlEl.textContent = activeTab.url;
      currentUrlEl.title = activeTab.url;

      if (isInternalUrl(activeTab.url)) {
        showState("internal");
        return;
      }

      // Query background service worker for cached or fresh scan result
      chrome.runtime.sendMessage(
        { action: "GET_TAB_SCAN", tabId: activeTab.id, url: activeTab.url },
        (response) => {
          if (chrome.runtime.lastError) {
            showState("error");
            errorMessageEl.textContent = "Extension communication error: " + chrome.runtime.lastError.message;
            return;
          }
          renderScanResult(response);
        }
      );
    } catch (err) {
      showState("error");
      errorMessageEl.textContent = "Failed to query active tab: " + err.message;
    }
  }

  // ---------------------------------------------------------------------------
  // Event Listeners
  // ---------------------------------------------------------------------------

  // Rescan Button
  rescanBtn.addEventListener("click", () => {
    if (!activeTab || !activeTab.url || isInternalUrl(activeTab.url)) return;

    showState("loading");
    checkBackendHealth();

    chrome.runtime.sendMessage(
      { action: "RESCAN_TAB", tabId: activeTab.id, url: activeTab.url },
      (response) => {
        if (chrome.runtime.lastError) {
          showState("error");
          errorMessageEl.textContent = "Rescan failed: " + chrome.runtime.lastError.message;
          return;
        }
        renderScanResult(response);
      }
    );
  });

  // Retry Connection Button
  retryBtn.addEventListener("click", () => {
    init();
  });

  // Copy URL Button
  copyUrlBtn.addEventListener("click", async () => {
    if (!activeTab || !activeTab.url) return;
    try {
      await navigator.clipboard.writeText(activeTab.url);
      copyUrlBtn.title = "Copied to clipboard!";
      setTimeout(() => {
        copyUrlBtn.title = "Copy URL";
      }, 1500);
    } catch (_) {}
  });

  // Start initialization
  init();
});
