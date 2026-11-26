/**
 * AI Sentinel - Background Service Worker (Manifest V3)
 * Handles automated real-time URL monitoring, communication with the Python Flask backend,
 * badge updates, in-flight scan synchronization, and security warning dispatching.
 */

const BACKEND_URL = "http://127.0.0.1:5000";
const SCAN_ENDPOINT = `${BACKEND_URL}/scan`;
const HEALTH_ENDPOINT = `${BACKEND_URL}/health`;

// In-memory cache for fast tab retrieval and preventing duplicate scans
const tabScanResults = new Map();

// Map of currently in-flight scan promises: tabId -> { url: string, promise: Promise }
const inFlightScans = new Map();

/**
 * Determines whether a URL is scannable (valid http/https and not internal).
 * Strictly ignores internal pages: chrome://, chrome-extension://, about:, etc.
 */
function isScannableUrl(url) {
  if (!url || typeof url !== "string") return false;
  const trimmed = url.trim();

  const unscannablePrefixes = [
    "chrome://",
    "chrome-extension://",
    "edge://",
    "about:",
    "devtools://",
    "view-source:",
    "file://",
    "data:",
    "javascript:"
  ];

  for (const prefix of unscannablePrefixes) {
    if (trimmed.startsWith(prefix)) {
      return false;
    }
  }

  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch (e) {
    return false;
  }
}

/**
 * Updates the action badge on the extension icon according to safety status.
 * Visual indicator mapping:
 * - Scanning : "..." (Blue #3B82F6)
 * - 0–30     : "LOW" (Green #10B981)
 * - 31–60    : "MED" (Yellow #F59E0B)
 * - 61–100   : "HIGH" (Red #EF4444)
 * - Error    : "ERR" (Red #EF4444)
 */
function updateBadge(tabId, status, score) {
  if (!tabId) return;

  let text = "";
  let color = "#6B7280";

  if (status === "scanning") {
    text = "...";
    color = "#3B82F6"; // Blue loading indicator
  } else if (status === "error") {
    text = "ERR";
    color = "#EF4444"; // Red error indicator
  } else if (status === "internal") {
    text = "";
    color = "#6B7280";
  } else if (status === "High Risk" || status === "Malicious" || (typeof score === "number" && score >= 61)) {
    text = "HIGH";
    color = "#EF4444"; // Red
  } else if (status === "Medium Risk" || status === "Suspicious" || (typeof score === "number" && score >= 31)) {
    text = "MED";
    color = "#F59E0B"; // Yellow
  } else if (status === "Low Risk" || status === "Safe" || (typeof score === "number" && score <= 30)) {
    text = "LOW";
    color = "#10B981"; // Green
  } else {
    text = "";
    color = "#6B7280";
  }

  chrome.action.setBadgeText({ tabId: tabId, text: text });
  chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
}

/**
 * Creates optional system desktop notification for critical threats.
 */
function notifyThreat(title, message) {
  if (chrome.notifications && typeof chrome.notifications.create === "function") {
    try {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: title,
        message: message,
        priority: 2
      }, () => {
        // Notification callback (ignore lastError if notifications disabled by OS)
        if (chrome.runtime.lastError) {}
      });
    } catch (_) {}
  }
}

/**
 * Scans a target URL by sending it to the AI Sentinel Flask backend.
 * Integrates deduplication, in-flight reuse, timeout management, and notification dispatch.
 */
async function scanUrl(url, tabId, force = false) {
  if (!isScannableUrl(url)) {
    const internalResult = {
      isInternal: true,
      url: url,
      category: "Internal",
      safety_status: "Internal",
      risk_score: null,
      detection_reason: "Internal browser page protected by browser sandbox.",
      recommendation: "Browser system pages (chrome://, about:) are isolated and not subject to external phishing.",
      timestamp: Date.now()
    };
    tabScanResults.set(tabId, internalResult);
    updateBadge(tabId, "internal");
    return internalResult;
  }

  const cleanUrl = url.trim();

  // 1. Check memory cache to avoid duplicate scans of the same URL during repeated tab updates
  const cached = tabScanResults.get(tabId);
  if (!force && cached && cached.url === cleanUrl && !cached.error) {
    updateBadge(tabId, cached.category || cached.safety_status, cached.risk_score);
    return cached;
  }

  // 2. Check if a scan is already actively in-flight for this tab and URL
  if (inFlightScans.has(tabId)) {
    const active = inFlightScans.get(tabId);
    if (!force && active.url === cleanUrl) {
      return active.promise;
    }
  }

  // 3. Indicate scan in progress with badge loading indicator
  updateBadge(tabId, "scanning");

  // Create scan execution promise
  const scanPromise = (async () => {
    const scanPayload = { url: cleanUrl };

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 9000);

      const response = await fetch(SCAN_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(scanPayload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorDetail = `Backend HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson && errJson.error) {
            errorDetail = errJson.error;
          }
        } catch (_) {}

        // Never mark website as safe when scanning fails
        const errResult = {
          error: true,
          errorMessage: errorDetail,
          url: cleanUrl,
          category: "Error",
          safety_status: "Error",
          risk_score: null,
          detection_reason: errorDetail,
          recommendation: "Unable to verify safety status. Backend reported an error.",
          timestamp: Date.now()
        };

        tabScanResults.set(tabId, errResult);
        updateBadge(tabId, "error");
        return errResult;
      }

      const data = await response.json();

      const result = {
        ...data,
        error: false,
        isInternal: false,
        timestamp: Date.now()
      };

      // Store in memory and local storage
      tabScanResults.set(tabId, result);
      chrome.storage.local.set({ [`scan_${tabId}`]: result });

      // Update badge
      updateBadge(tabId, result.category || result.safety_status, result.risk_score);

      // Automated On-Page Threat Warning Dispatching
      const isHighRisk = result.category === "High Risk" || result.safety_status === "Malicious" || (result.risk_score !== null && result.risk_score >= 61);
      const isMediumRisk = result.category === "Medium Risk" || (result.risk_score !== null && result.risk_score >= 31 && result.risk_score <= 60);

      if (isHighRisk) {
        // High Risk: Prominent Warning Notification Banner
        chrome.tabs.sendMessage(tabId, {
          action: "DISPLAY_MALICIOUS_WARNING",
          data: result
        }).catch(() => {
          // Content script may not be ready yet if tab is still initializing
        });

        notifyThreat(
          `AI Sentinel Alert: High Risk Site (${result.risk_score}/100)`,
          `Potential phishing hazard detected on: ${cleanUrl}`
        );
      } else if (isMediumRisk) {
        // Medium Risk: Subtle Caution Notification
        chrome.tabs.sendMessage(tabId, {
          action: "DISPLAY_CAUTION_WARNING",
          data: result
        }).catch(() => {});
      }

      return result;
    } catch (err) {
      // Connection failure / offline handling - NEVER display as safe
      const isOffline = err.name === "AbortError" || err.message?.includes("fetch");
      const errMsg = isOffline
        ? "Backend connection failed. Ensure Flask server is running at http://127.0.0.1:5000."
        : `Scan error: ${err.message}`;

      const errorResult = {
        error: true,
        isOffline: true,
        errorMessage: errMsg,
        url: cleanUrl,
        category: "Error",
        safety_status: "Error",
        risk_score: null,
        detection_reason: "Failed to connect to AI Sentinel detection server.",
        recommendation: "Backend connection error. Verify that 'python backend/app.py' is running on port 5000.",
        timestamp: Date.now()
      };

      tabScanResults.set(tabId, errorResult);
      updateBadge(tabId, "error");
      return errorResult;
    } finally {
      inFlightScans.delete(tabId);
    }
  })();

  // Track in-flight scan
  inFlightScans.set(tabId, { url: cleanUrl, promise: scanPromise });
  return scanPromise;
}

// -----------------------------------------------------------------------------
// Real-Time Event Listeners (Manifest V3)
// -----------------------------------------------------------------------------

// 1. Monitor tab navigation: detect completed website navigations
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Trigger scan when navigation completes or when URL changes
  if (changeInfo.status === "complete" && tab.url) {
    scanUrl(tab.url, tabId);
  }
});

// 2. Active Tab Switch: update badge or trigger scan
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (!tab || !tab.url) return;

    if (tabScanResults.has(activeInfo.tabId)) {
      const cached = tabScanResults.get(activeInfo.tabId);
      if (cached.error) {
        updateBadge(activeInfo.tabId, "error");
      } else if (cached.isInternal) {
        updateBadge(activeInfo.tabId, "internal");
      } else {
        updateBadge(activeInfo.tabId, cached.category || cached.safety_status, cached.risk_score);
      }
    } else {
      scanUrl(tab.url, activeInfo.tabId);
    }
  } catch (e) {
    // Tab might have closed
  }
});

// 3. Tab Closed: clean up in-memory state and storage
chrome.tabs.onRemoved.addListener((tabId) => {
  tabScanResults.delete(tabId);
  inFlightScans.delete(tabId);
  chrome.storage.local.remove([`scan_${tabId}`]);
});

// 4. Runtime message communication for Popup and Content Script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_TAB_SCAN") {
    const tabId = message.tabId;
    const url = message.url;

    if (inFlightScans.has(tabId)) {
      // If a scan is currently in progress, wait for it
      inFlightScans.get(tabId).promise.then((res) => sendResponse(res));
      return true;
    } else if (tabScanResults.has(tabId)) {
      sendResponse(tabScanResults.get(tabId));
    } else if (url) {
      scanUrl(url, tabId).then((res) => sendResponse(res));
      return true; // Keep channel open for async response
    } else {
      sendResponse(null);
    }
  } else if (message.action === "RESCAN_TAB") {
    const tabId = message.tabId;
    const url = message.url;
    scanUrl(url, tabId, true).then((res) => sendResponse(res));
    return true; // Async response
  } else if (message.action === "CHECK_BACKEND_HEALTH") {
    fetch(HEALTH_ENDPOINT)
      .then((res) => res.json())
      .then((data) => sendResponse({ online: true, data }))
      .catch((err) => sendResponse({ online: false, error: err.message }));
    return true;
  }
});
