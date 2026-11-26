/**
 * AI Sentinel - Security Operations Dashboard Client
 * Fetches real scan telemetry from Flask backend, renders Chart.js visualizations,
 * and manages real-time scan history.
 */

// Detect backend base URL (works both when served from Flask and when opened as local file)
const API_BASE = window.location.origin.includes("127.0.0.1") || window.location.origin.includes("localhost")
  ? window.location.origin
  : "http://127.0.0.1:5000";

let categoryChart = null;
let dailyChart = null;
let riskDistChart = null;

let autoRefreshTimer = null;
let cachedHistory = [];

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();

  // Manual refresh button
  document.getElementById("manual-refresh-btn").addEventListener("click", () => {
    fetchStatistics();
    fetchHistory();
  });

  // Auto-refresh toggle
  const autoToggle = document.getElementById("auto-refresh-toggle");
  autoToggle.addEventListener("change", (e) => {
    if (e.target.checked) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });

  // Quick scan form
  const scanForm = document.getElementById("quick-scan-form");
  scanForm.addEventListener("submit", handleQuickScan);

  // Search & Filter listeners
  document.getElementById("history-search-input").addEventListener("input", filterAndRenderHistory);
  document.getElementById("history-status-filter").addEventListener("change", filterAndRenderHistory);

  startAutoRefresh();
});

function startAutoRefresh() {
  stopAutoRefresh();
  autoRefreshTimer = setInterval(() => {
    fetchStatistics();
    fetchHistory();
  }, 15000);
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

async function initDashboard() {
  await checkBackendStatus();
  await Promise.all([fetchStatistics(), fetchHistory()]);
}

/**
 * Checks backend health connectivity.
 */
async function checkBackendStatus() {
  const pill = document.getElementById("backend-status-pill");
  const text = document.getElementById("backend-status-text");

  try {
    const res = await fetch(`${API_BASE}/health`, { method: "GET" });
    if (res.ok) {
      pill.className = "status-pill status-online";
      text.textContent = "Backend Online (Port 5000)";
    } else {
      pill.className = "status-pill status-offline";
      text.textContent = `Backend HTTP ${res.status}`;
    }
  } catch (err) {
    pill.className = "status-pill status-offline";
    text.textContent = "Backend Offline";
  }
}

/**
 * Fetches aggregate scan telemetry from GET /api/stats.
 */
async function fetchStatistics() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderStatCards(data);
    renderCharts(data);
  } catch (err) {
    console.warn("Failed to fetch dashboard statistics:", err);
  }
}

/**
 * Updates top metrics counters.
 */
function renderStatCards(data) {
  const total = data.total_scans || 0;
  const safe = data.safe_count || 0;
  const suspicious = data.suspicious_count || 0;
  const malicious = data.malicious_count || 0;
  const rate = typeof data.threat_percentage === "number" ? data.threat_percentage : 0;

  document.getElementById("stat-total-scans").textContent = total.toLocaleString();
  document.getElementById("stat-safe-scans").textContent = safe.toLocaleString();
  document.getElementById("stat-suspicious-scans").textContent = suspicious.toLocaleString();
  document.getElementById("stat-malicious-scans").textContent = malicious.toLocaleString();
  document.getElementById("stat-threat-rate").textContent = `${rate}%`;

  const bar = document.getElementById("stat-threat-bar");
  if (bar) {
    bar.style.width = `${Math.min(100, Math.max(0, rate))}%`;
  }
}

/**
 * Renders the 3 Chart.js threat statistics charts.
 */
function renderCharts(data) {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js not loaded");
    return;
  }

  const safe = data.safe_count || 0;
  const suspicious = data.suspicious_count || 0;
  const malicious = data.malicious_count || 0;

  // Chart 1: Safe vs Suspicious vs Malicious (Doughnut)
  const ctxCategory = document.getElementById("categoryDoughnutChart");
  if (ctxCategory) {
    if (categoryChart) categoryChart.destroy();
    categoryChart = new Chart(ctxCategory, {
      type: "doughnut",
      data: {
        labels: ["Safe (Low Risk)", "Suspicious (Medium)", "Malicious (High)"],
        datasets: [{
          data: [safe, suspicious, malicious],
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
          borderColor: "#131d33",
          borderWidth: 2,
          hoverOffset: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#94a3b8", font: { size: 10, weight: 600 }, boxWidth: 12 }
          }
        },
        cutout: "65%"
      }
    });
  }

  // Chart 2: Daily Website Scans (Timeline Bar)
  const ctxDaily = document.getElementById("dailyScansBarChart");
  if (ctxDaily) {
    const dailyData = data.daily_scans || [];
    const labels = dailyData.map(d => d.date);
    const safeSeries = dailyData.map(d => d.safe);
    const suspSeries = dailyData.map(d => d.suspicious);
    const malSeries = dailyData.map(d => d.malicious);

    if (dailyChart) dailyChart.destroy();
    dailyChart = new Chart(ctxDaily, {
      type: "bar",
      data: {
        labels: labels.length > 0 ? labels : ["Today"],
        datasets: [
          {
            label: "Safe",
            data: labels.length > 0 ? safeSeries : [safe],
            backgroundColor: "#10b981",
            borderRadius: 4,
          },
          {
            label: "Suspicious",
            data: labels.length > 0 ? suspSeries : [suspicious],
            backgroundColor: "#f59e0b",
            borderRadius: 4,
          },
          {
            label: "Malicious",
            data: labels.length > 0 ? malSeries : [malicious],
            backgroundColor: "#ef4444",
            borderRadius: 4,
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            stacked: true,
            ticks: { color: "#64748b", font: { size: 10 } },
            grid: { display: false }
          },
          y: {
            stacked: true,
            ticks: { color: "#64748b", font: { size: 10 }, stepSize: 1 },
            grid: { color: "rgba(255, 255, 255, 0.05)" }
          }
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#94a3b8", font: { size: 10, weight: 600 }, boxWidth: 12 }
          }
        }
      }
    });
  }

  // Chart 3: Risk Score Distribution (Histogram Bar)
  const ctxRisk = document.getElementById("riskDistributionChart");
  if (ctxRisk) {
    const dist = data.score_distribution || { "0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0 };
    if (riskDistChart) riskDistChart.destroy();
    riskDistChart = new Chart(ctxRisk, {
      type: "bar",
      data: {
        labels: ["0–20", "21–40", "41–60", "61–80", "81–100"],
        datasets: [{
          label: "Scans",
          data: [dist["0-20"], dist["21-40"], dist["41-60"], dist["61-80"], dist["81-100"]],
          backgroundColor: ["#10b981", "#38bdf8", "#f59e0b", "#f97316", "#ef4444"],
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: "#64748b", font: { size: 10 } },
            grid: { display: false }
          },
          y: {
            ticks: { color: "#64748b", font: { size: 10 }, stepSize: 1 },
            grid: { color: "rgba(255, 255, 255, 0.05)" }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

/**
 * Fetches scan history records from GET /api/history.
 */
async function fetchHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history?limit=100`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    cachedHistory = data.history || [];
    filterAndRenderHistory();
  } catch (err) {
    console.warn("Failed to fetch scan history:", err);
    const tbody = document.getElementById("history-table-body");
    tbody.innerHTML = `<tr><td colspan="5" class="table-loading">Failed to load history from backend. Ensure Flask is running.</td></tr>`;
  }
}

/**
 * Filters cached history by search term and category selector, then updates DOM table.
 */
function filterAndRenderHistory() {
  const searchTerm = (document.getElementById("history-search-input").value || "").toLowerCase().trim();
  const filterCat = document.getElementById("history-status-filter").value;

  const filtered = cachedHistory.filter((item) => {
    // Category match
    if (filterCat !== "ALL") {
      const cat = (item.category || item.safety_status || "").toLowerCase();
      if (!cat.includes(filterCat.toLowerCase())) {
        return false;
      }
    }

    // Search term match
    if (searchTerm) {
      const url = (item.url || "").toLowerCase();
      const expl = (item.explanation || "").toLowerCase();
      const ind = (item.detected_indicators || []).join(" ").toLowerCase();
      if (!url.includes(searchTerm) && !expl.includes(searchTerm) && !ind.includes(searchTerm)) {
        return false;
      }
    }
    return true;
  });

  const tbody = document.getElementById("history-table-body");
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="table-loading">No scan records matching current search criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map((item) => {
    const score = typeof item.risk_score === "number" ? item.risk_score : 0;
    const cat = item.category || (score <= 30 ? "Low Risk" : (score <= 60 ? "Medium Risk" : "High Risk"));

    let badgeClass = "badge-safe";
    let scoreColor = "#10b981";

    if (cat === "High Risk" || item.safety_status === "Malicious" || score >= 61) {
      badgeClass = "badge-malicious";
      scoreColor = "#ef4444";
    } else if (cat === "Medium Risk" || item.safety_status === "Suspicious" || score >= 31) {
      badgeClass = "badge-suspicious";
      scoreColor = "#f59e0b";
    }

    const explanation = item.explanation || "Evaluated by AI Sentinel ML model.";
    const indicators = (item.detected_indicators && item.detected_indicators.length > 0)
      ? `<div style="font-size: 10.5px; color: #94a3b8; margin-top: 4px;">• ${item.detected_indicators.slice(0, 2).map(escapeHtml).join(" • ")}</div>`
      : "";

    return `
      <tr>
        <td><span class="badge-status ${badgeClass}">${escapeHtml(cat)}</span></td>
        <td class="url-cell" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</td>
        <td><span class="score-badge" style="color: ${scoreColor}">${score}/100</span></td>
        <td class="explanation-cell">
          <div>${escapeHtml(explanation)}</div>
          ${indicators}
        </td>
        <td class="timestamp-cell">${escapeHtml(item.timestamp || "")}</td>
      </tr>
    `;
  }).join("");
}

/**
 * Handles instant test scan directly from the dashboard input.
 */
async function handleQuickScan(e) {
  e.preventDefault();
  const input = document.getElementById("quick-scan-input");
  const btn = document.getElementById("quick-scan-btn");
  const feedback = document.getElementById("quick-scan-result");
  const url = input.value.trim();

  if (!url) return;

  btn.disabled = true;
  btn.textContent = "Scanning...";
  feedback.className = "quick-scan-feedback";
  feedback.classList.remove("hidden");
  feedback.innerHTML = `<span>⏳ Dispatching real-time scan to Random Forest ML and RAG engine...</span>`;

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    const data = await res.json();
    if (!res.ok) {
      feedback.innerHTML = `<span style="color: #ef4444;">❌ Scan Error: ${escapeHtml(data.error || "Failed")}</span>`;
    } else {
      const score = data.risk_score;
      const cat = data.category;
      const expl = data.ai_generated_explanation || data.explanation;
      const color = cat === "High Risk" ? "#ef4444" : (cat === "Medium Risk" ? "#f59e0b" : "#10b981");

      feedback.innerHTML = `
        <div>
          <strong style="color: ${color};">${escapeHtml(cat)} (Score: ${score}/100)</strong>
          <span style="color: #cbd5e1; margin-left: 8px;">${escapeHtml(expl)}</span>
        </div>
      `;
      input.value = "";

      // Immediately refresh stats and history
      await fetchStatistics();
      await fetchHistory();
    }
  } catch (err) {
    feedback.innerHTML = `<span style="color: #ef4444;">❌ Network Error: Could not connect to Flask API (${err.message})</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze URL";
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
