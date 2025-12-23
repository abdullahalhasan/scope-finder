(() => {
  "use strict";

  // -----------------------------
  // DOM helpers
  // -----------------------------
  const $ = (id) => document.getElementById(id);

  const scanForm = $("scanForm");
  const targetEl = $("target");
  const excludeEl = $("exclude_ips");
  const minPortEl = $("min_port");
  const maxPortEl = $("max_port");

  const scanBtn = $("scanBtn");
  const stopBtn = $("stopBtn");

  const loadingSpinner = $("loadingSpinner");
  const errorAlert = $("errorAlert");

  const resultsContainer = $("resultsContainer");
  const noResultsText = $("noResultsText");
  const scanTargetLabel = $("scanTargetLabel");

  // NEW: Saved IP lists UI (optional elements; will no-op if missing)
  const savedTargetListEl = $("saved_target_list");
  const savedExcludeListEl = $("saved_exclude_list");
  const savedTargetPreviewEl = $("saved_target_preview");
  const savedExcludePreviewEl = $("saved_exclude_preview");

  // NEW: data injected by index.html (window.PROHORI_IP_LISTS = [...])
  const IP_LISTS = Array.isArray(window.PROHORI_IP_LISTS) ? window.PROHORI_IP_LISTS : [];

  // We'll reuse the existing spinner text line as the status line (no HTML changes needed)
  let scanStatusTextEl = null;

  // Scan state
  let isScanning = false;
  let scanFetchAbort = null;

  // Progress polling state
  let progressPollTimer = null;

  // Elapsed time
  let scanStartTs = null;
  let lastElapsedMs = null;

  // -----------------------------
  // Formatting helpers
  // -----------------------------
  function formatElapsed(ms) {
    if (typeof ms !== "number" || ms < 0) return "—";
    const totalSec = Math.floor(ms / 1000);
    const hh = Math.floor(totalSec / 3600);
    const mm = Math.floor((totalSec % 3600) / 60);
    const ss = totalSec % 60;

    if (hh > 0) {
      return `${String(hh).padStart(2, "0")}:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
    }
    return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // -----------------------------
  // Saved IP lists (Admin-managed)
  // -----------------------------
  function _norm(s) {
    return String(s || "").trim().toLowerCase();
  }

  function findListByName(name, listType) {
    const n = _norm(name);
    const t = _norm(listType);
    if (!n || !t) return null;

    // exact match on name
    return IP_LISTS.find((x) => _norm(x?.name) === n && _norm(x?.list_type) === t) || null;
  }

  function setPreview(el, text) {
    if (!el) return;
    const v = String(text || "").trim();
    if (v) {
      el.textContent = v;
      el.classList.remove("text-muted");
    } else {
      el.textContent = "—";
      el.classList.add("text-muted");
    }
  }

  function applySavedTargetByName(name) {
    const match = findListByName(name, "target");
    if (match && targetEl) {
      targetEl.value = match.value_text || "";
      setPreview(savedTargetPreviewEl, match.value_text || "");
    } else {
      setPreview(savedTargetPreviewEl, "");
    }
  }

  function applySavedExcludeByName(name) {
    const match = findListByName(name, "exclude");
    if (match && excludeEl) {
      excludeEl.value = match.value_text || "";
      setPreview(savedExcludePreviewEl, match.value_text || "");
    } else {
      setPreview(savedExcludePreviewEl, "");
    }
  }

  // -----------------------------
  // UI utilities
  // -----------------------------
  function ensureStatusLine() {
    if (!loadingSpinner) return null;

    // Find the spinner text line: <div class="mt-2 small text-muted">Scanning…</div>
    const candidates = loadingSpinner.querySelectorAll("div");
    for (const div of candidates) {
      if (div.classList.contains("mt-2") && div.classList.contains("text-muted")) {
        scanStatusTextEl = div;
        scanStatusTextEl.id = "scanStatusText";
        scanStatusTextEl.style.whiteSpace = "pre-line"; // allow multi-line updates
        return scanStatusTextEl;
      }
    }

    // If not found, create one
    scanStatusTextEl = document.createElement("div");
    scanStatusTextEl.className = "mt-2 small text-muted";
    scanStatusTextEl.id = "scanStatusText";
    scanStatusTextEl.style.whiteSpace = "pre-line"; // allow multi-line updates
    loadingSpinner.appendChild(scanStatusTextEl);
    return scanStatusTextEl;
  }

  function setStatus(text) {
    ensureStatusLine();
    if (!scanStatusTextEl) return;
    scanStatusTextEl.textContent = text || "";
  }

  function showError(msg) {
    if (!errorAlert) return;
    errorAlert.textContent = msg || "Something went wrong.";
    errorAlert.classList.remove("d-none");
  }

  function clearError() {
    if (!errorAlert) return;
    errorAlert.textContent = "";
    errorAlert.classList.add("d-none");
  }

  function setLoading(loading) {
    isScanning = !!loading;

    if (loadingSpinner) {
      loadingSpinner.classList.toggle("d-none", !loading);
    }

    if (scanBtn) scanBtn.disabled = loading;
    if (stopBtn) stopBtn.disabled = !loading;
  }

  function setTargetLabel({ target, excludeIps, minPort, maxPort }) {
    if (!scanTargetLabel) return;
    const ex = (excludeIps || "").trim();
    scanTargetLabel.textContent = `Target: ${target} | Exclude: ${ex ? ex : "none"} | Ports: ${minPort}-${maxPort}`;
  }

  // -----------------------------
  // Progress polling (GET /api/progress)
  // -----------------------------
  function startProgressPolling() {
    stopProgressPolling();
    progressPollTimer = setInterval(fetchProgressOnce, 500);
  }

  function stopProgressPolling() {
    if (progressPollTimer) {
      clearInterval(progressPollTimer);
      progressPollTimer = null;
    }
  }

  async function fetchProgressOnce() {
    if (!isScanning) return;

    try {
      const r = await fetch("/api/progress", { method: "GET", cache: "no-store" });
      if (!r.ok) return;

      const p = await r.json();
      if (!p || !p.active) return;

      // Prefer backend elapsed_sec if provided, otherwise UI timer
      const elapsedMs =
        typeof p.elapsed_sec === "number"
          ? Math.max(0, Math.floor(p.elapsed_sec * 1000))
          : (scanStartTs ? (Date.now() - scanStartTs) : 0);

      const timeLine = `Time: ${formatElapsed(elapsedMs)}`;

      const statusLine = `Status: ${p.phase || "-"}${p.current_ip ? ` | IP: ${p.current_ip}` : ""}`;

      const portsTestedLine =
        (p.ports_done != null && p.port_total && p.current_ip)
          ? `Ports Tested ${p.ports_done}/${p.port_total} of IP ${p.current_ip} (${p.host_index || 0}/${p.host_total || 0})`
          : "";

      const summaryLine = [
        (p.excluded_count != null) ? `Excluded IP: ${p.excluded_count}` : "",
        (p.open_found != null) ? `Open Port: ${p.open_found}` : "",
      ].filter(Boolean).join(" | ");

      const completedLine =
        (p.percent != null) ? `Completed: ${p.percent}%` : "";

      // Keep your exact “stable” lines layout
      const lines = [timeLine, statusLine, portsTestedLine, summaryLine, completedLine]
        .filter((x) => x && x.trim().length > 0);

      setStatus(lines.join("\n"));
    } catch {
      // ignore polling errors
    }
  }

  // -----------------------------
  // Render results
  // -----------------------------
  function renderResults(payload) {
    if (!resultsContainer) return;

    const scanId = payload.scan_id;
    const target = payload.target;
    const excludeIps = payload.exclude_ips || "";
    const excludedCount = payload.excluded_count ?? 0;
    const cancelled = !!payload.cancelled;

    const hosts = payload.results || {};
    const hostIps = Object.keys(hosts);

    const durationText = lastElapsedMs != null ? formatElapsed(lastElapsedMs) : "—";

    let html = "";

    html += `
      <div class="mb-3">
        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2">
          <div>
            <div class="fw-semibold">Scan Complete</div>
            <div class="text-muted small">
              Scan ID: ${escapeHtml(scanId)} |
              Target: ${escapeHtml(target)} |
              Exclude IPs: ${escapeHtml(excludeIps || "none")} |
              Excluded Count: ${escapeHtml(excludedCount)} |
              Duration: ${escapeHtml(durationText)}
            </div>
          </div>
          <div>
            ${cancelled ? `<span class="badge text-bg-warning">Cancelled</span>` : `<span class="badge text-bg-success">Finished</span>`}
          </div>
        </div>
      </div>
    `;

    if (cancelled) {
      html += `
        <div class="alert alert-warning">
          Scan was cancelled. Results may be partial.
        </div>
      `;
    }

    if (hostIps.length === 0) {
      html += `<p class="text-muted mb-0">No live hosts detected (or no results returned).</p>`;
      resultsContainer.innerHTML = html;
      if (noResultsText) noResultsText.classList.add("d-none");
      return;
    }

    html += `<div class="accordion" id="resultsAccordion">`;

    hostIps.sort().forEach((ip, idx) => {
      const host = hosts[ip] || {};
      const hostname = host.hostname || "N/A";
      const ports = Array.isArray(host.ports) ? host.ports : [];
      const openCount = ports.length;

      const headingId = `heading${idx}`;
      const collapseId = `collapse${idx}`;

      html += `
        <div class="accordion-item">
          <h2 class="accordion-header" id="${headingId}">
            <button class="accordion-button ${idx === 0 ? "" : "collapsed"}" type="button"
              data-bs-toggle="collapse" data-bs-target="#${collapseId}"
              aria-expanded="${idx === 0 ? "true" : "false"}" aria-controls="${collapseId}">
              <div class="d-flex flex-column flex-md-row w-100 justify-content-between gap-2">
                <div>
                  <span class="fw-semibold">${escapeHtml(ip)}</span>
                  <span class="text-muted small ms-2">(${escapeHtml(hostname)})</span>
                </div>
                <div class="small">
                  <span class="badge text-bg-secondary">Open ports: ${openCount}</span>
                </div>
              </div>
            </button>
          </h2>
          <div id="${collapseId}" class="accordion-collapse collapse ${idx === 0 ? "show" : ""}"
            aria-labelledby="${headingId}" data-bs-parent="#resultsAccordion">
            <div class="accordion-body">
      `;

      if (openCount === 0) {
        html += `<p class="text-muted mb-0">No open ports detected.</p>`;
      } else {
        html += `
          <div class="table-responsive">
            <table class="table table-sm align-middle mb-0">
              <thead class="table-light">
                <tr>
                  <th style="width: 90px;">Port</th>
                  <th style="width: 80px;">Proto</th>
                  <th style="width: 160px;">Service</th>
                  <th style="width: 100px;">State</th>
                  <th>Banner</th>
                </tr>
              </thead>
              <tbody>
        `;

        ports.forEach((p) => {
          html += `
            <tr>
              <td>${escapeHtml(p.port)}</td>
              <td>${escapeHtml(p.protocol || "tcp")}</td>
              <td>${escapeHtml(p.service || "unknown")}</td>
              <td>${escapeHtml(p.state || "open")}</td>
              <td class="text-wrap" style="max-width: 520px;">
                ${p.banner ? `<code>${escapeHtml(p.banner)}</code>` : `<span class="text-muted">—</span>`}
              </td>
            </tr>
          `;
        });

        html += `
              </tbody>
            </table>
          </div>
        `;
      }

      const findings = host.findings || {};
      if (findings && Object.keys(findings).length > 0) {
        html += `
          <hr class="my-3" />
          <div>
            <div class="fw-semibold mb-2">Findings</div>
            <pre class="small bg-light p-2 rounded border mb-0" style="white-space: pre-wrap;">${escapeHtml(JSON.stringify(findings, null, 2))}</pre>
          </div>
        `;
      }

      html += `
            </div>
          </div>
        </div>
      `;
    });

    html += `</div>`;
    resultsContainer.innerHTML = html;
    if (noResultsText) noResultsText.classList.add("d-none");
  }

  // -----------------------------
  // Scan / Stop actions
  // -----------------------------
  async function startScan() {
    clearError();

    const target = (targetEl?.value || "").trim();
    const excludeIps = (excludeEl?.value || "").trim();
    const minPort = parseInt(minPortEl?.value || "1", 10);
    const maxPort = parseInt(maxPortEl?.value || "1024", 10);

    if (!target) {
      showError("Target is required.");
      return;
    }
    if (Number.isNaN(minPort) || Number.isNaN(maxPort) || minPort < 1 || maxPort > 65535 || minPort > maxPort) {
      showError("Invalid port range. Please check Min Port / Max Port.");
      return;
    }

    scanStartTs = Date.now();
    lastElapsedMs = null;

    setTargetLabel({ target, excludeIps, minPort, maxPort });
    setLoading(true);
    setStatus("Time: 00:00\nStatus: starting\nMessage: Starting scan…");

    // Start real-time progress polling
    startProgressPolling();

    // Allow user to abort the fetch (UI only). Server-side stop is /api/stop.
    scanFetchAbort = new AbortController();

    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: scanFetchAbort.signal,
        body: JSON.stringify({
          target: target,
          exclude_ips: excludeIps, // IMPORTANT: keeps exclude working
          min_port: minPort,
          max_port: maxPort,
        }),
      });

      let data = null;
      try {
        data = await resp.json();
      } catch {
        data = null;
      }

      if (!resp.ok || !data || data.success === false) {
        const msg = (data && data.error) ? data.error : `Scan failed (HTTP ${resp.status}).`;
        showError(msg);
        return;
      }

      lastElapsedMs = Date.now() - scanStartTs;
      setStatus(`Time: ${formatElapsed(lastElapsedMs)}\nStatus: done\nMessage: Scan finished. Rendering results…`);

      renderResults(data);
    } catch (err) {
      if (err && err.name === "AbortError") {
        const elapsed = scanStartTs ? Date.now() - scanStartTs : null;
        setStatus(`Time: ${elapsed != null ? formatElapsed(elapsed) : "—"}\nStatus: stopping\nMessage: Stop requested (UI aborted request).`);
        showError("Scan request aborted (stop requested). Server may still return partial results.");
      } else {
        setStatus("Time: —\nStatus: error\nMessage: Scan failed.");
        showError(`Scan error: ${err?.message || err}`);
      }
    } finally {
      stopProgressPolling();
      setLoading(false);
      scanFetchAbort = null;

      if (lastElapsedMs == null && scanStartTs) {
        lastElapsedMs = Date.now() - scanStartTs;
      }
    }
  }

  async function stopScan() {
    clearError();

    // If nothing is running, do nothing
    if (!isScanning) return;

    // Disable Stop so user can’t spam it
    if (stopBtn) stopBtn.disabled = true;

    const elapsed = scanStartTs ? Date.now() - scanStartTs : null;
    setStatus(`Time: ${elapsed != null ? formatElapsed(elapsed) : "—"}\nStatus: stopping\nMessage: Stop requested…`);

    // IMPORTANT: do NOT abort /api/scan fetch
    // IMPORTANT: do NOT stop progress polling here
    // IMPORTANT: do NOT setLoading(false) here
    try {
        await fetch("/api/stop", { method: "POST" });
    } catch {
        // ignore
    }
  }


  // -----------------------------
  // Wire up events
  // -----------------------------
  function init() {
    ensureStatusLine();

    // NEW: saved lists events (optional)
    if (savedTargetListEl) {
      savedTargetListEl.addEventListener("input", () => {
        applySavedTargetByName(savedTargetListEl.value);
      });
      // initial preview if prefilled
      if (savedTargetListEl.value) applySavedTargetByName(savedTargetListEl.value);
    }

    if (savedExcludeListEl) {
      savedExcludeListEl.addEventListener("input", () => {
        applySavedExcludeByName(savedExcludeListEl.value);
      });
      // initial preview if prefilled
      if (savedExcludeListEl.value) applySavedExcludeByName(savedExcludeListEl.value);
    }

    if (!scanForm) return;

    scanForm.addEventListener("submit", (e) => {
      e.preventDefault();
      if (isScanning) return;
      startScan();
    });

    if (stopBtn) {
      stopBtn.addEventListener("click", (e) => {
        e.preventDefault();
        stopScan();
      });
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
