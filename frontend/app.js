document.addEventListener('DOMContentLoaded', () => {
  const apiUrlInput = document.getElementById('apiUrlInput');
  const reconnectBtn = document.getElementById('reconnectBtn');
  const statusBadge = document.getElementById('statusBadge');
  const statusText = document.getElementById('statusText');
  const dbEngineBadge = document.getElementById('dbEngineBadge');

  // JWT Auth Elements
  const authPills = document.querySelectorAll('.auth-pill-btn[data-user]');
  const demoModeBtn = document.getElementById('demoModeBtn');
  const authStatusChip = document.getElementById('authStatusChip');
  const authStatusLabel = document.getElementById('authStatusLabel');

  // Schema Scanning Elements
  const scanBtn = document.getElementById('scanBtn');
  const bgScanBtn = document.getElementById('bgScanBtn');
  const bgScanBar = document.getElementById('bgScanBar');
  const bgScanProgress = document.getElementById('bgScanProgress');
  const bgScanPct = document.getElementById('bgScanPct');
  const bgScanLabel = document.getElementById('bgScanLabel');
  const scanStatus = document.getElementById('scanStatus');
  const schemaBadgesList = document.getElementById('schemaBadgesList');

  // Query Operations Elements
  const sqlInput = document.getElementById('sqlInput');
  const runBtn = document.getElementById('runBtn');
  const queryMeta = document.getElementById('queryMeta');
  const errorAlert = document.getElementById('errorAlert');
  const maskStrategySelect = document.getElementById('maskStrategySelect');

  // Results Table Elements
  const resultsCount = document.getElementById('resultsCount');
  const resultsTable = document.getElementById('resultsTable');
  const resultsThead = document.getElementById('resultsThead');
  const resultsTbody = document.getElementById('resultsTbody');
  const emptyPlaceholder = document.getElementById('emptyPlaceholder');

  // Session State
  let currentAuthToken = null;
  let currentUser = null;
  let bgScanInterval = null;

  function getApiBaseUrl() {
    let url = apiUrlInput.value.trim();
    if (!url) url = 'http://127.0.0.1:8000';
    return url.replace(/\/+$/, '');
  }

  // --- Authentication System ---
  async function authenticateAs(username, password, role) {
    const baseUrl = getApiBaseUrl();
    try {
      const response = await fetch(`${baseUrl}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        throw new Error('Authentication failed');
      }

      const data = await response.json();
      currentAuthToken = data.access_token;
      currentUser = data.user;

      // Update Auth UI
      authStatusChip.className = 'auth-status-chip';
      authStatusLabel.textContent = `JWT: ${currentUser.username} (${currentUser.role.toUpperCase()})`;

      // Sync active persona pill
      authPills.forEach(btn => {
        if (btn.getAttribute('data-user') === username) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });
      demoModeBtn.classList.remove('active');

      // Sync radio button to match authenticated role
      const radio = document.querySelector(`input[name="userRole"][value="${currentUser.role}"]`);
      if (radio) radio.checked = true;

    } catch (err) {
      console.warn('Auto-login fallback:', err);
      // Fallback to demo mode
      currentAuthToken = null;
      authStatusChip.className = 'auth-status-chip unauth';
      authStatusLabel.textContent = `Demo Mode (${role})`;
    }
  }

  // Persona Pill Click Listeners
  authPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const username = pill.getAttribute('data-user');
      const password = pill.getAttribute('data-pass');
      const role = pill.getAttribute('data-role');
      authenticateAs(username, password, role);
    });
  });

  // Demo Mode (Unauthenticated) Listener
  demoModeBtn.addEventListener('click', () => {
    currentAuthToken = null;
    currentUser = null;
    authPills.forEach(p => p.classList.remove('active'));
    demoModeBtn.classList.add('active');
    authStatusChip.className = 'auth-status-chip unauth';
    const selectedRoleEl = document.querySelector('input[name="userRole"]:checked');
    const role = selectedRoleEl ? selectedRoleEl.value : 'Support';
    authStatusLabel.textContent = `Anonymous Demo (${role})`;
  });

  // Sync radio change with demo mode label if unauthenticated
  document.querySelectorAll('input[name="userRole"]').forEach(radio => {
    radio.addEventListener('change', () => {
      if (!currentAuthToken) {
        authStatusLabel.textContent = `Anonymous Demo (${radio.value})`;
      }
    });
  });

  // --- Health Check ---
  async function checkHealth() {
    const baseUrl = getApiBaseUrl();
    statusBadge.className = 'status-badge connecting';
    statusText.textContent = 'Connecting...';

    try {
      const response = await fetch(`${baseUrl}/health`, { method: 'GET' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      if (data.status === 'ok') {
        statusBadge.className = 'status-badge online';
        statusText.textContent = `Online · ${data.database || 'ready'}`;
        if (dbEngineBadge) {
          const engineName = data.engine ? data.engine.toUpperCase() : 'SQLITE';
          dbEngineBadge.textContent = `${engineName} Read-Only`;
        }
      } else {
        statusBadge.className = 'status-badge connecting';
        statusText.textContent = `Degraded · ${data.status}`;
      }
    } catch (err) {
      statusBadge.className = 'status-badge offline';
      statusText.textContent = 'Gateway Offline';
    }
  }

  reconnectBtn.addEventListener('click', checkHealth);

  // --- Quick Template Chips ---
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const templateSql = chip.getAttribute('data-sql');
      if (templateSql) {
        sqlInput.value = templateSql;
        sqlInput.focus();
      }
    });
  });

  // --- PII Schema Scan (Synchronous) ---
  async function scanSchema() {
    const baseUrl = getApiBaseUrl();
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    scanStatus.textContent = 'Contacting gateway for table schema inspection...';

    try {
      const headers = {};
      if (currentAuthToken) headers['Authorization'] = `Bearer ${currentAuthToken}`;

      const response = await fetch(`${baseUrl}/scan?table=customers`, {
        method: 'GET',
        headers,
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.detail || `Scan failed (HTTP ${response.status})`);
      }

      const data = await response.json();
      const columns = data.columns || [];
      const totalCols = data.total_columns || columns.length;

      scanStatus.innerHTML = `✅ Successfully inspected table <strong>${data.table || 'customers'}</strong> (${totalCols} columns classified)`;

      schemaBadgesList.innerHTML = '';
      columns.forEach(col => {
        const item = document.createElement('div');
        item.className = 'schema-item';

        let tagClass = 'tag-public';
        if (col.tag === 'FINANCIAL_CONFIDENTIAL') tagClass = 'tag-financial';
        else if (col.tag === 'PII_HIGH') tagClass = 'tag-pii-high';
        else if (col.tag === 'PII_MEDIUM') tagClass = 'tag-pii-med';
        else if (col.tag === 'PII_LOW') tagClass = 'tag-pii-low';

        item.innerHTML = `
          <div class="schema-col-name" title="${escapeHtml(col.heuristic || '')}">
            ${escapeHtml(col.name)}
          </div>
          <span class="schema-tag ${tagClass}" title="Sensitivity: ${col.sensitivity} | Confidence: ${col.confidence} | Heuristic: ${escapeHtml(col.heuristic || '')}">
            ${escapeHtml(col.tag)}
          </span>
        `;
        schemaBadgesList.appendChild(item);
      });
    } catch (err) {
      scanStatus.innerHTML = `❌ <strong>Scan Error</strong>: ${escapeHtml(err.message)}`;
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = 'Scan Schema';
    }
  }

  scanBtn.addEventListener('click', scanSchema);

  // --- Background PII Scanner ---
  async function triggerBackgroundScan() {
    const baseUrl = getApiBaseUrl();
    bgScanBtn.disabled = true;
    bgScanBar.classList.remove('hidden');
    bgScanLabel.textContent = 'Triggering background worker...';
    bgScanProgress.style.width = '10%';
    bgScanPct.textContent = '10%';

    try {
      const headers = {};
      if (currentAuthToken) headers['Authorization'] = `Bearer ${currentAuthToken}`;

      const response = await fetch(`${baseUrl}/scan/start`, {
        method: 'POST',
        headers,
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.detail || 'Failed to start background scan.');
      }

      // Poll status until completion
      if (bgScanInterval) clearInterval(bgScanInterval);
      bgScanInterval = setInterval(pollScanStatus, 400);

    } catch (err) {
      bgScanLabel.textContent = `Scan trigger error: ${err.message}`;
      bgScanBtn.disabled = false;
      setTimeout(() => bgScanBar.classList.add('hidden'), 3500);
    }
  }

  async function pollScanStatus() {
    const baseUrl = getApiBaseUrl();
    try {
      const response = await fetch(`${baseUrl}/scan/status`);
      if (!response.ok) return;
      const statusData = await response.json();

      const pct = statusData.progress_pct || 0;
      bgScanProgress.style.width = `${pct}%`;
      bgScanPct.textContent = `${pct}%`;

      if (statusData.status === 'completed') {
        clearInterval(bgScanInterval);
        bgScanLabel.textContent = `Completed: ${statusData.tables_scanned || 1} table(s), ${statusData.columns_classified || 8} columns classified`;
        bgScanBtn.disabled = false;
        // Refresh visible schema radar
        scanSchema();
        setTimeout(() => bgScanBar.classList.add('hidden'), 4000);
      } else if (statusData.status === 'failed') {
        clearInterval(bgScanInterval);
        bgScanLabel.textContent = `Scan failed: ${statusData.error || 'Unknown error'}`;
        bgScanBtn.disabled = false;
      } else {
        bgScanLabel.textContent = `Scanning schemas... (${pct}%)`;
      }
    } catch (e) {
      clearInterval(bgScanInterval);
      bgScanBtn.disabled = false;
    }
  }

  bgScanBtn.addEventListener('click', triggerBackgroundScan);

  // --- Run Query Operations ---
  async function runQuery() {
    const baseUrl = getApiBaseUrl();
    const sql = sqlInput.value.trim();
    const selectedRoleEl = document.querySelector('input[name="userRole"]:checked');
    const role = selectedRoleEl ? selectedRoleEl.value : 'Support';
    const maskStrategy = maskStrategySelect ? maskStrategySelect.value : 'redact';

    if (!sql) {
      showError('Please enter a SQL query statement.');
      return;
    }

    hideError();
    runBtn.disabled = true;
    runBtn.innerHTML = '<span class="btn-icon">⏳</span> Executing...';
    queryMeta.textContent = `Routing query via gateway as ${role}...`;

    const startTime = performance.now();

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (currentAuthToken) {
        headers['Authorization'] = `Bearer ${currentAuthToken}`;
      }

      const payload = {
        role: role,
        sql: sql,
        mask_strategy: maskStrategy,
        max_rows: 1000,
      };

      const response = await fetch(`${baseUrl}/query`, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(payload),
      });

      const elapsed = Math.round(performance.now() - startTime);

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        const detailMsg = errJson.detail || `Query execution error (HTTP ${response.status})`;
        throw new Error(detailMsg);
      }

      const data = await response.json();
      const columns = data.columns || [];
      const rows = data.rows || [];
      const meta = data.meta || {};

      const effectiveRole = meta.role_applied || role;
      const authNotice = meta.auth_source === 'jwt_verified' ? ' [JWT Verified]' : ' [Demo Mode]';
      const stratNotice = effectiveRole === 'Analyst' ? ` · Strategy: ${meta.mask_strategy || maskStrategy}` : '';

      queryMeta.textContent = `Executed in ${elapsed}ms · Role: ${effectiveRole}${authNotice}${stratNotice} · Returned ${rows.length} row(s)`;
      renderResults(columns, rows, effectiveRole);
    } catch (err) {
      showError(err.message);
      queryMeta.textContent = `Query rejected or failed`;
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = '<span class="btn-icon">▶</span> Run Query via Gateway';
    }
  }

  runBtn.addEventListener('click', runQuery);

  // Keyboard shortcut Ctrl+Enter or Cmd+Enter
  sqlInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runQuery();
    }
  });

  // --- Render Table Results ---
  function renderResults(columns, rows, role) {
    if (!columns || columns.length === 0) {
      resultsThead.innerHTML = '';
      resultsTbody.innerHTML = '';
      resultsTable.classList.add('hidden');
      emptyPlaceholder.classList.remove('hidden');
      emptyPlaceholder.innerHTML = '<div class="empty-icon">ℹ️</div><p>Query executed successfully but returned 0 columns.</p>';
      resultsCount.textContent = '0 rows';
      return;
    }

    emptyPlaceholder.classList.add('hidden');
    resultsTable.classList.remove('hidden');
    resultsCount.textContent = `${rows.length} row(s)`;

    // Header
    resultsThead.innerHTML = `<tr>${columns.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr>`;

    // Body
    resultsTbody.innerHTML = rows.map(row => {
      const cells = row.map(val => {
        if (val === null || val === undefined) {
          return '<td style="color: var(--text-muted)">NULL</td>';
        }
        const strVal = String(val);
        // Highlight masked, redacted, or hashed values
        if (strVal === '[REDACTED]') {
          return `<td><span class="cell-redacted">[REDACTED]</span></td>`;
        } else if (strVal.startsWith('sha256:')) {
          return `<td><span class="cell-hash">${escapeHtml(strVal)}</span></td>`;
        } else if (
          strVal.includes('XXXX') ||
          strVal.includes('***') ||
          strVal === '[CONFIDENTIAL]' ||
          strVal === '[PARTIALLY MASKED]' ||
          strVal === '[PROTECTED]'
        ) {
          return `<td><span class="cell-masked">${escapeHtml(strVal)}</span></td>`;
        } else {
          return `<td>${escapeHtml(strVal)}</td>`;
        }
      }).join('');
      return `<tr>${cells}</tr>`;
    }).join('');
  }

  function showError(msg) {
    errorAlert.textContent = `❌ ${msg}`;
    errorAlert.classList.remove('hidden');
  }

  function hideError() {
    errorAlert.textContent = '';
    errorAlert.classList.add('hidden');
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // --- Initial Startup ---
  checkHealth();
  // Auto authenticate as Support (Ravi) by default for realistic demo
  authenticateAs('support_ravi', 'password123', 'Support').then(() => {
    scanSchema();
  });
});
