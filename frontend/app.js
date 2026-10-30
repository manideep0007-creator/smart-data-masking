document.addEventListener('DOMContentLoaded', () => {
  const apiUrlInput = document.getElementById('apiUrlInput');
  const reconnectBtn = document.getElementById('reconnectBtn');
  const statusBadge = document.getElementById('statusBadge');
  const statusText = document.getElementById('statusText');

  const scanBtn = document.getElementById('scanBtn');
  const scanStatus = document.getElementById('scanStatus');
  const schemaBadgesList = document.getElementById('schemaBadgesList');

  const sqlInput = document.getElementById('sqlInput');
  const runBtn = document.getElementById('runBtn');
  const queryMeta = document.getElementById('queryMeta');
  const errorAlert = document.getElementById('errorAlert');

  const resultsCount = document.getElementById('resultsCount');
  const resultsTable = document.getElementById('resultsTable');
  const resultsThead = document.getElementById('resultsThead');
  const resultsTbody = document.getElementById('resultsTbody');
  const emptyPlaceholder = document.getElementById('emptyPlaceholder');

  // Quick Template Chips
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const templateSql = chip.getAttribute('data-sql');
      if (templateSql) {
        sqlInput.value = templateSql;
        sqlInput.focus();
      }
    });
  });

  function getApiBaseUrl() {
    let url = apiUrlInput.value.trim();
    if (!url) url = 'http://127.0.0.1:8000';
    return url.replace(/\/+$/, '');
  }

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

  // --- PII Schema Scan ---
  async function scanSchema() {
    const baseUrl = getApiBaseUrl();
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    scanStatus.textContent = 'Contacting gateway for table schema inspection...';

    try {
      const response = await fetch(`${baseUrl}/scan?table=customers`, { method: 'GET' });
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
          <div class="schema-col-name" title="${col.heuristic || ''}">
            ${col.name}
          </div>
          <span class="schema-tag ${tagClass}" title="Sensitivity: ${col.sensitivity} | Confidence: ${col.confidence}">
            ${col.tag}
          </span>
        `;
        schemaBadgesList.appendChild(item);
      });
    } catch (err) {
      scanStatus.innerHTML = `❌ <strong>Scan Error</strong>: ${err.message}`;
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = 'Scan Schema';
    }
  }

  scanBtn.addEventListener('click', scanSchema);

  // --- Run Query ---
  async function runQuery() {
    const baseUrl = getApiBaseUrl();
    const sql = sqlInput.value.trim();
    const selectedRoleEl = document.querySelector('input[name="userRole"]:checked');
    const role = selectedRoleEl ? selectedRoleEl.value : 'Support';

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
      const response = await fetch(`${baseUrl}/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: role, sql: sql })
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

      queryMeta.textContent = `Executed in ${elapsed}ms · Role: ${role} · Returned ${rows.length} row(s)`;
      renderResults(columns, rows, role);
    } catch (err) {
      showError(err.message);
      queryMeta.textContent = `Query failed · Status 400/500`;
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = '<span class="btn-icon">▶</span> Run Query via Gateway';
    }
  }

  runBtn.addEventListener('click', runQuery);

  // Allow Ctrl+Enter or Cmd+Enter to execute query
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
        // Highlight masked or redacted values
        if (strVal === '[REDACTED]') {
          return `<td><span class="cell-redacted">[REDACTED]</span></td>`;
        } else if (strVal.includes('XXXX') || strVal.includes('***') || strVal === '[CONFIDENTIAL]' || strVal === '[PARTIALLY MASKED]') {
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

  // Initial load actions
  checkHealth();
  scanSchema(); // Automatically discover schema on load
});

