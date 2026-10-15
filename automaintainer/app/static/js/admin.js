let selectedSessionId = null;
let activeEventSource = null;
let currentTab = 'active';
let allSessions = [];

function setTab(tab) {
    currentTab = tab;
    ['active', 'review', 'merged', 'blocked'].forEach(t => {
        const el = document.getElementById('tab' + t.charAt(0).toUpperCase() + t.slice(1));
        if (t === tab) {
            el.className = "px-3 py-1 text-xs font-semibold rounded bg-blue-600 text-white";
        } else {
            el.className = "px-3 py-1 text-xs font-semibold rounded bg-gray-700 text-gray-300 hover:bg-gray-600";
        }
    });
    renderSessionsTable();
}

async function loadMetrics() {
    try {
        const res = await fetch("/metrics-summary");
        if (res.ok) {
            const data = await res.json();
            document.getElementById("statCandidates").innerText = data.candidates_scanned.toLocaleString();
            document.getElementById("statOpportunities").innerText = data.opportunities_found;
            document.getElementById("statSessions").innerText = data.active_sessions;
            document.getElementById("statPRsOpened").innerText = data.prs_opened;
            document.getElementById("statPRsMerged").innerText = data.prs_merged;
        }
    } catch (_) {}
}

async function loadSessions() {
    try {
        const res = await fetch("/v1/sessions");
        if (res.ok) {
            allSessions = await res.json();
            renderSessionsTable();
        }
    } catch (_) {}
}

function renderSessionsTable() {
    const tbody = document.getElementById("sessionsTableBody");
    tbody.innerHTML = "";

    let filtered = allSessions;
    if (currentTab === 'active') {
        filtered = allSessions.filter(s => ['DISCOVERED', 'ELIGIBLE', 'ANALYZING', 'PLANNING', 'WORKING', 'VALIDATING', 'PR_OPEN'].includes(s.state));
    } else if (currentTab === 'review') {
        filtered = allSessions.filter(s => ['AWAITING_POLICY', 'MAINTAINER_REVIEW', 'CHANGES_REQUESTED'].includes(s.state));
    } else if (currentTab === 'merged') {
        filtered = allSessions.filter(s => s.state === 'MERGED');
    } else if (currentTab === 'blocked') {
        filtered = allSessions.filter(s => ['REJECTED', 'CANCELLED', 'SAFETY_STOP', 'EXPIRED'].includes(s.state));
    }

    if (!filtered || filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-gray-500">No sessions in '${currentTab}' view.</td></tr>`;
        return;
    }

    filtered.forEach(s => {
        const row = document.createElement("tr");
        row.className = "hover:bg-gray-750 cursor-pointer transition";
        row.onclick = () => selectSession(s);
        row.innerHTML = `
            <td class="px-4 py-3 font-mono text-xs text-blue-400 font-semibold">${s.id}</td>
            <td class="px-4 py-3 text-xs">${s.repository_id}</td>
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-xs state-badge bg-gray-700 text-gray-200">${s.state}</span></td>
            <td class="px-4 py-3 text-xs font-mono text-yellow-400">${s.risk_tier}</td>
            <td class="px-4 py-3 text-xs font-mono">${s.opportunity_score}</td>
            <td class="px-4 py-3"><button class="text-xs text-indigo-400 hover:underline">Inspect</button></td>
        `;
        tbody.appendChild(row);
    });
}

function selectSession(s) {
    selectedSessionId = s.id;
    const inspector = document.getElementById("inspectorContent");
    inspector.innerHTML = `
        <div class="space-y-1">
            <p><strong class="text-white">ID:</strong> <span class="font-mono text-blue-400">${s.id}</span></p>
            <p><strong class="text-white">Mode:</strong> ${s.mode}</p>
            <p><strong class="text-white">State:</strong> <span class="text-yellow-400 font-mono font-bold">${s.state}</span></p>
            <p><strong class="text-white">Version:</strong> ${s.version}</p>
            <p><strong class="text-white">Risk Tier:</strong> ${s.risk_tier}</p>
            <p><strong class="text-white">Opportunity Score:</strong> ${s.opportunity_score}/100</p>
            <p><strong class="text-white">Terminal State:</strong> ${s.is_terminal ? "YES (Immutable)" : "NO (Active)"}</p>
        </div>
    `;
    document.getElementById("cancelBtn").disabled = s.is_terminal;
    document.getElementById("pauseBtn").disabled = s.is_terminal;
    document.getElementById("approveBtn").disabled = (s.state !== "AWAITING_POLICY");

    startSSEStream(s.id);
}

function startSSEStream(sessionId) {
    if (activeEventSource) {
        activeEventSource.close();
    }
    const logBox = document.getElementById("liveStreamLogs");
    logBox.innerHTML = `<span class="text-blue-400">[Connecting SSE stream for ${sessionId}...]</span><br/>`;

    activeEventSource = new EventSource(`/v1/sessions/${sessionId}/stream`);
    activeEventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            const line = document.createElement("div");
            line.innerText = `[${new Date().toLocaleTimeString()}] ${data.message || JSON.stringify(data)}`;
            logBox.appendChild(line);
            logBox.scrollTop = logBox.scrollHeight;
        } catch(_) {
            const line = document.createElement("div");
            line.innerText = event.data;
            logBox.appendChild(line);
        }
    };
    activeEventSource.onerror = function(_) {
        const line = document.createElement("div");
        line.className = "text-yellow-500";
        line.innerText = `[Stream Closed/Reconnecting...]`;
        logBox.appendChild(line);
        activeEventSource.close();
    };
}

async function cancelActiveSession() {
    if (!selectedSessionId) return;
    await fetch(`/v1/sessions/${selectedSessionId}/cancel`, { method: "POST" });
    loadData();
}

async function pauseActiveSession() {
    if (!selectedSessionId) return;
    await fetch(`/v1/sessions/${selectedSessionId}/pause`, { method: "POST" });
    loadData();
}

async function approveActiveSession() {
    if (!selectedSessionId) return;
    await fetch(`/v1/sessions/${selectedSessionId}/approve`, { method: "POST" });
    loadData();
}

async function toggleGlobalKill() {
    const res = await fetch("/v1/ops/kill-switch/global?active=true", { method: "POST" });
    const data = await res.json();
    alert("GLOBAL KILL SWITCH ENGAGED: " + data.global_mutation_kill_active);
}

function loadData() {
    loadMetrics();
    loadSessions();
}

loadData();
setInterval(loadData, 5000);
