let serverStartTime = 0;
let localSecondsElapsed = 0;
let activeRawTab = "health";

let latencyHistory = [];
try {
    const saved = sessionStorage.getItem("am_latency_history");
    if (saved) {
        latencyHistory = JSON.parse(saved);
    }
} catch (_) {
    latencyHistory = [];
}

function formatDuration(totalSeconds) {
    if (totalSeconds < 60) return `${totalSeconds}s`;
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) {
        return `${hours}h ${minutes}m ${seconds}s`;
    }
    return `${minutes}m ${seconds}s`;
}

setInterval(() => {
    if (serverStartTime > 0) {
        localSecondsElapsed++;
        const formatted = formatDuration(localSecondsElapsed);
        const uptimeEl = document.getElementById("uptimeDisplay");
        if (uptimeEl) uptimeEl.textContent = formatted;
        const diagUptime = document.getElementById("diagUptime");
        if (diagUptime) diagUptime.textContent = formatted;
    }
}, 1000);

let countdown = 15;
const countdownMax = 15;
const ringCircumference = 37.7;

function updateRefreshRing(val) {
    const ring = document.getElementById("refreshRingFill");
    if (!ring) return;
    const progress = Math.max(0, Math.min(1, val / countdownMax));
    const offset = ringCircumference * (1 - progress);
    ring.setAttribute("stroke-dasharray", ringCircumference.toFixed(1));
    ring.setAttribute("stroke-dashoffset", offset.toFixed(1));
}

setInterval(() => {
    countdown--;
    if (countdown <= 0) {
        fetchLiveTelemetry();
        countdown = countdownMax;
    }
    const timerEl = document.getElementById("refreshTimer");
    if (timerEl) timerEl.textContent = countdown;
    updateRefreshRing(countdown);
}, 1000);

function dismissIncidentBanner() {
    const banner = document.getElementById("incidentAlertBanner");
    if (banner) banner.classList.add("is-hidden");
    try {
        sessionStorage.setItem("am_incident_dismissed", "true");
    } catch (_) {}
}

function createProviderBadge(providerName, isPrimary = false) {
    const p = (providerName || "").toLowerCase().trim();
    const pill = document.createElement("span");
    pill.className = "provider-badge";

    const bullet = document.createElement("span");
    bullet.className = "provider-bullet";
    bullet.setAttribute("aria-hidden", "true");
    pill.appendChild(bullet);

    let label = providerName;
    if (p.includes("cerebras")) {
        pill.classList.add("provider-cerebras");
        label = "Cerebras";
    } else if (p.includes("groq")) {
        pill.classList.add("provider-groq");
        label = "Groq";
    } else if (p.includes("google") || p.includes("gemini")) {
        pill.classList.add("provider-google");
        label = "Google Gemini";
    } else {
        pill.classList.add("provider-default");
    }

    if (isPrimary) {
        label += " (primary)";
    }
    const textNode = document.createTextNode(label);
    pill.appendChild(textNode);
    return pill;
}

function renderLatencyChart() {
    if (!latencyHistory || latencyHistory.length === 0) return;

    const values = latencyHistory.map((item) => item.latency);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const sum = values.reduce((acc, curr) => acc + curr, 0);
    const avg = Math.round(sum / values.length);
    const current = values[values.length - 1];

    const statMin = document.getElementById("statMinLatency");
    if (statMin) statMin.textContent = `Min: ${min}ms`;
    const statAvg = document.getElementById("statAvgLatency");
    if (statAvg) statAvg.textContent = `Avg: ${avg}ms`;
    const statMax = document.getElementById("statMaxLatency");
    if (statMax) statMax.textContent = `Max: ${max}ms`;
    const statCur = document.getElementById("statCurrentLatency");
    if (statCur) statCur.textContent = `Current: ${current}ms`;

    const oldest = latencyHistory[0];
    const latest = latencyHistory[latencyHistory.length - 1];
    const oldTimeEl = document.getElementById("latencyOldestTime");
    if (oldTimeEl && oldest && oldest.time) {
        oldTimeEl.textContent = new Date(oldest.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    const latTimeEl = document.getElementById("latencyLatestTime");
    if (latTimeEl && latest && latest.time) {
        latTimeEl.textContent = new Date(latest.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    const svgWidth = 600;
    const svgHeight = 90;
    const paddingX = 14;
    const paddingTop = 12;
    const paddingBottom = 16;
    const usableWidth = svgWidth - paddingX * 2;
    const usableHeight = svgHeight - paddingTop - paddingBottom;

    const range = Math.max(20, max - min);
    const points = latencyHistory.map((entry, idx) => {
        const x = latencyHistory.length === 1
            ? svgWidth / 2
            : paddingX + (idx / (latencyHistory.length - 1)) * usableWidth;
        const normalized = (entry.latency - min) / range;
        const y = (svgHeight - paddingBottom) - (normalized * usableHeight);
        return { x: Math.round(x), y: Math.round(y), latency: entry.latency, time: entry.time };
    });

    if (points.length === 0) return;

    let pathD = `M ${points[0].x} ${points[0].y}`;
    for (let i = 1; i < points.length; i++) {
        pathD += ` L ${points[i].x} ${points[i].y}`;
    }

    const linePath = document.getElementById("latencyLinePath");
    if (linePath) linePath.setAttribute("d", pathD);

    const areaD = `${pathD} L ${points[points.length - 1].x} ${svgHeight} L ${points[0].x} ${svgHeight} Z`;
    const areaPath = document.getElementById("latencyAreaPath");
    if (areaPath) areaPath.setAttribute("d", areaD);

    const dotsGroup = document.getElementById("latencyDotsGroup");
    if (dotsGroup) {
        dotsGroup.innerHTML = "";
        points.forEach((pt) => {
            const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            circle.setAttribute("cx", pt.x);
            circle.setAttribute("cy", pt.y);
            circle.setAttribute("r", "4");
            circle.setAttribute("class", "latency-dot");

            const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
            const timeStr = pt.time ? new Date(pt.time).toLocaleTimeString() : "";
            title.textContent = `${pt.latency}ms (${timeStr})`;
            circle.appendChild(title);

            dotsGroup.appendChild(circle);
        });
    }
}

function switchRawTab(tabName, btnEl) {
    activeRawTab = tabName;
    document.querySelectorAll(".raw-tab").forEach((t) => t.classList.remove("is-active"));
    if (btnEl) btnEl.classList.add("is-active");

    const panels = {
        health: document.getElementById("panelHealth"),
        inference: document.getElementById("panelInference"),
        managed: document.getElementById("panelManaged"),
    };

    Object.keys(panels).forEach((k) => {
        if (panels[k]) {
            if (k === tabName) {
                panels[k].classList.remove("is-hidden");
            } else {
                panels[k].classList.add("is-hidden");
            }
        }
    });
}

function copyActiveJsonPayload() {
    let targetPreId = "opsJsonBox";
    if (activeRawTab === "inference") {
        targetPreId = "inferenceJsonBox";
    } else if (activeRawTab === "managed") {
        targetPreId = "managedJsonBox";
    }

    const preEl = document.getElementById(targetPreId);
    if (!preEl) return;
    const content = preEl.textContent || "";

    const copyBtn = document.getElementById("btnCopyRaw");
    const copyText = document.getElementById("btnCopyText");

    const onCopied = () => {
        if (copyText) copyText.textContent = "Copied!";
        if (copyBtn) copyBtn.classList.add("is-copied");
        setTimeout(() => {
            if (copyText) copyText.textContent = "Copy JSON";
            if (copyBtn) copyBtn.classList.remove("is-copied");
        }, 2000);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(content).then(onCopied).catch(() => {
            fallbackCopy(content, onCopied);
        });
    } else {
        fallbackCopy(content, onCopied);
    }
}

function fallbackCopy(text, cb) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
        document.execCommand("copy");
        cb();
    } catch (_) {}
    document.body.removeChild(ta);
}

async function fetchLiveTelemetry() {
    const refreshIcon = document.getElementById("refreshBtnIcon");
    if (refreshIcon) refreshIcon.classList.add("is-spinning");

    const startTime = performance.now();
    try {
        const res = await fetch("/v1/ops/health?format=json");
        const duration = Math.round(performance.now() - startTime);

        latencyHistory.push({ time: Date.now(), latency: duration });
        if (latencyHistory.length > 20) {
            latencyHistory.shift();
        }
        try {
            sessionStorage.setItem("am_latency_history", JSON.stringify(latencyHistory));
        } catch (_) {}
        renderLatencyChart();

        const pingLatency = document.getElementById("pingLatency");
        if (pingLatency) pingLatency.textContent = `${duration}ms roundtrip`;
        const endpointLatency = document.getElementById("endpointLatency");
        if (endpointLatency) endpointLatency.textContent = `${duration}ms API latency`;

        const data = await res.json();
        const opsJsonBox = document.getElementById("opsJsonBox");
        if (opsJsonBox) opsJsonBox.textContent = JSON.stringify(data, null, 2);

        const opsHttpCode = document.getElementById("opsHttpCode");
        if (opsHttpCode) opsHttpCode.textContent = `${res.status} OK`;

        if (data.uptime_seconds !== undefined) {
            localSecondsElapsed = data.uptime_seconds;
            const formatted = formatDuration(localSecondsElapsed);
            const uptimeEl = document.getElementById("uptimeDisplay");
            if (uptimeEl) uptimeEl.textContent = formatted;
            const diagUptime = document.getElementById("diagUptime");
            if (diagUptime) diagUptime.textContent = formatted;
        }

        if (data.started_at) {
            serverStartTime = data.started_at;
            const bootDate = new Date(data.started_at * 1000);
            const bootEl = document.getElementById("bootTimeDisplay");
            if (bootEl) bootEl.textContent = bootDate.toLocaleTimeString() + " " + bootDate.toLocaleDateString();
        }

        if (data.environment) {
            const envMeta = document.getElementById("envMeta");
            if (envMeta) envMeta.textContent = `Environment: ${data.environment}`;
            const diagEnv = document.getElementById("diagEnv");
            if (diagEnv) diagEnv.textContent = data.environment;
        }

        const isHealthy = res.ok && data.status === "healthy";
        const statusTitle = document.getElementById("statusTitle");
        if (statusTitle) statusTitle.textContent = isHealthy ? "All Core Systems Operational" : "Service Operating in Degraded Mode";

        const overallBanner = document.getElementById("overallBanner");
        if (overallBanner) overallBanner.className = isHealthy ? "overall-banner status-healthy" : "overall-banner status-degraded";

        const overallBadge = document.getElementById("overallBadge");
        if (overallBadge) {
            overallBadge.className = isHealthy ? "status-badge badge-healthy" : "status-badge badge-degraded";
            overallBadge.textContent = isHealthy ? "OPERATIONAL" : "DEGRADED";
        }

        const diagEngine = document.getElementById("diagEngineStatus");
        if (diagEngine) {
            diagEngine.textContent = isHealthy ? "Healthy" : "Degraded";
            diagEngine.className = isHealthy ? "kv-val text-brand" : "kv-val";
        }

        const alertBanner = document.getElementById("incidentAlertBanner");
        if (alertBanner) {
            let isDismissed = false;
            try {
                isDismissed = sessionStorage.getItem("am_incident_dismissed") === "true";
            } catch (_) {}

            if (!isHealthy && !isDismissed) {
                alertBanner.classList.remove("is-hidden");
                const incidentText = document.getElementById("incidentText");
                const errList = data.errors && data.errors.length > 0 ? data.errors.join(", ") : "Subsystem degraded";
                if (incidentText) incidentText.textContent = `Active Incident: ${errList}`;
            } else if (isHealthy) {
                alertBanner.classList.add("is-hidden");
                try {
                    sessionStorage.removeItem("am_incident_dismissed");
                } catch (_) {}
            }
        }

        if (data.checks) {
            const dbBadge = document.getElementById("dbBadge");
            if (dbBadge) {
                dbBadge.textContent = data.checks.database ? "CONNECTED" : "DISCONNECTED";
                dbBadge.className = data.checks.database ? "status-badge badge-healthy" : "status-badge badge-degraded";
            }
            const diagDb = document.getElementById("diagDbStatus");
            if (diagDb) {
                diagDb.textContent = data.checks.database ? "Connected" : "Disconnected";
                diagDb.className = data.checks.database ? "kv-val text-brand" : "kv-val";
            }

            const queueBadge = document.getElementById("queueBadge");
            if (queueBadge) {
                queueBadge.textContent = data.checks.queue ? "OPERATIONAL" : "DEGRADED";
                queueBadge.className = data.checks.queue ? "status-badge badge-healthy" : "status-badge badge-degraded";
            }
            const diagQueue = document.getElementById("diagQueueStatus");
            if (diagQueue) {
                diagQueue.textContent = data.checks.queue ? "Operational" : "Degraded";
                diagQueue.className = data.checks.queue ? "kv-val text-brand" : "kv-val";
            }

            const sandBadge = document.getElementById("sandboxBadge");
            if (sandBadge) {
                sandBadge.textContent = data.checks.sandbox ? "READY" : "DEGRADED";
                sandBadge.className = data.checks.sandbox ? "status-badge badge-healthy" : "status-badge badge-degraded";
            }
            const diagSand = document.getElementById("diagSandboxStatus");
            if (diagSand) {
                diagSand.textContent = data.checks.sandbox ? "Active" : "Degraded";
                diagSand.className = data.checks.sandbox ? "kv-val text-brand" : "kv-val";
            }
        }
    } catch (err) {
        const opsBox = document.getElementById("opsJsonBox");
        if (opsBox) opsBox.textContent = `Error reaching /v1/ops/health: ${err.message}`;

        const statusTitle = document.getElementById("statusTitle");
        if (statusTitle) statusTitle.textContent = "Control Plane Unreachable";

        const overallBanner = document.getElementById("overallBanner");
        if (overallBanner) overallBanner.className = "overall-banner status-degraded";

        const overallBadge = document.getElementById("overallBadge");
        if (overallBadge) {
            overallBadge.className = "status-badge badge-degraded";
            overallBadge.textContent = "OFFLINE";
        }

        const alertBanner = document.getElementById("incidentAlertBanner");
        if (alertBanner) {
            alertBanner.classList.remove("is-hidden");
            const incidentText = document.getElementById("incidentText");
            if (incidentText) incidentText.textContent = `Active Incident: Unable to reach AutoMaintainer backend (${err.message})`;
        }
    }

    try {
        const infRes = await fetch("/v1/ops/inference-status");
        if (infRes.ok) {
            const infData = await infRes.json();
            const infJsonBox = document.getElementById("inferenceJsonBox");
            if (infJsonBox) infJsonBox.textContent = JSON.stringify(infData, null, 2);

            const infHttpCode = document.getElementById("infHttpCode");
            if (infHttpCode) infHttpCode.textContent = `${infRes.status} OK`;

            const isInfHealthy = infData.status === "healthy";
            const infBadge = document.getElementById("inferenceBadge");
            if (infBadge) {
                infBadge.textContent = isInfHealthy ? "OPERATIONAL" : "DEGRADED";
                infBadge.className = isInfHealthy ? "status-badge badge-healthy" : "status-badge badge-degraded";
            }

            const diagInf = document.getElementById("diagInfStatus");
            if (diagInf) {
                diagInf.textContent = isInfHealthy ? "Healthy" : "Degraded";
                diagInf.className = isInfHealthy ? "kv-val text-brand" : "kv-val";
            }

            const diagPrimary = document.getElementById("diagInfPrimary");
            if (diagPrimary) {
                diagPrimary.innerHTML = "";
                if (infData.primary_provider) {
                    diagPrimary.appendChild(createProviderBadge(infData.primary_provider, true));
                } else {
                    diagPrimary.textContent = "none";
                }
            }

            const diagPriority = document.getElementById("diagInfPriority");
            if (diagPriority) {
                diagPriority.innerHTML = "";
                if (Array.isArray(infData.configured_priority) && infData.configured_priority.length > 0) {
                    infData.configured_priority.forEach((p, idx) => {
                        diagPriority.appendChild(createProviderBadge(p, idx === 0));
                    });
                } else {
                    diagPriority.textContent = "none configured";
                }
            }

            const diagActive = document.getElementById("diagActiveProviders");
            if (diagActive) {
                diagActive.innerHTML = "";
                const providers = infData.active_providers || [];
                if (providers.length > 0) {
                    providers.forEach((p) => {
                        diagActive.appendChild(createProviderBadge(p));
                    });
                } else {
                    const fallback = document.createElement("span");
                    fallback.className = "provider-badge provider-default";
                    fallback.textContent = "none detected";
                    diagActive.appendChild(fallback);
                }
            }

            const infMeta = document.getElementById("inferenceMeta");
            if (infMeta) {
                infMeta.innerHTML = "";
                const primarySpan = document.createElement("span");
                primarySpan.textContent = "Primary: ";
                infMeta.appendChild(primarySpan);
                if (infData.primary_provider) {
                    infMeta.appendChild(createProviderBadge(infData.primary_provider, true));
                }
                if (Array.isArray(infData.active_providers) && infData.active_providers.length > 1) {
                    const failoverSpan = document.createElement("span");
                    failoverSpan.textContent = " • Redundant: ";
                    infMeta.appendChild(failoverSpan);
                    infData.active_providers.filter(p => p !== infData.primary_provider).forEach(p => {
                        infMeta.appendChild(createProviderBadge(p));
                    });
                }
            }
        }
    } catch (_) {}

    try {
        const repoRes = await fetch("/v1/public/managed-repos");
        if (repoRes.ok) {
            const repoData = await repoRes.json();
            const managedJsonBox = document.getElementById("managedJsonBox");
            if (managedJsonBox) managedJsonBox.textContent = JSON.stringify(repoData, null, 2);

            const countBadge = document.getElementById("managedCountBadge");
            if (countBadge) countBadge.textContent = `${repoData.managed_count || 0} registered`;

            const listEl = document.getElementById("managedReposList");
            if (listEl && Array.isArray(repoData.repositories)) {
                listEl.innerHTML = "";
                if (repoData.repositories.length === 0) {
                    listEl.innerHTML = `<div class="fleet-item"><span class="fleet-desc">No managed repositories registered yet.</span></div>`;
                } else {
                    repoData.repositories.forEach((repo) => {
                        const item = document.createElement("div");
                        item.className = "fleet-item";

                        const left = document.createElement("div");
                        const link = document.createElement("a");
                        link.className = "fleet-repo-name";
                        link.href = `https://github.com/${repo.repository}`;
                        link.target = "_blank";
                        link.rel = "noopener";
                        link.textContent = `${repo.repository} ↗`;

                        const meta = document.createElement("div");
                        meta.className = "fleet-repo-meta";

                        const branchTag = document.createElement("span");
                        branchTag.className = "fleet-meta-tag";
                        branchTag.textContent = `branch: ${repo.branch || "main"}`;

                        const prioTag = document.createElement("span");
                        prioTag.className = "fleet-meta-tag";
                        prioTag.textContent = `priority: ${repo.priority || "standard"}`;

                        meta.appendChild(branchTag);
                        meta.appendChild(prioTag);

                        left.appendChild(link);
                        left.appendChild(meta);

                        const right = document.createElement("span");
                        right.className = "status-badge badge-healthy";
                        right.textContent = "MONITORED";

                        item.appendChild(left);
                        item.appendChild(right);
                        listEl.appendChild(item);
                    });
                }
            }
        }
    } catch (_) {}

    if (refreshIcon) refreshIcon.classList.remove("is-spinning");
}

fetchLiveTelemetry();
