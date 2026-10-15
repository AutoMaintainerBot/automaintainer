const diffData = {
    actions: {
        title: "fix(ci): pin GitHub Actions to immutable commit hashes #142",
        branch: "AutoMaintainerBot:pin-actions",
        code: '<span class="diff-line diff-ctx">@@ -18,5 +18,5 @@ jobs:</span>\n<span class="diff-line diff-ctx">     steps:</span>\n<span class="diff-line diff-del">-     - uses: actions/checkout@v3</span>\n<span class="diff-line diff-add">+     - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.2.2</span>\n<span class="diff-line diff-ctx">       with:</span>\n<span class="diff-line diff-ctx">         fetch-depth: 0</span>'
    },
    docs: {
        title: "docs(readme): repair broken 404 documentation links #143",
        branch: "AutoMaintainerBot:fix-docs-links",
        code: '<span class="diff-line diff-ctx">@@ -42,4 +42,4 @@</span>\n<span class="diff-line diff-ctx"> For configuration details, see the guide:</span>\n<span class="diff-line diff-del">-See [Scaling Guide](https://legacy.docs.dev/clustering) for cluster sizing.</span>\n<span class="diff-line diff-add">+See [Scaling Guide](https://automaintainer.onrender.com/status) for cluster sizing.</span>'
    },
    deps: {
        title: "chore(deps): update urllib3 to patch CVE security advisory #144",
        branch: "AutoMaintainerBot:update-urllib3",
        code: '<span class="diff-line diff-ctx">@@ -12,4 +12,4 @@</span>\n<span class="diff-line diff-ctx"> [tool.poetry.dependencies]</span>\n<span class="diff-line diff-del">-urllib3 = "^1.26.5"</span>\n<span class="diff-line diff-add">+urllib3 = "^2.2.3"</span>'
    },
    badges: {
        title: "docs(readme): repair broken CI status badges #145",
        branch: "AutoMaintainerBot:fix-readme-badges",
        code: '<span class="diff-line diff-ctx">@@ -3,3 +3,3 @@</span>\n<span class="diff-line diff-ctx"> # my-open-source-project</span>\n<span class="diff-line diff-del">-[![CI Status](https://travis-ci.org/org/repo.svg?branch=master)](https://travis-ci.org/org/repo)</span>\n<span class="diff-line diff-add">+[![CI Status](https://github.com/org/repo/actions/workflows/ci.yml/badge.svg)](https://github.com/org/repo/actions)</span>\n<span class="diff-line diff-ctx"> A modern high-performance library...</span>'
    },
    format: {
        title: "chore(tooling): synchronize prettier and editorconfig standards #146",
        branch: "AutoMaintainerBot:sync-tooling",
        code: '<span class="diff-line diff-ctx">@@ -1,5 +1,5 @@</span>\n<span class="diff-line diff-ctx"> {</span>\n<span class="diff-line diff-del">-  "trailingComma": "none",</span>\n<span class="diff-line diff-add">+  "trailingComma": "es5",</span>\n<span class="diff-line diff-ctx">   "singleQuote": true,</span>\n<span class="diff-line diff-ctx">   "tabWidth": 2</span>\n<span class="diff-line diff-ctx"> }</span>'
    }
};

function setDiff(type, btn) {
    document.querySelectorAll('.diff-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    const item = diffData[type];
    if (!item) return;
    document.getElementById('prTitleText').textContent = item.title;
    document.getElementById('diffCode').innerHTML = item.code;
}

let debounceTimer = null;
let lastAuditedRepo = '';
const repoInput = document.getElementById('repoInput');
const prevImg = document.getElementById('prevImg');
const prevName = document.getElementById('prevName');
const prevDesc = document.getElementById('prevDesc');

function cleanRepo(str) {
    return str.replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '').trim();
}

function formatDiffLines(rawDiff) {
    if (!rawDiff) return '<span class="diff-line diff-ctx">No diff generated</span>';
    return rawDiff.split('\n').map(line => {
        const esc = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        if (line.startsWith('+')) {
            return `<span class="diff-line diff-add">${esc}</span>`;
        } else if (line.startsWith('-')) {
            return `<span class="diff-line diff-del">${esc}</span>`;
        } else if (line.startsWith('@@')) {
            return `<span class="diff-line diff-hunk">${esc}</span>`;
        } else {
            return `<span class="diff-line diff-ctx">${esc}</span>`;
        }
    }).join('\n');
}

if (repoInput) {
    repoInput.addEventListener('input', (e) => {
        clearTimeout(debounceTimer);
        const val = cleanRepo(e.target.value);
        if (!val || !val.includes('/')) return;

        debounceTimer = setTimeout(async () => {
            try {
                const res = await fetch(`https://api.github.com/repos/${val}`);
                if (res.ok) {
                    const data = await res.json();
                    prevName.textContent = data.full_name;
                    prevDesc.textContent = data.description || 'Public repository on GitHub';
                    if (data.owner && data.owner.avatar_url) {
                        prevImg.src = data.owner.avatar_url;
                    }
                }
            } catch (_) {}
        }, 450);
    });
}

async function runDryRun() {
    const raw = repoInput.value.trim();
    const repo = cleanRepo(raw);
    const alertBox = document.getElementById('alertBox');
    const btn = document.getElementById('btnDryRun');
    const dryRunContainer = document.getElementById('dryRunContainer');

    if (!repo || !repo.includes('/') || repo.split('/').length !== 2) {
        alertBox.className = 'alert-box error';
        alertBox.textContent = 'Please enter a valid repository format: owner/repo (such as octocat/Hello-World)';
        return;
    }

    btn.disabled = true;
    btn.innerHTML = 'Auditing...';
    alertBox.className = 'alert-box';
    alertBox.style.display = 'none';

    try {
        const res = await fetch('/v1/public/managed-repos/dry-run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repository: repo })
        });

        const data = await res.json();
        if (res.ok) {
            lastAuditedRepo = data.repository;
            document.getElementById('dryRunRepoTitle').textContent = data.repository;
            document.getElementById('dryRunStars').textContent = `★ ${data.stars.toLocaleString()} stars`;
            document.getElementById('dryRunBranch').textContent = `branch: ${data.default_branch}`;
            document.getElementById('dryRunChoresCount').textContent = data.chores_count;

            const choresList = document.getElementById('dryRunChoresList');
            choresList.innerHTML = (data.chores || []).map(c => `
                <div class="chore-card-mini">
                    <div class="chore-mini-header">
                        <span class="chore-tag">${c.type}</span>
                        <span class="chore-conf">${c.confidence}% confidence</span>
                    </div>
                    <div class="chore-mini-summary">${c.summary}</div>
                    <div class="chore-mini-meta">${(c.target_paths || []).join(', ')}</div>
                </div>
            `).join('');

            document.getElementById('dryRunDiffPreview').innerHTML = formatDiffLines(data.sample_diff);
            dryRunContainer.classList.remove('is-hidden');
            dryRunContainer.style.display = 'block';
            dryRunContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            alertBox.className = 'alert-box error';
            alertBox.textContent = data.detail || 'Could not audit repository. Please verify the repo is public.';
        }
    } catch (_) {
        alertBox.className = 'alert-box error';
        alertBox.textContent = 'Connection error during dry run. Please try again.';
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M11.536 3.464a5 5 0 010 7.072L8 14.07l-3.536-3.535a5 5 0 017.072-7.072zM8 9a2 2 0 100-4 2 2 0 000 4z"/></svg> Run Dry-Run Audit`;
    }
}

async function confirmRegisterFromDryRun() {
    const repo = lastAuditedRepo || cleanRepo(repoInput.value.trim());
    if (!repo) return;
    repoInput.value = repo;
    await registerRepo();
}

async function registerRepo() {
    const raw = repoInput.value.trim();
    const repo = cleanRepo(raw);
    const alertBox = document.getElementById('alertBox');
    const btn = document.getElementById('btnRegister');

    if (!repo || !repo.includes('/') || repo.split('/').length !== 2) {
        alertBox.className = 'alert-box error';
        alertBox.textContent = 'Please enter a valid repository format: owner/repo (such as octocat/Hello-World)';
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Adding...';
    alertBox.className = 'alert-box';
    alertBox.style.display = 'none';

    try {
        const res = await fetch('/v1/public/managed-repos/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                repository: repo,
                contact: 'web-portal',
                notes: 'Registered via web portal'
            })
        });

        const data = await res.json();
        if (res.ok) {
            alertBox.className = 'alert-box success';
            alertBox.textContent = `Repository ${repo} registered! AutoMaintainer will inspect it on the next cycle.`;
            repoInput.value = '';
        } else {
            alertBox.className = 'alert-box error';
            alertBox.textContent = data.detail || 'Could not register repository. Please verify the repo is public.';
        }
    } catch (_) {
        alertBox.className = 'alert-box error';
        alertBox.textContent = 'Connection error. Please try again or submit a PR on GitHub.';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Add repo directly';
    }
}

function copySnippet() {
    const raw = repoInput.value.trim();
    const repo = cleanRepo(raw) || "organization/repository";
    const snippet = `- repository: "${repo}"\n  priority: "standard"\n  branch: "main"`;
    navigator.clipboard.writeText(snippet).then(() => {
        alert("YAML snippet copied to clipboard!");
    });
}
