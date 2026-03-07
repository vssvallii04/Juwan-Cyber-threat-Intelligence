const API = "http://127.0.0.1:8000";

let phishingCount = 0;
let legitimateCount = 0;
let totalCount = 0;
let currentThreatLevel = "LOW";
let pieChart = null;
let threatChart = null;

/* -------- Initialize Charts on Load -------- */
document.addEventListener('DOMContentLoaded', () => {
    initializePieChart();
    initializeThreatChart();
    syncInputs();
});

/* -------- Initialize Pie Chart -------- */
function initializePieChart() {
    const ctx = document.getElementById("pieChart");
    if (!ctx) return;
    
    pieChart = new Chart(ctx.getContext("2d"), {
        type: "doughnut",
        data: {
            labels: ["Phishing", "Legitimate"],
            datasets: [{
                data: [0, 0],
                backgroundColor: ["#ef4444", "#22c55e"],
                borderColor: ["rgba(239, 68, 68, 0.3)", "rgba(34, 197, 94, 0.3)"],
                borderWidth: 2,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#cbd5e1",
                        font: { size: 11 },
                        padding: 10
                    }
                }
            }
        }
    });
}

/* -------- Initialize Threat Chart -------- */
function initializeThreatChart() {
    const ctx = document.getElementById("threatChart");
    if (!ctx) return;

    threatChart = new Chart(ctx.getContext("2d"), {
        type: "bar",
        data: {
            labels: ["Phishing", "Legitimate"],
            datasets: [{
                label: "Total Detections",
                data: [0, 0],
                backgroundColor: ["#ef4444", "#22c55e"],
                borderColor: ["#dc2626", "#16a34a"],
                borderWidth: 2,
                borderRadius: 8,
                hoverBackgroundColor: ["#f87171", "#4ade80"]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: "#cbd5e1" },
                    grid: { color: "rgba(71, 85, 105, 0.1)" }
                },
                x: {
                    ticks: { color: "#cbd5e1" },
                    grid: { display: false }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: "#cbd5e1",
                        font: { size: 11 }
                    }
                }
            }
        }
    });
}

/* -------- Format Result Display -------- */
function formatResult(data, type) {
    if (!data || data.error) {
        return `<div class="result-box" style="color: #fca5a5;">Error: ${data?.error || 'Unknown error'}</div>`;
    }

    const prediction = data.prediction || data.final_decision || 'unknown';
    const isPhishing = prediction.toLowerCase() === 'phishing';
    const className = isPhishing ? 'phishing' : 'legitimate';
    const confidence = data.confidence || data.confidence_score || 0;

    let html = `<div class="result-box ${className}">`;
    html += `<div class="result-label">${type} Analysis Result</div>`;
    html += `<div class="result-value">${prediction.toUpperCase()}</div>`;
    html += `<div class="result-detail">Confidence: ${(confidence * 100).toFixed(1)}%</div>`;

    if (data.feature_contributions) {
        html += `<div class="feature-list">`;
        html += `<div class="result-label" style="margin-bottom: 0.75rem;">Feature Analysis</div>`;
        for (const [key, value] of Object.entries(data.feature_contributions)) {
            html += `<div class="feature-item">
                <span class="feature-name">${key.replace(/_/g, ' ')}</span>
                <span class="feature-score">${(value * 100).toFixed(1)}%</span>
            </div>`;
        }
        html += `</div>`;
    }

    if (data.detected_keywords) {
        html += `<div class="feature-list">`;
        html += `<div class="result-label">Detected Keywords</div>`;
        html += `<div style="margin-top: 0.5rem; font-size: 0.85rem; color: var(--text-secondary);">`;
        html += data.detected_keywords.join(', ');
        html += `</div></div>`;
    }

    if (data.threat_level) {
        html += `<div class="result-detail" style="margin-top: 1rem; font-weight: 600;">Threat Level: <span style="color: ${
            data.threat_level === 'HIGH' ? '#ef4444' : 
            data.threat_level === 'MEDIUM' ? '#f59e0b' : '#22c55e'
        }">${data.threat_level}</span></div>`;
    }

    html += `</div>`;
    return html;
}

/* -------- Update Threat Level -------- */
function updateThreatLevel(threatLevel = null) {
    if (threatLevel) {
        currentThreatLevel = threatLevel;
    } else if (phishingCount >= 3) {
        currentThreatLevel = "HIGH";
    } else if (phishingCount >= 1) {
        currentThreatLevel = "MEDIUM";
    } else {
        currentThreatLevel = "LOW";
    }

    const threatLevelEl = document.querySelector('.threat-indicator');
    if (threatLevelEl) {
        threatLevelEl.textContent = currentThreatLevel;
        threatLevelEl.className = 'threat-indicator ' + currentThreatLevel.toLowerCase();
        
        // Update threat bar
        const percentage = Math.min((phishingCount / Math.max(totalCount, 3)) * 100, 100);
        const threatBar = document.querySelector('.threat-bar-fill');
        if (threatBar) {
            threatBar.style.width = percentage + '%';
        }
    }
}

/* -------- Email Detection -------- */
async function checkEmail() {
    const text = document.getElementById("emailText").value.trim();

    if (!text) {
        const result = document.getElementById("emailResult");
        result.innerHTML = '<div class="result-box" style="color: #f59e0b;">Please enter email content to analyze</div>';
        result.className = 'result-container warning';
        return;
    }

    const result = document.getElementById("emailResult");
    result.innerHTML = '<div style="text-align: center; color: var(--text-muted);">🔍 Analyzing...</div>';

    try {
        const res = await fetch(`${API}/analyze/email`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ text })
        });

        const data = await res.json();

        if (!res.ok) {
            result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Error: ${data.message || 'Email analysis failed'}</div>`;
            result.className = 'result-container error';
            return;
        }

        result.innerHTML = formatResult(data, 'Email');
        result.className = 'result-container success';

        // Update stats
        if (data.prediction === "phishing") {
            phishingCount++;
        } else {
            legitimateCount++;
        }
        totalCount++;

        document.getElementById("totalScans").textContent = totalCount;
        document.getElementById("phishingCount").textContent = phishingCount;
        document.getElementById("legitimateCount").textContent = legitimateCount;

        updateThreatLevel();
        if (pieChart) {
            pieChart.data.datasets[0].data = [phishingCount, legitimateCount];
            pieChart.update();
        }
        if (threatChart) {
            threatChart.data.datasets[0].data = [phishingCount, legitimateCount];
            threatChart.update();
        }

    } catch (error) {
        result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Network Error: ${error.message}</div>`;
        result.className = 'result-container error';
    }
}

/* -------- URL Detection -------- */
async function checkURL() {
    const url = document.getElementById("urlText").value.trim();

    if (!url) {
        const result = document.getElementById("urlResult");
        result.innerHTML = '<div class="result-box" style="color: #f59e0b;">Please enter a URL to analyze</div>';
        result.className = 'result-container warning';
        return;
    }

    const result = document.getElementById("urlResult");
    result.innerHTML = '<div style="text-align: center; color: var(--text-muted);">🔍 Analyzing...</div>';

    try {
        const res = await fetch(`${API}/analyze/url`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ url })
        });

        const data = await res.json();

        if (!res.ok) {
            result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Error: ${data.message || 'URL analysis failed'}</div>`;
            result.className = 'result-container error';
            return;
        }

        result.innerHTML = formatResult(data, 'URL');
        result.className = 'result-container success';

        // Update stats
        if (data.prediction === "phishing") {
            phishingCount++;
        } else {
            legitimateCount++;
        }
        totalCount++;

        document.getElementById("totalScans").textContent = totalCount;
        document.getElementById("phishingCount").textContent = phishingCount;
        document.getElementById("legitimateCount").textContent = legitimateCount;

        updateThreatLevel();
        if (pieChart) {
            pieChart.data.datasets[0].data = [phishingCount, legitimateCount];
            pieChart.update();
        }
        if (threatChart) {
            threatChart.data.datasets[0].data = [phishingCount, legitimateCount];
            threatChart.update();
        }

    } catch (error) {
        result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Network Error: ${error.message}</div>`;
        result.className = 'result-container error';
    }
}

/* -------- Chat Detection -------- */
async function checkChat() {
    const text = document.getElementById("chatText").value.trim();

    if (!text) {
        const result = document.getElementById("chatResult");
        result.innerHTML = '<div class="result-box" style="color: #f59e0b;">Please enter a message to analyze</div>';
        result.className = 'result-container warning';
        return;
    }

    const result = document.getElementById("chatResult");
    result.innerHTML = '<div style="text-align: center; color: var(--text-muted);">🔍 Analyzing...</div>';

    try {
        const res = await fetch(`${API}/analyze/chat`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ text })
        });

        const data = await res.json();

        if (!res.ok) {
            result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Error: ${data.message || 'Chat analysis failed'}</div>`;
            result.className = 'result-container error';
            return;
        }

        result.innerHTML = formatResult(data, 'Chat');
        result.className = 'result-container success';

    } catch (error) {
        result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Network Error: ${error.message}</div>`;
        result.className = 'result-container error';
    }
}

/* -------- Ensemble Decision -------- */
async function checkEnsemble() {
    const email = document.getElementById("emailText2").value.trim();
    const url = document.getElementById("urlText2").value.trim();
    const chat = document.getElementById("chatText2").value.trim();

    if (!email && !url && !chat) {
        const result = document.getElementById("ensembleResult");
        result.innerHTML = '<div class="result-box" style="color: #f59e0b;">Please provide at least one input (email, URL, or chat)</div>';
        result.className = 'result-container warning';
        return;
    }

    const result = document.getElementById("ensembleResult");
    result.innerHTML = '<div style="text-align: center; color: var(--text-muted);">🚀 Running ensemble analysis...</div>';

    try {
        const res = await fetch(`${API}/analyze/ensemble`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ email, url, chat })
        });

        const data = await res.json();

        if (!res.ok) {
            result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Error: ${data.message || 'Ensemble analysis failed'}</div>`;
            result.className = 'result-container error';
            return;
        }

        result.innerHTML = formatResult(data, 'Ensemble');
        result.className = 'result-container success';

        // Update threat level and stats
        if (data.threat_level) {
            updateThreatLevel(data.threat_level);
        }

        if (data.final_decision === "phishing") {
            phishingCount++;
        } else {
            legitimateCount++;
        }

        totalCount++;
        document.getElementById("totalScans").textContent = totalCount;
        document.getElementById("phishingCount").textContent = phishingCount;
        document.getElementById("legitimateCount").textContent = legitimateCount;

        if (pieChart) {
            pieChart.data.datasets[0].data = [phishingCount, legitimateCount];
            pieChart.update();
        }
        if (threatChart) {
            threatChart.data.datasets[0].data = [phishingCount, legitimateCount];
            threatChart.update();
        }

    } catch (error) {
        result.innerHTML = `<div class="result-box" style="color: #fca5a5;">Network Error: ${error.message}</div>`;
        result.className = 'result-container error';
    }
}

/* -------- Sync Inputs to Ensemble Tab -------- */
function syncInputs() {
    document.getElementById('emailText').addEventListener('change', () => {
        document.getElementById('emailText2').value = document.getElementById('emailText').value;
    });
    document.getElementById('urlText').addEventListener('change', () => {
        document.getElementById('urlText2').value = document.getElementById('urlText').value;
    });
    document.getElementById('chatText').addEventListener('change', () => {
        document.getElementById('chatText2').value = document.getElementById('chatText').value;
    });
}