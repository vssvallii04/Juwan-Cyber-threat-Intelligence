const API = "http://127.0.0.1:8000";

let phishingCount = 0;
let legitimateCount = 0;
let totalCount = 0;
let currentThreatLevel = "LOW";

/* -------- Error Display -------- */
function displayError(elementId, message) {
    const element = document.getElementById(elementId);
    element.innerHTML = `<div style="color: #d32f2f; background: #ffebee; padding: 12px; border-radius: 4px; border-left: 4px solid #d32f2f;"><strong>Error:</strong> ${message}</div>`;
}

function displaySuccess(elementId, data) {
    const element = document.getElementById(elementId);
    element.innerHTML = `<div style="color: #388e3c; background: #e8f5e9; padding: 12px; border-radius: 4px; border-left: 4px solid #388e3c;"><strong>Success:</strong><pre>${JSON.stringify(data, null, 2)}</pre></div>`;
}

/* -------- Threat Level Helper -------- */
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
    
    const threatLevelEl = document.getElementById("threatLevel");
    threatLevelEl.textContent = currentThreatLevel;
    
    // Apply color coding with styling
    const color = 
        currentThreatLevel === "HIGH" ? "#d32f2f" :
        currentThreatLevel === "MEDIUM" ? "#f57c00" : 
        "#388e3c";
    
    threatLevelEl.style.color = color;
    threatLevelEl.style.fontWeight = "bold";
    threatLevelEl.style.fontSize = "18px";
}

/* -------- Dashboard Chart -------- */
const ctx = document.getElementById("pieChart").getContext("2d");
const threatChart = new Chart(ctx, {
    type: "bar",
    data: {
        labels: ["Phishing", "Legitimate"],
        datasets: [{
            label: "Threat Detection",
            data: [0, 0],
            backgroundColor: ["#d32f2f", "#388e3c"]
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});


/* -------- Email Detection -------- */
async function checkEmail() {
    const text = document.getElementById("emailText").value;

    if (!text.trim()) {
        displayError("emailResult", "Please enter email text to analyze");
        return;
    }

    try {
        const res = await fetch(`${API}/analyze/email`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ text })
        });

        const data = await res.json();

        if (!res.ok) {
            displayError("emailResult", data.message || "Email analysis failed");
            return;
        }

        displaySuccess("emailResult", data);

        /* Update Dashboard */
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

        threatChart.data.datasets[0].data = [phishingCount, legitimateCount];
        threatChart.update();

    } catch (error) {
        displayError("emailResult", `Network error: ${error.message}`);
    }
}


/* -------- URL Detection -------- */
async function checkURL() {
    const url = document.getElementById("urlText").value;

    if (!url.trim()) {
        displayError("urlResult", "Please enter a URL to analyze");
        return;
    }

    try {
        const res = await fetch(`${API}/analyze/url`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ url })
        });

        const data = await res.json();

        if (!res.ok) {
            displayError("urlResult", data.message || "URL analysis failed");
            return;
        }

        displaySuccess("urlResult", data);

    } catch (error) {
        displayError("urlResult", `Network error: ${error.message}`);
    }
}


/* -------- Chat Detection -------- */
async function checkChat() {
    const text = document.getElementById("chatText").value;

    if (!text.trim()) {
        displayError("chatResult", "Please enter chat message to analyze");
        return;
    }

    try {
        const res = await fetch(`${API}/analyze/chat`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ text })
        });

        const data = await res.json();

        if (!res.ok) {
            displayError("chatResult", data.message || "Chat analysis failed");
            return;
        }

        displaySuccess("chatResult", data);

    } catch (error) {
        displayError("chatResult", `Network error: ${error.message}`);
    }
}


/* -------- Ensemble Decision -------- */
async function checkEnsemble() {
    const email = document.getElementById("emailText").value;
    const url = document.getElementById("urlText").value;
    const chat = document.getElementById("chatText").value;

    if (!email.trim() && !url.trim() && !chat.trim()) {
        displayError("ensembleResult", "Please provide at least one of: email, URL, or chat text");
        return;
    }

    try {
        const res = await fetch(`${API}/analyze/ensemble`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ email, url, chat })
        });

        const data = await res.json();

        if (!res.ok) {
            displayError("ensembleResult", data.message || "Ensemble analysis failed");
            return;
        }

        displaySuccess("ensembleResult", data);

        /* Update threat level based on ensemble decision */
        if (data.final_decision && data.threat_level) {
            updateThreatLevel(data.threat_level);
            
            // Update phishing count if threat detected
            if (data.final_decision === "phishing") {
                phishingCount++;
            } else {
                legitimateCount++;
            }
            
            totalCount++;
            document.getElementById("totalScans").textContent = totalCount;
            document.getElementById("phishingCount").textContent = phishingCount;
            document.getElementById("legitimateCount").textContent = legitimateCount;
            
            threatChart.data.datasets[0].data = [phishingCount, legitimateCount];
            threatChart.update();
        }

    } catch (error) {
        displayError("ensembleResult", `Network error: ${error.message}`);
    }
}