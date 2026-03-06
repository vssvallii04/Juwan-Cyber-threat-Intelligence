const API = "http://127.0.0.1:8000";

let phishingCount = 0;
let legitimateCount = 0;
let totalCount = 0;
let currentThreatLevel = "LOW";

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
    
    // Apply color coding
    threatLevelEl.style.color = 
        currentThreatLevel === "HIGH" ? "#d32f2f" :
        currentThreatLevel === "MEDIUM" ? "#f57c00" : 
        "#388e3c";
}
/* -------- Dashboard Chart -------- */

const ctx = document.getElementById("pieChart").getContext("2d");
const threatChart = new Chart(ctx, {
    type: "bar",
    data: {
        labels: ["Phishing", "Legitimate"],
        datasets: [{
            label: "Threat Detection",
            data: [0, 0]
        }]
    }
});


/* -------- Email Detection -------- */
async function checkEmail() {

    const text = document.getElementById("emailText").value;

    const res = await fetch(`${API}/analyze/email`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ text })
    });

    const data = await res.json();

    document.getElementById("emailResult").textContent =
        JSON.stringify(data, null, 2);

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

    /* Update Threat Level - Use ensemble decision for accuracy */
    updateThreatLevel();

    threatChart.data.datasets[0].data =
        [phishingCount, legitimateCount];

    threatChart.update();
}



/* -------- URL Detection -------- */
async function checkURL() {

    const url = document.getElementById("urlText").value;

    const res = await fetch(`${API}/analyze/url`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ url })
    });

    const data = await res.json();

    document.getElementById("urlResult").textContent =
        JSON.stringify(data, null, 2);
}



/* -------- Chat Detection -------- */

async function checkChat() {

    const text = document.getElementById("chatText").value;

    const res = await fetch(`${API}/analyze/chat`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ text })
    });

    const data = await res.json();

    document.getElementById("chatResult").textContent =
        JSON.stringify(data, null, 2);
}


/* -------- Ensemble Decision -------- */

async function checkEnsemble() {

    const email = document.getElementById("emailText").value;
    const url = document.getElementById("urlText").value;
    const chat = document.getElementById("chatText").value;

    const res = await fetch(`${API}/analyze/ensemble`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ email, url, chat })
    });

    const data = await res.json();

    document.getElementById("ensembleResult").textContent =
        JSON.stringify(data, null, 2);

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
}