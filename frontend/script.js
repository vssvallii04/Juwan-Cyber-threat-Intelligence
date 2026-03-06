async function checkURL() {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");

    if (!url) {
        resultDiv.innerHTML = "❌ Please enter a URL";
        return;
    }

    resultDiv.innerHTML = "⏳ Checking...";

    try {
        const response = await fetch("http://127.0.0.1:8000/analyze/url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        resultDiv.innerHTML = `
            <p><b>Prediction:</b> ${data.prediction}</p>
            <p><b>Confidence:</b> ${data.confidence}</p>
            <p><b>Top Signals:</b> ${data.top_signals?.join(", ")}</p>
        `;
    } catch (error) {
        resultDiv.innerHTML = "❌ Server error";
    }
}
