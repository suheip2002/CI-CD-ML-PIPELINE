// Function to display results in a specific HTML element
function displayResult(elementId, content) {
    document.getElementById(elementId).innerHTML = content;
}

// Function to display errors
function displayError(elementId, error) {
    document.getElementById(elementId).innerHTML = `<p style="color: red;">Error: ${error}</p>`;
}

// Function to get severity class for styling
function getSeverityClass(severity) {
    switch (severity) {
        case "Critical": return "severity-critical";
        case "High": return "severity-high";
        case "Medium": return "severity-medium";
        case "Low": return "severity-low";
        default: return "";
    }
}

// Function to assess vulnerability manually
async function assessVulnerability() {
    const description = document.getElementById("description").value;
    const cwe_ids = document.getElementById("cwe_ids").value;
    const resultElementId = "assessment-result";

    if (!description && !cwe_ids) {
        displayError(resultElementId, "Please provide at least a description or CWE IDs.");
        return;
    }

    try {
        const response = await fetch("/api/vulnerability/assess", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ description, cwe_ids }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Failed to assess vulnerability");
        }

        const data = await response.json();
        const resultContent = `
            <h3>Assessment Result</h3>
            <p><strong>Description:</strong> ${data.description}</p>
            <p><strong>CWE IDs:</strong> ${data.cwe_ids}</p>
            <p><strong>Predicted Severity:</strong> <span class="${getSeverityClass(data.severity)}">${data.severity}</span></p>
            <h4>Recommendations:</h4>
            <ul>
                ${data.recommendations.map(rec => `<li>${rec}</li>`).join("")}
            </ul>
        `;
        displayResult(resultElementId, resultContent);
    } catch (error) {
        displayError(resultElementId, error);
    }
}

// Function to load sample vulnerabilities
async function loadSampleVulnerabilities() {
    const resultElementId = "sample-vulnerabilities-result";
    document.getElementById("sample-btn").disabled = true; // Disable button during fetch

    try {
        const response = await fetch("/api/vulnerability/sample");
        if (!response.ok) {
            throw new Error("Failed to load sample vulnerabilities");
        }
        const data = await response.json();

        let resultContent =
            `<div class="result"><h3>Sample Vulnerability Assessments</h3>`;

        data.forEach((item, index) => {
            resultContent += `
                <div class="cli-assessment-item"> <!-- Removed inline styles, added class -->
                    <h4>Vulnerability ${index + 1}</h4>
                    <p><strong>Description:</strong> ${item.description}</p>
                    <p><strong>CWE IDs:</strong> ${item.cwe_ids}</p>
                    <p><strong>Predicted Severity:</strong> <span class="${getSeverityClass(item.severity)}">${item.severity}</span></p>
                </div>
            `;
        });

        resultContent += `</div>`;
        displayResult(resultElementId, resultContent);

        // Update statistics
        updateStatistics(data);

    } catch (error) {
        displayError(resultElementId, error);
    } finally {
        document.getElementById("sample-btn").disabled = false;
    }
}

// Function to refresh CLI results
async function refreshCliResults() {
    const resultElementId = "cli-results";
    try {
        const response = await fetch("/api/vulnerability/cli-results");
        if (!response.ok) {
            throw new Error("Failed to load CLI results");
        }
        const data = await response.json();

        let resultContent =
            `<div class="result"><h3>CLI Assessment Results</h3>`;

        if (data.results && data.results.length > 0) {
            data.results.forEach((item, index) => {
                resultContent += `
                    <div class="cli-assessment-item"> <!-- Removed inline styles, added class -->
                        <h4>CLI Assessment ${index + 1}</h4>
                        <p><strong>Timestamp:</strong> ${new Date(item.timestamp).toLocaleString()}</p>
                        <p><strong>Description:</strong> ${item.description}</p>
                        <p><strong>CWE IDs:</strong> ${item.cwe_ids}</p>
                        <p><strong>Predicted Severity:</strong> <span class="${getSeverityClass(item.severity)}">${item.severity}</span></p>
                    </div>
                `;
            });
        } else {
            resultContent += `<p>Waiting for CLI assessments...</p>`;
        }

        resultContent += `</div>`;
        displayResult(resultElementId, resultContent);

    } catch (error) {
        displayError(resultElementId, error);
    }
}

// Update statistics display
function updateStatistics(data) {
    const stats = {
        total: data.length,
        critical: data.filter(item => item.severity === "Critical").length,
        high: data.filter(item => item.severity === "High").length,
        medium: data.filter(item => item.severity === "Medium").length,
        low: data.filter(item => item.severity === "Low").length
    };

    const statsContent = `
        <div class="stat-card">
            <div class="stat-box">
                <div class="stat-number">${stats.total}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #e74c3c;">${stats.critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #e67e33;">${stats.high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #f39c12;">${stats.medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #27ae60;">${stats.low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
    `;

    document.getElementById("stats-grid").innerHTML = statsContent;
}

// Auto-refresh CLI results every 10 seconds
setInterval(refreshCliResults, 10000);

// Initialize the dashboard
document.addEventListener("DOMContentLoaded", function() {
    console.log("Vulnerability Assessment Dashboard loaded.");
    // Load initial CLI results
    refreshCliResults();
});
