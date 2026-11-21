
"use strict";

// Find the scanner elements on the page.
const scanForm = document.getElementById("message-scan-form");
const messageInput = document.getElementById("message-input");
const analyzeButton = document.getElementById("analyze-button");
const buttonText = analyzeButton.querySelector(".button-text");
const loadingSpinner = document.getElementById("loading-spinner");
const characterCount = document.getElementById("character-count");
const scanStatus = document.getElementById("scan-status");

const scanResult = document.getElementById("scan-result");
const resultTitle = document.getElementById("result-title");
const riskBadge = document.getElementById("risk-badge");
const indicatorScore = document.getElementById("indicator-score");
const resultSummary = document.getElementById("result-summary");
const findingsList = document.getElementById("findings-list");
const resultDisclaimer = document.getElementById("result-disclaimer");


// Update the character counter.
messageInput.addEventListener("input", () => {
    characterCount.textContent =
        `${messageInput.value.length} / 5000 characters`;
});


// Display an error or information message.
function updateStatus(message, isError = false) {
    scanStatus.textContent = message;
    scanStatus.classList.toggle("error", isError);
}


// Display analysis results safely.
function displayResults(data) {

    const allowedRiskLevels = ["High", "Medium", "Low"];

    if (!allowedRiskLevels.includes(data.risk_level)) {
        throw new Error("The server returned an unknown risk level.");
    }

    if (!Array.isArray(data.findings)) {
        throw new Error("The server returned invalid analysis findings.");
    }

    resultTitle.textContent = "Analysis complete";

    riskBadge.textContent = `${data.risk_level} risk indicators`;

    riskBadge.className =
        `risk-badge risk-${data.risk_level.toLowerCase()}`;

    indicatorScore.textContent = String(data.indicator_score);

    resultSummary.textContent = data.summary;

    resultDisclaimer.textContent = data.disclaimer;

    // Clear previous results.
    findingsList.replaceChildren();

    if (data.findings.length === 0) {

        const emptyMessage = document.createElement("li");

        emptyMessage.className = "no-findings";

        emptyMessage.textContent =
            "No configured warning patterns were detected. " +
            "This does not establish that the message is safe.";

        findingsList.appendChild(emptyMessage);

    } else {

        data.findings.forEach((finding) => {

            const item = document.createElement("li");

            item.className = "finding-item";

            const title = document.createElement("strong");

            title.textContent = finding.label || "Warning indicator";

            const description = document.createElement("p");

            description.textContent =
                finding.description || "No additional explanation available.";

            item.appendChild(title);
            item.appendChild(description);

            findingsList.appendChild(item);
        });
    }

    scanResult.hidden = false;

    // Bring the results into view for keyboard and screen-reader users.
    resultTitle.focus?.();

    scanResult.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


// Send the message to the Flask API.
scanForm.addEventListener("submit", async (event) => {

    event.preventDefault();

    const message = messageInput.value.trim();

    // Check for empty input.
    if (!message) {

        scanResult.hidden = true;

        updateStatus("Please enter a message before analysing.", true);

        messageInput.focus();

        return;
    }

    // Check the maximum message length.
    if (message.length > 5000) {

        scanResult.hidden = true;

        updateStatus("The message must not exceed 5000 characters.", true);

        return;
    }

    // Prepare the loading state.
    analyzeButton.disabled = true;

    buttonText.textContent = "Analysing...";

    loadingSpinner.hidden = false;

    scanResult.hidden = true;

    updateStatus("Checking the message for configured warning signs...");

    try {

        const response = await fetch("/api/analyze-message", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                message: message
            })
        });

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.error || "The message could not be analysed."
            );
        }

        displayResults(data);

        updateStatus("Analysis completed. Review the findings carefully.");

    } catch (error) {

        scanResult.hidden = true;

        updateStatus(
            error.message || "Unable to connect to CyberSaathi.",
            true
        );

    } finally {

        // Restore the button.
        analyzeButton.disabled = false;

        buttonText.textContent = "Analyse message";

        loadingSpinner.hidden = true;
    }
});
