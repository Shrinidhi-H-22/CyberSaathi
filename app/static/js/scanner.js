
"use strict";

// =========================================
// MESSAGE SCANNER ELEMENTS
// =========================================

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


// =========================================
// MESSAGE CHARACTER COUNTER
// =========================================

messageInput.addEventListener("input", () => {
    characterCount.textContent =
        `${messageInput.value.length} / 5000 characters`;
});


// =========================================
// MESSAGE STATUS
// =========================================

function updateStatus(message, isError = false) {
    scanStatus.textContent = message;
    scanStatus.classList.toggle("error", isError);
}


// =========================================
// DISPLAY MESSAGE ANALYSIS RESULTS
// =========================================

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

    resultTitle.focus?.();

    scanResult.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}


// =========================================
// MESSAGE SCANNER SUBMISSION
// =========================================

scanForm.addEventListener("submit", async (event) => {

    event.preventDefault();

    const message = messageInput.value.trim();

    if (!message) {

        scanResult.hidden = true;

        updateStatus("Please enter a message before analysing.", true);

        messageInput.focus();

        return;
    }

    if (message.length > 5000) {

        scanResult.hidden = true;

        updateStatus("The message must not exceed 5000 characters.", true);

        return;
    }

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

        analyzeButton.disabled = false;

        buttonText.textContent = "Analyse message";

        loadingSpinner.hidden = true;
    }
});


// =========================================
// URL SCANNER ELEMENTS
// =========================================

const urlScanForm = document.getElementById("url-scan-form");
const urlInput = document.getElementById("url-input");
const urlAnalyzeButton = document.getElementById("url-analyze-button");
const urlButtonText = document.querySelector(".url-button-text");
const urlLoadingSpinner = document.getElementById("url-loading-spinner");
const urlCharacterCount = document.getElementById("url-character-count");
const urlScanStatus = document.getElementById("url-scan-status");

const urlScanResult = document.getElementById("url-scan-result");
const urlResultTitle = document.getElementById("url-result-title");
const urlRiskBadge = document.getElementById("url-risk-badge");
const urlResultHostname = document.getElementById("url-result-hostname");
const urlIndicatorScore = document.getElementById("url-indicator-score");
const urlResultSummary = document.getElementById("url-result-summary");
const urlFindingsList = document.getElementById("url-findings-list");
const urlResultDisclaimer = document.getElementById("url-result-disclaimer");

// URLhaus result elements
const urlhausResult = document.getElementById("urlhaus-result");
const urlhausStatus = document.getElementById("urlhaus-status");
const urlhausDescription = document.getElementById("urlhaus-description");


// =========================================
// URL CHARACTER COUNTER
// =========================================

urlInput.addEventListener("input", () => {

    urlCharacterCount.textContent =
        `${urlInput.value.length} / 2048 characters`;

});


// =========================================
// URL SCANNER STATUS
// =========================================

function updateUrlStatus(message, isError = false) {

    urlScanStatus.textContent = message;

    urlScanStatus.classList.toggle("error", isError);

}


// =========================================
// DISPLAY URLHAUS RESULTS
// =========================================

function displayUrlhausResults(data) {

    urlhausResult.hidden = false;

    // Handle missing or invalid URLhaus responses.
    if (!data || typeof data !== "object") {

        urlhausStatus.textContent = "Unavailable";

        urlhausStatus.className =
            "urlhaus-status urlhaus-unavailable";

        urlhausDescription.textContent =
            "The URLhaus lookup could not be completed. " +
            "Only the structural URL analysis is available.";

        return;
    }

    if (data.status === "found") {

        urlhausStatus.textContent = "Threat listed";

        urlhausStatus.className =
            "urlhaus-status urlhaus-found";

        let description =
            "This URL is listed in URLhaus as a known " +
            "malware-related threat. Avoid visiting it.";

        if (
            typeof data.threat === "string" &&
            data.threat.trim()
        ) {
            description += ` Threat category: ${data.threat}.`;
        }

        urlhausDescription.textContent = description;

    } else if (data.status === "not_found") {

        urlhausStatus.textContent = "Not listed";

        urlhausStatus.className =
            "urlhaus-status urlhaus-not-found";

        urlhausDescription.textContent =
            "URLhaus did not find this URL in its database. " +
            "This does not guarantee that the URL is safe.";

    } else {

        urlhausStatus.textContent = "Unavailable";

        urlhausStatus.className =
            "urlhaus-status urlhaus-unavailable";

        urlhausDescription.textContent =
            "The URLhaus lookup could not be completed. " +
            "Only the structural URL analysis is available.";

    }
}


// =========================================
// DISPLAY URL ANALYSIS RESULTS
// =========================================

function displayUrlResults(data) {

    const allowedRiskLevels = ["High", "Medium", "Low"];

    if (!allowedRiskLevels.includes(data.risk_level)) {

        throw new Error("The server returned an unknown risk level.");

    }

    if (!Array.isArray(data.findings)) {

        throw new Error("The server returned invalid URL findings.");

    }

    if (typeof data.hostname !== "string") {

        throw new Error("The server returned an invalid hostname.");

    }

    urlResultTitle.textContent = "URL analysis complete";

    urlRiskBadge.textContent =
        `${data.risk_level} risk indicators`;

    urlRiskBadge.className =
        `risk-badge risk-${data.risk_level.toLowerCase()}`;

    urlResultHostname.textContent = data.hostname;

    urlIndicatorScore.textContent =
        String(data.indicator_score);

    urlResultSummary.textContent = data.summary;

    urlResultDisclaimer.textContent = data.disclaimer;

    // Display URLhaus threat-intelligence results.
    displayUrlhausResults(data.urlhaus);

    // Remove previous URL findings.
    urlFindingsList.replaceChildren();

    if (data.findings.length === 0) {

        const emptyMessage = document.createElement("li");

        emptyMessage.className = "no-findings";

        emptyMessage.textContent =
            "No configured URL warning patterns were detected. " +
            "This does not prove that the website is safe.";

        urlFindingsList.appendChild(emptyMessage);

    } else {

        data.findings.forEach((finding) => {

            const item = document.createElement("li");

            item.className = "finding-item";

            const title = document.createElement("strong");

            title.textContent =
                finding.label || "URL warning indicator";

            const description = document.createElement("p");

            description.textContent =
                finding.description ||
                "No additional explanation available.";

            item.appendChild(title);

            item.appendChild(description);

            urlFindingsList.appendChild(item);

        });

    }

    urlScanResult.hidden = false;

    urlScanResult.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });

}


// =========================================
// URL SCANNER SUBMISSION
// =========================================

urlScanForm.addEventListener("submit", async (event) => {

    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {

        urlScanResult.hidden = true;

        updateUrlStatus(
            "Please enter a website address.",
            true
        );

        urlInput.focus();

        return;

    }

    if (url.length > 2048) {

        urlScanResult.hidden = true;

        updateUrlStatus(
            "The URL cannot exceed 2048 characters.",
            true
        );

        return;

    }

    urlAnalyzeButton.disabled = true;

    urlButtonText.textContent = "Analysing URL...";

    urlLoadingSpinner.hidden = false;

    urlScanResult.hidden = true;

    updateUrlStatus(
        "Checking URL structure and external threat intelligence..."
    );

    try {

        const response = await fetch("/api/analyze-url", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.error || "The URL could not be analysed."
            );

        }

        displayUrlResults(data);

        updateUrlStatus(
            "URL analysis completed. Review both checks carefully."
        );

    } catch (error) {

        urlScanResult.hidden = true;

        updateUrlStatus(
            error.message || "Unable to connect to CyberSaathi.",
            true
        );

    } finally {

        urlAnalyzeButton.disabled = false;

        urlButtonText.textContent = "Analyse URL";

        urlLoadingSpinner.hidden = true;

    }

});
