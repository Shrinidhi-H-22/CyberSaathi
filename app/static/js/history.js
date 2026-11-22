
"use strict";


// History dashboard elements.
const historyStatus = document.getElementById("history-status");

const historyEmpty = document.getElementById("history-empty");

const historyTableWrapper = document.getElementById(
    "history-table-wrapper"
);

const historyTableBody = document.getElementById(
    "history-table-body"
);

const historyRecordCount = document.getElementById(
    "history-record-count"
);

const totalScans = document.getElementById("total-scans");

const messageScans = document.getElementById("message-scans");

const urlScans = document.getElementById("url-scans");

const highScans = document.getElementById("high-scans");

const refreshHistoryButton = document.getElementById(
    "refresh-history"
);

const clearHistoryButton = document.getElementById(
    "clear-history"
);


// Update the status message.
function setHistoryStatus(message, isError = false) {

    historyStatus.textContent = message;

    historyStatus.classList.toggle("error", isError);

}


// Format UTC timestamps using the browser's local timezone.
function formatScanDate(timestamp) {

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return "Unknown date";
    }

    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short"
    }).format(date);

}


// Create a safe table cell.
function createCell(value, className = "") {

    const cell = document.createElement("td");

    cell.textContent = String(value ?? "—");

    if (className) {
        cell.className = className;
    }

    return cell;

}


// Create a risk badge without injecting HTML.
function createRiskBadge(riskLevel) {

    const badge = document.createElement("span");

    const allowedLevels = ["High", "Medium", "Low"];

    const validLevel = allowedLevels.includes(riskLevel)
        ? riskLevel
        : "Unknown";

    badge.textContent = validLevel;

    badge.className = `history-risk history-risk-${validLevel.toLowerCase()}`;

    return badge;

}


// Create a scan type label.
function createTypeBadge(scanType) {

    const badge = document.createElement("span");

    const validType = scanType === "message"
        ? "Message"
        : scanType === "url"
            ? "URL"
            : "Unknown";

    badge.textContent = validType;

    badge.className = "history-type";

    return badge;

}


// Render one row in the history table.
function createHistoryRow(scan) {

    const row = document.createElement("tr");

    row.appendChild(
        createCell(formatScanDate(scan.created_at), "history-date-cell")
    );

    const typeCell = document.createElement("td");

    typeCell.appendChild(
        createTypeBadge(scan.scan_type)
    );

    row.appendChild(typeCell);


    const riskCell = document.createElement("td");

    riskCell.appendChild(
        createRiskBadge(scan.risk_level)
    );

    row.appendChild(riskCell);


    row.appendChild(
        createCell(scan.indicator_score)
    );

    row.appendChild(
        createCell(scan.finding_count)
    );

    row.appendChild(
        createCell(scan.link_count)
    );

    row.appendChild(
        createCell(scan.summary, "history-summary-cell")
    );


    return row;

}


// Calculate statistics and render saved scans.
function renderHistory(data) {

    const scans = Array.isArray(data.scans)
        ? data.scans
        : [];

    const messageCount = scans.filter(
        scan => scan.scan_type === "message"
    ).length;

    const urlCount = scans.filter(
        scan => scan.scan_type === "url"
    ).length;

    const highCount = scans.filter(
        scan => scan.risk_level === "High"
    ).length;


    totalScans.textContent = String(data.count);

    messageScans.textContent = String(messageCount);

    urlScans.textContent = String(urlCount);

    highScans.textContent = String(highCount);

    historyRecordCount.textContent =
        `${data.count} records`;


    historyTableBody.replaceChildren();


    if (scans.length === 0) {

        historyTableWrapper.hidden = true;

        historyEmpty.hidden = false;

        clearHistoryButton.disabled = true;

        return;

    }


    historyEmpty.hidden = true;

    historyTableWrapper.hidden = false;

    clearHistoryButton.disabled = false;


    scans.forEach(scan => {

        const row = createHistoryRow(scan);

        historyTableBody.appendChild(row);

    });

}


// Load recent history from Flask.
async function loadHistory() {

    refreshHistoryButton.disabled = true;

    setHistoryStatus("Loading your saved scan history...");

    try {

        const response = await fetch("/api/history?limit=100", {
            method: "GET",
            headers: {
                "Accept": "application/json"
            }
        });


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "Unable to load scan history."
            );

        }


        renderHistory(data);

        setHistoryStatus(
            data.count > 0
                ? "Your saved scan history is up to date."
                : "No saved scans were found."
        );


    } catch (error) {

        historyTableWrapper.hidden = true;

        historyEmpty.hidden = true;

        setHistoryStatus(
            error.message || "Unable to load scan history.",
            true
        );


    } finally {

        refreshHistoryButton.disabled = false;

    }

}


// Refresh the scan history.
refreshHistoryButton.addEventListener("click", () => {

    loadHistory();

});


// Clear saved scan history after confirmation.
clearHistoryButton.addEventListener("click", async () => {

    if (clearHistoryButton.disabled) {
        return;
    }

    const confirmed = window.confirm(
        "Are you sure you want to delete all saved scan history? " +
        "This action cannot be undone."
    );

    if (!confirmed) {
        return;
    }


    clearHistoryButton.disabled = true;

    refreshHistoryButton.disabled = true;

    setHistoryStatus("Clearing saved scan history...");


    try {

        const response = await fetch("/api/history", {

            method: "DELETE",

            headers: {
                "Accept": "application/json"
            }

        });


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "Unable to clear scan history."
            );

        }


        await loadHistory();

        setHistoryStatus(
            `${data.deleted_count} scan record(s) cleared successfully.`
        );


    } catch (error) {

        setHistoryStatus(
            error.message || "Unable to clear scan history.",
            true
        );

    } finally {

        clearHistoryButton.disabled = false;

        refreshHistoryButton.disabled = false;

    }

});


// Load the dashboard when the page opens.
loadHistory();
