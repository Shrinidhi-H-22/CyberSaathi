# CyberSaathi

### Pause. Check. Stay safe.

CyberSaathi is a web-based cybersecurity awareness and digital safety platform designed to help users identify potentially suspicious messages, phishing URLs, and online threats through explainable analysis.

The project combines rule-based message analysis, URL structure inspection, and URLhaus threat intelligence to provide understandable security insights.

## Features

- **Message Scanner:** Analyses messages for suspicious language and potential scam indicators.
- **URL Scanner:** Examines URL structures for potentially suspicious characteristics.
- **Combined Analysis:** Identifies URLs within messages and analyses them alongside message content.
- **URLhaus Integration:** Checks URLs against URLhaus threat-intelligence data when API access is configured.
- **Scan History:** Maintains a history of scan results using SQLite.
- **Privacy-conscious History:** Stores scan metadata rather than original message contents or complete URLs.
- **Responsive Interface:** Provides a clean, accessible interface for desktop and mobile users.

## Technology Stack

- Python
- Flask
- HTML
- CSS
- JavaScript
- SQLite
- pytest
- URLhaus API

## Project Structure

```text
CyberSaathi/
├── app/
│   ├── routes/
│   ├── services/
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
├── instance/
├── tests/
├── .env
├── .gitignore
├── requirements.txt
├── run.py
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Shrinidhi-H-22/CyberSaathi.git
cd CyberSaathi
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure URLhaus (optional)

To enable URLhaus threat-intelligence lookups, create a `.env` file in the project root and add your own API authentication key:

```env
URLHAUS_AUTH_KEY=your_api_key_here
```

Do not share or commit your `.env` file or API key.

### 6. Run the application

```bash
python run.py
```

### 7. Open CyberSaathi

Visit:

```text
http://127.0.0.1:5000
```

## Running Tests

Run the complete automated test suite using:

```bash
python -m pytest -q
```

The project has reached **80 passing automated tests** at the latest verified checkpoint.

## Important Security Limitations

CyberSaathi provides preliminary security indicators, not a guarantee that a message or URL is safe or malicious.

- URL structural analysis does not visit the website.
- It does not independently verify website ownership, DNS records, certificates, redirects, or page contents.
- URLhaus checks are dependent on external API availability and configuration.
- A URL not found in URLhaus is not necessarily safe.
- URLhaus is a malware-distribution threat-intelligence source, not a universal phishing detector.

Use caution when sharing private URLs, authentication tokens, or sensitive information with external services.

## Project Goal

To make digital safety easier to understand through accessible, explainable cybersecurity analysis and practical awareness.

## Developer

**Designed & Developed by Shrinidhi**
