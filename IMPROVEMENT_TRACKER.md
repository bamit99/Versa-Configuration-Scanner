# Versa Configuration Auditor - Improvement Tracker

This document tracks potential architectural, performance, and feature enhancements for the tool.

---

### 🚀 Architecture & Scalability

1.  **Replace In-Memory Task Store with a Persistent Queue**
    *   **Problem:** The current `tasks = {}` dictionary is volatile. If the Flask application restarts for any reason, all information about ongoing or completed scans is lost.
    *   **Suggestion:** Integrate a more robust task queue system like **Celery** with a message broker like **Redis** or **RabbitMQ**. This would make the scanning process persistent and resilient to application restarts.
    *   **Status:** `Not Started`

2.  **Use a Database for Storing Findings and Reports**
    *   **Problem:** Reports are saved as individual HTML and CSV files. This makes historical analysis, searching, and data aggregation difficult.
    *   **Suggestion:** Use a database (e.g., **SQLite** for simplicity, or **PostgreSQL** for scalability) to store scan metadata and individual findings. Reports could then be rendered dynamically from this data. This would also enable a historical dashboard feature.
    *   **Status:** `In Progress`

### ⚡️ Performance

1.  **Optimize Large File Parsing**
    *   **Problem:** The current `parse_cli_config` function processes the configuration file line by line, which could be a bottleneck for extremely large files (e.g., >50MB).
    *   **Suggestion:** Investigate and benchmark more performant parsing strategies if this becomes a noticeable issue.
    *   **Status:** `Not Started`

### ✨ User Experience (UX)

1.  **Implement Granular, Real-time Progress Updates**
    *   **Problem:** The frontend only shows a generic "running" status. The user has no insight into what's happening.
    *   **Suggestion:** The backend worker should update the task status with more detail (e.g., "Parsing Configuration", "Normalizing Data", "Evaluating Rule 15/45..."). The frontend can then display a more informative progress bar or status message.
    *   **Status:** `Not Started`

2.  **Create a Historical Scan Dashboard**
    *   **Problem:** There is no way to view past scans.
    *   **Suggestion:** If a database is implemented (see Architecture #2), create a `/history` page that lists all previous scans, their status, a summary of findings, and a link to the full report.
    *   **Status:** `In Progress`

4.  **Implement Global Navigation (Home/Scanner & History Buttons)**
    *   **Problem:** Navigating between the scanner and history pages is not intuitive, and there's no clear "home" button from reports.
    *   **Suggestion:** Add a persistent navigation bar to all pages (`base.html`) with links to the main scanner page and the new history page.
    *   **Status:** `In Progress`

3.  **Add Interactive Filtering to Reports**
    *   **Problem:** The HTML report is static.
    *   **Suggestion:** Add JavaScript to the `report.html` template to allow users to filter findings by severity or search by rule ID or description directly in the browser.
    *   **Status:** `Not Started`

### 🛠️ Maintainability & Code Quality

1.  **Add Automated Tests**
    *   **Problem:** The project currently has no unit or integration tests, making it risky to refactor or add new features.
    *   **Suggestion:** Create a `/tests` directory and add tests using a framework like **pytest**. We should test the config parser, the rule engine, and the API endpoints.
    *   **Status:** `Not Started`

2.  **Externalize Configuration**
    *   **Problem:** Configuration variables like folder paths are hard-coded in `app.py`.
    *   **Suggestion:** Move configuration into a separate `config.py` file or use environment variables to follow best practices (e.g., The 12-Factor App).
    *   **Status:** `Not Started`

### 🔒 Security

1.  **Implement Dependency Vulnerability Scanning**
    *   **Problem:** The project's dependencies could have known vulnerabilities.
    *   **Suggestion:** Integrate a tool like `pip-audit` into a CI/CD pipeline or a local pre-commit hook to automatically check `requirements.txt` for security issues.
    *   **Status:** `Not Started`
