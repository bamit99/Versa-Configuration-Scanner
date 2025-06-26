# Configuration Auditor

This is a web-based tool designed to audit network device configuration files for security vulnerabilities and best-practice deviations. It supports multiple platforms and provides a user-friendly interface for uploading files, tracking scan progress, and reviewing historical reports.

## Features

-   **Multi-Platform Support with Auto-Detection:** Automatically identifies the vendor/platform (Versa, Cisco IOS, Juniper Junos) of the uploaded configuration file based on its content. Manual platform selection available when auto-detection fails.
-   **Multi-Format Support:** Parses configurations from CLI (`set` commands), JSON, and XML files.
-   **Asynchronous Scanning & Session Recovery:** Long-running scans are processed in the background with real-time progress updates. The tool can recover the status of ongoing or completed scans upon returning.
-   **Extensible Rule Engine:** Audit rules are defined in external JSON files, organized by platform, making it easy to add or modify checks without changing the core application logic.
-   **Web-Based UI with Navigation:** A clean and intuitive user interface with a global navigation bar to easily switch between the main scanner page and the scan history.
-   **Scan History Dashboard:** A dedicated page to view a list of all past scans, their status, and links to their respective reports.
-   **HTML & CSV Reporting:** Generates a user-friendly HTML report with severity-based color coding and a CSV file for easy data export and analysis.
-   **Persistent Scan Records:** Scan metadata (status, filename, platform, report link) is stored in a SQLite database, ensuring history is retained across application restarts.
-   **Real-time Progress Tracking:** Live status updates during scanning with loading indicators and error handling.
-   **Debug Mode:** Optional debugging mode to troubleshoot upload and scanning issues.

## Project Structure

```
.
├── app.py              # Main Flask application file (routes, views, task management)
├── engine.py           # Contains core logic: PlatformDetector, BaseConfigParser, VersaConfigParser, RuleEngine
├── database.py         # Handles SQLite database initialization and operations for scan history
├── IMPROVEMENT_TRACKER.md # Document tracking potential future enhancements
├── rules/              # Directory for platform-specific audit rules
│   └── versa/
│       └── rules.json  # Audit rules for Versa configurations
├── requirements.txt    # Python package dependencies
├── templates/
│   ├── base.html       # Base template for consistent UI (includes navigation)
│   ├── index.html      # Main configuration upload/scanner page
│   ├── report.html     # Audit report view template
│   └── history.html    # Scan history dashboard template
├── uploads/            # Directory for storing uploaded config files (ignored by git)
│   └── .gitkeep
├── reports/            # Directory for generated HTML and CSV reports (ignored by git)
│   └── .gitkeep
└── .gitignore          # Specifies files and directories to be ignored by git
```

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/bamit99/Versa-Configuration-Scanner.git
    cd Versa-Configuration-Scanner
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # Using venv
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

    # Or using conda
    conda create --name config-auditor python=3.11
    conda activate config-auditor
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: If you are on Windows and encounter errors while installing `MarkupSafe`, you may need to install the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).*

4.  **Run the application:**
    ```bash
    python app.py
    ```
    You can also specify the host and port. To make the application accessible on your local network, use:
    ```bash
    python app.py --host 0.0.0.0 --port 8080
    ```

5.  Open your web browser and navigate to the host and port you specified (e.g., `http://127.0.0.1:5000` or `http://<your-lan-ip>:8080`).

## How to Extend

The tool is designed for easy extension, particularly for adding new platforms or audit rules.

### Adding New Audit Rules

To add a new audit rule for an **existing platform** (e.g., Versa):

1.  **Locate the Platform's Rule File:** Navigate to the `rules/` directory and find the JSON file for your target platform (e.g., `rules/versa/rules.json`).
2.  **Define the Rule:** Add a new JSON object to this file. The `check` object within the rule defines how the `RuleEngine` evaluates the configuration. You do **not** need to modify `engine.py` for new rules, as the engine is designed to interpret the `check` logic dynamically.

    Example structure:
    ```json
    {
        "id": "VOS-NEW-001",
        "name": "New Example Rule",
        "severity": "MEDIUM",
        "description": "A brief description of the new rule.",
        "details": "More detailed explanation of the vulnerability or misconfiguration.",
        "affected_config_template": "A template string showing the affected config, e.g., 'System: Feature {feature_name} is misconfigured.'",
        "check": {
            "operator": "for_each",
            "target": "system_services",
            "item_var": "service",
            "inner_check": {
                "condition": {
                    "operator": "and",
                    "conditions": [
                        { "target": "service.name", "operator": "equals", "value": "example-feature" },
                        { "target": "service.status", "operator": "equals", "value": "misconfigured" }
                    ]
                },
                "affected_params": {
                    "feature_name": "service.name"
                }
            }
        }
    }
    ```
    The `RuleEngine` supports various operators (`equals`, `contains`, `is_present`, `for_each`, `and`, `or`, etc.) to define complex checks.

### Adding Support for a New Platform

To add a new network platform (e.g., Cisco IOS, Juniper Junos):

1.  **Create a New Parser:**
    *   In `engine.py`, create a new class that inherits from `BaseConfigParser` (e.g., `CiscoIOSConfigParser`).
    *   Implement the `load_config` method to parse the new platform's configuration format into a raw data structure.
    *   Implement the `normalize_configuration` method to transform this raw data into the standardized data model used by the `RuleEngine`.
2.  **Update `PARSERS` Dictionary:**
    *   In `app.py`, add your new parser class to the `PARSERS` dictionary, mapping a platform name (e.g., `'cisco_ios'`) to your new parser class.
3.  **Create Platform-Specific Rules:**
    *   Create a new directory under `rules/` for your platform (e.g., `rules/cisco_ios/`).
    *   Inside this directory, create a `rules.json` file containing the audit rules specific to this new platform, following the structure described above.
4.  **Update UI (Optional but Recommended):**
    *   In `templates/index.html`, add an `<option>` tag to the platform selection dropdown for your new platform.
    *   (Optional) Enhance the `PlatformDetector` in `engine.py` with heuristics to auto-detect your new platform based on its unique configuration syntax.

This modular approach allows for continuous expansion of the auditor's capabilities.

## Recent Fixes and Improvements

### Version 2.0 Updates (June 2025)

**Fixed Critical Issues:**
- ✅ **Upload Button Not Working**: Fixed missing JavaScript DOM element references and template block issues
- ✅ **Flask Context Errors**: Resolved background thread template rendering issues by implementing direct HTML generation
- ✅ **Missing Progress Updates**: Added real-time scanning progress with loading indicators
- ✅ **Template Integration**: Fixed base template to properly include JavaScript from child templates

**New Features:**
- 🆕 **Debug Mode**: Added optional debugging checkbox to troubleshoot upload/scan issues
- 🆕 **Enhanced Error Handling**: Improved error messages and UI state management
- 🆕 **Better Platform Detection**: Enhanced auto-detection algorithms with scoring system
- 🆕 **Responsive UI**: Improved loading states and button feedback

## Testing

A sample test configuration file (`test_config_sample.txt`) is included to verify the application functionality. This file contains various security misconfigurations that should trigger multiple audit findings:

- Telnet service enabled (CRITICAL)
- Insecure SNMP community "public" (HIGH)
- Overly permissive security policies (MEDIUM)

To test:
1. Start the application: `python app.py`
2. Upload `test_config_sample.txt`
3. Verify the scan completes and generates a report with expected findings

## Troubleshooting

### Common Issues

**Upload button does nothing:**
- Ensure you're using the latest version with the fixed JavaScript
- Check browser console (F12) for JavaScript errors
- Enable debug mode checkbox for detailed response information

**Scan fails with Flask context errors:**
- This has been fixed in the latest version
- Ensure you're using the updated `app.py` with `generate_html_report()` function

**Platform not detected:**
- Use manual platform selection from the dropdown
- Check that your configuration file matches one of the supported formats
- Verify file extension is .txt, .json, .xml, or .cli

**Reports not generating:**
- Check that the `reports/` directory exists and is writable
- Verify sufficient disk space
- Check application logs for specific error messages

### Debug Mode

Enable the debug checkbox on the main page to see detailed information about:
- Upload responses from the server
- Scan initiation responses
- Status polling responses
- Error details and network issues

This helps identify where issues occur in the upload → scan → report pipeline.
