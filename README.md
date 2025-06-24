# Versa Configuration Auditor

This is a web-based tool to audit Versa Networks configuration files for security vulnerabilities and best-practice deviations. You can upload configuration files in various formats (CLI, JSON, XML), and the tool will generate a report with its findings.

## Features

- **Multi-Format Support:** Parses configurations from CLI (`set` commands), JSON, and XML files.
- **Extensible Rule Engine:** Audit rules are defined in an external `rules.json` file, making it easy to add or modify checks without changing the core application logic.
- **Web-Based UI:** A simple and clean user interface for uploading files and viewing reports.
- **HTML & CSV Reporting:** Generates a user-friendly HTML report and a CSV file for easy data export and analysis.
- **Persistent CSV Reports:** Findings are appended to a CSV file, creating a historical log of all scans.

## Project Structure

```
.
├── app.py              # Main Flask application file (routes, views, config parsing)
├── engine.py           # Contains the core RuleEngine for evaluating configs
├── rules.json          # Extensible list of audit rules
├── requirements.txt    # Python package dependencies
├── templates/
│   ├── index.html      # Main upload page
│   └── report.html     # Report view template
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
    conda create --name versa-auditor python=3.11
    conda activate versa-auditor
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

Adding a new audit rule is a two-step process:

1.  **Define the Rule in `rules.json`:**
    Add a new JSON object to the `rules.json` file with the following structure:
    ```json
    {
        "id": "VOS-CAT-00X",
        "severity": "MEDIUM",
        "description": "A brief description of the rule.",
        "details": "More detailed explanation of the vulnerability or misconfiguration and why it's a problem.",
        "affected_config_template": "A template string showing the part of the config that is affected, e.g., 'System > Services > {service_name}'"
    }
    ```

2.  **Implement the Logic in `engine.py`:**
    In the `RuleEngine.evaluate` method, add the Python code to check the `normalized_config` data for the condition defined in your new rule. If the condition is met, call `self._add_finding()` with the rule's ID.

    ```python
    # In engine.py inside the evaluate method

    # RULE_ID: VOS-CAT-00X
    if 'VOS-CAT-00X' in self.rules:
        # Your logic here to check the normalized_config
        if (condition_is_met):
            self._add_finding('VOS-CAT-00X', affected_config_params={'param': 'value'})
    ```

This modular approach allows for easy expansion of the auditor's capabilities.
