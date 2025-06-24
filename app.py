import os
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
import json
import xml.etree.ElementTree as ET
import shlex
import re
from functools import wraps
import csv
import datetime
from engine import RuleEngine, load_rules

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'json', 'xml', 'cli'} # Add more if needed
CONFIG_DIR = 'configs' # Directory to store parsed configs
REPORTS_DIR = 'reports' # Directory for generated reports

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024 # Max upload size 64MB
app.secret_key = os.urandom(24) # Needed for flashing messages

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Versa Configuration Parsing Logic (from previous example, adapted) ---
class VersaConfigParser:
    def __init__(self):
        self.raw_config_data = None
        self.normalized_config_data = None
        self.config_format = None

    def load_config(self, filepath):
        """Loads configuration data from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                if content.strip().startswith('{') or content.strip().startswith('['):
                    try:
                        self.raw_config_data = json.loads(content)
                        self.config_format = 'json'
                        app.logger.info(f"Successfully loaded JSON configuration from {filepath}")
                    except json.JSONDecodeError:
                        try:
                            self.raw_config_data = ET.fromstring(content)
                            self.config_format = 'xml'
                            app.logger.info(f"Successfully loaded XML configuration from {filepath}")
                        except ET.ParseError:
                            app.logger.error(f"Error: File {filepath} is not valid JSON or XML.")
                            self.raw_config_data = None
                # More robust check for CLI format, allowing for headers
                elif '\nset ' in content or content.strip().startswith('set '):
                    self.raw_config_data = self.parse_cli_config(content)
                    self.config_format = 'cli'
                    app.logger.info(f"Successfully loaded and parsed CLI configuration from {filepath}")
                else:
                    app.logger.error(f"Error: Unknown configuration format in {filepath}. Expected JSON, XML, or Versa CLI 'set' format.")
                    self.raw_config_data = None
            return self.raw_config_data
        except FileNotFoundError:
            app.logger.error(f"Error: File not found at {filepath}")
            self.raw_config_data = None
            return None
        except UnicodeDecodeError:
            app.logger.error(f"Encoding error: Could not decode file {filepath} with UTF-8.")
            # Optionally, try another encoding like 'latin-1' as a fallback
            try:
                with open(filepath, 'r', encoding='latin-1') as f:
                    app.logger.warning(f"Attempting to read {filepath} with 'latin-1' encoding.")
                    content = f.read()
                    # ... (rest of the parsing logic would need to be duplicated or refactored)
                    # For now, just return None to indicate failure
                self.raw_config_data = None
                return None
            except Exception as e:
                app.logger.error(f"Failed to read file with fallback encoding: {e}")
                self.raw_config_data = None
                return None
        except Exception as e:
            app.logger.error(f"Error loading configuration from file: {e}")
            self.raw_config_data = None
            return None

    def parse_cli_config(self, cli_output):
        """
        Parses Versa CLI configuration output (set commands) into a structured dictionary.
        Handles value assignments to keys that are also parent nodes for other keys.
        """
        config_dict = {}
        for line in cli_output.strip().split('\n'):
            line = line.strip()
            if not line.startswith('set '):
                continue

            try:
                parts = shlex.split(line)[1:]
            except ValueError:
                app.logger.warning(f"Skipping malformed CLI line: {line}")
                continue

            if not parts:
                continue

            current_level = config_dict
            for i, part in enumerate(parts):
                # If we are at the last part, it's a value or a presence flag
                if i == len(parts) - 1:
                    # It's a presence flag, e.g., 'set system services ssh'
                    if isinstance(current_level, dict):
                         current_level[part] = {'__present__': True}
                    break

                next_part = parts[i+1]
                # If the next part is the last part, then the current part is the key and the next is the value
                if i + 1 == len(parts) - 1:
                    if part not in current_level:
                        current_level[part] = next_part
                    # If the key already exists, convert it to a list of values
                    elif isinstance(current_level[part], list):
                        current_level[part].append(next_part)
                    else: # It exists and is not a list
                        # If it's a dictionary, add the value as a special key
                        if isinstance(current_level[part], dict):
                            current_level[part]['__value__'] = next_part
                        else: # It's a single value, convert to list
                            current_level[part] = [current_level[part], next_part]
                    break # Done with this line
                
                # Navigate deeper into the dictionary
                if part not in current_level:
                    current_level[part] = {}
                
                # If we encounter a string where a dict should be, we need to convert it
                if isinstance(current_level[part], str):
                    # Convert the existing string value into a dict with a special __value__ key
                    current_level[part] = {'__value__': current_level[part]}

                current_level = current_level[part]
                if not isinstance(current_level, dict):
                    app.logger.warning(f"Configuration conflict in line: '{line}'. Path is obstructed.")
                    break # Cannot go deeper

        return config_dict


    def normalize_configuration(self):
        """
        Normalizes the loaded configuration into a unified internal data model.
        This is a placeholder and requires detailed knowledge of Versa's data.
        """
        if not self.raw_config_data:
            app.logger.warning("No raw configuration data loaded to normalize.")
            return None

        normalized_data = {
            "device_templates": [],
            "sdwan_policies": [],
            "security_policies": [],
            "interface_configs": [],
            "routing_configs": [],
            "system_services": [],
            "user_auth_profiles": [],
            "raw_cli_structure": None # Store the parsed CLI dict if applicable
        }

        if self.config_format == 'cli':
            normalized_data['raw_cli_structure'] = self.raw_config_data
            # --- Mapping CLI output to normalized structure ---
            # This is highly speculative and depends on Versa's actual CLI structure

            # --- Mapping CLI output to normalized structure ---
            cli_config = self.raw_config_data

            # Map system services
            if cli_config.get('system', {}).get('services'):
                services = cli_config['system']['services']
                if services.get('telnet') and services['telnet'].get('__present__'):
                    normalized_data['system_services'].append({'name': 'telnet', 'enabled': True})
                if services.get('web-management'):
                    web_config = services['web-management']
                    normalized_data['system_services'].append({
                        'name': 'web-management',
                        'http_enabled': 'http' in web_config,
                        'https_port': web_config.get('https', {}).get('port')
                    })
                if services.get('ntp', {}).get('server'):
                     normalized_data['system_services'].append({'name': 'ntp', 'configured': True})
                if services.get('snmp', {}).get('community'):
                    communities = services['snmp']['community']
                    normalized_data['system_services'].append({
                        'name': 'snmp',
                        'communities': list(communities.keys())
                    })
            
            # Map system login settings
            if cli_config.get('system', {}).get('login', {}).get('password', {}).get('complexity'):
                normalized_data['system_services'].append({'name': 'password-complexity', 'enabled': True})

            # Map security policies
            if cli_config.get('security', {}).get('policy'):
                policies = cli_config['security']['policy']
                for policy_name, policy_details in policies.items():
                    if not isinstance(policy_details, dict): continue
                    rule_list = []
                    if 'rule' in policy_details:
                        for rule_id, rule_data in policy_details['rule'].items():
                            if not isinstance(rule_data, dict): continue
                            rule_list.append({
                                'id': rule_id,
                                'source': rule_data.get('source', 'any'),
                                'destination': rule_data.get('destination', 'any'),
                                'service': rule_data.get('service', 'any'),
                                'action': rule_data.get('then', {}).get('action', 'permit'),
                                'log': 'log' in rule_data.get('then', {})
                            })
                    normalized_data['security_policies'].append({'name': policy_name, 'rules': rule_list})


        elif self.config_format == 'xml':
            # Logic to parse and normalize XML would go here.
            # This would involve iterating through the XML tree (self.raw_config_data)
            # and mapping elements and attributes to the normalized_data structure.
            # For example:
            # for policy_elem in self.raw_config_data.findall('./security/policy'):
            #     policy_name = policy_elem.get('name')
            #     rules = []
            #     for rule_elem in policy_elem.findall('./rule'):
            #         rules.append(...)
            #     normalized_data['security_policies'].append({'name': policy_name, 'rules': rules})
            app.logger.warning("XML normalization is not yet fully implemented.")
            pass
        elif self.config_format == 'json':
            # Handle JSON normalization
            json_data = self.raw_config_data
            # Case 1: JSON is a dictionary with top-level keys (e.g., "security_policies")
            if isinstance(json_data, dict):
                if "security_policies" in json_data:
                    normalized_data["security_policies"].extend(json_data["security_policies"])
                if "system_services" in json_data:
                    normalized_data["system_services"].extend(json_data["system_services"])
                # ... and so on for other keys
            # Case 2: JSON is a list of configuration items
            elif isinstance(json_data, list):
                for item in json_data:
                    # Assuming each item has a 'type' field to distinguish it
                    item_type = item.get("type")
                    if item_type == "security_policy":
                        normalized_data["security_policies"].append(item)
                    elif item_type == "system_service":
                        normalized_data["system_services"].append(item)
                    # ... and so on for other types

        self.normalized_config_data = normalized_data
        app.logger.info("Configuration normalization process completed.")
        return self.normalized_config_data


# --- Flask Routes ---
@app.route('/')
def index():
    """Home page with file upload form."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file upload and initiates parsing and auditing."""
    if 'file' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected for uploading.', 'warning')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Process the uploaded file
        parser = VersaConfigParser()
        parsed_data = parser.load_config(filepath)

        if not parsed_data:
            flash(f"Could not parse the configuration file '{filename}'. Please ensure it is a valid and supported format (JSON, XML, or Versa CLI).", 'error')
            return redirect(url_for('index'))

        normalized_config = parser.normalize_configuration()

        # Load rules and perform audit
        rules = load_rules()
        rule_engine = RuleEngine(rules)
        findings = rule_engine.evaluate(normalized_config)

        # Save findings for reporting (e.g., in session or a temporary file)
        # For simplicity, we'll pass them to the report template directly.
        # In a real app, you might save to a database or session.
        report_filename = f"audit_report_{filename}.html"
        report_filepath = os.path.join(REPORTS_DIR, report_filename)

        # Generate HTML and CSV reports
        csv_report_name = write_findings_to_csv(findings, filename, report_filepath)
        try:
            with open(report_filepath, 'w', encoding='utf-8') as rf:
                rf.write(render_template('report.html',
                                          filename=filename,
                                          findings=findings,
                                          severity_counts=get_severity_counts(findings),
                                          total_findings=len(findings),
                                          total_rules=len(rules),
                                          csv_report_name=csv_report_name))
        except Exception as e:
            app.logger.error(f"Error generating report: {e}")
            return "Error generating report.", 500

        # Redirect to view the report
        return redirect(url_for('view_report', report_name=report_filename))

    else:
        flash('Invalid file type. Please upload .txt, .json, .xml, or .cli files.', 'error')
        return redirect(url_for('index'))

@app.route('/reports/<report_name>')
def view_report(report_name):
    """Displays a generated audit report."""
    return send_from_directory(REPORTS_DIR, report_name)

def get_severity_counts(findings):
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        severity = finding.get('severity', 'LOW').upper()
        if severity in counts:
            counts[severity] += 1
    return counts

def write_findings_to_csv(findings, original_filename, report_filepath):
    """Appends audit findings to a CSV file."""
    csv_filepath = os.path.splitext(report_filepath)[0] + '.csv'
    file_exists = os.path.isfile(csv_filepath)
    
    with open(csv_filepath, 'a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Timestamp', 'Scanned Filename', 'Rule ID', 'Severity', 'Description', 'Details', 'Affected Configuration']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()
        
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        for finding in findings:
            writer.writerow({
                'Timestamp': timestamp,
                'Scanned Filename': original_filename,
                'Rule ID': finding.get('rule_id'),
                'Severity': finding.get('severity'),
                'Description': finding.get('description'),
                'Details': finding.get('details'),
                'Affected Configuration': finding.get('affected_config')
            })
    app.logger.info(f"Appended {len(findings)} findings to {csv_filepath}")
    return os.path.basename(csv_filepath)


# --- Helper for Jinja2 to access current time ---
app.jinja_env.globals['now'] = datetime.datetime.utcnow

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Versa Configuration Auditor")
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to bind to (e.g., 0.0.0.0 to listen on all interfaces)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    args = parser.parse_args()

    # To run this:
    # 1. IMPORTANT: This file must be named something other than 'code.py' (e.g., 'app.py') to avoid conflicts with Python's standard library.
    # 2. Create a folder named 'templates' in the same directory.
    # 3. Save the HTML content above as 'index.html' and 'report.html' inside the 'templates' folder.
    # 4. Run from your terminal using the new filename (e.g., python app.py --host 0.0.0.0 --port 8080)
    # 5. Open your web browser to the specified host and port.
    app.run(host=args.host, port=args.port, debug=True)
