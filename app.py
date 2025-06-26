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
import threading
import uuid
import time # For simulating long-running tasks

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'json', 'xml', 'cli'} # Add more if needed
CONFIG_DIR = 'configs' # Directory to store parsed configs
REPORTS_DIR = 'reports' # Directory for generated reports

# In-memory store for tasks
# Structure: {task_id: {'status': 'pending/running/completed/failed', 'report_url': None, 'findings': None, 'filename': None, 'error': None}}
tasks = {}
task_lock = threading.Lock()

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
        Parses Versa CLI configuration output into a structured dictionary.
        This version handles complex nested structures and value assignments robustly.
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
                # If we are at the end of a path that assigns a value
                if i == len(parts) - 2:
                    key = parts[i]
                    value = parts[i+1]
                    # Ensure the current level at this key is a dictionary
                    if key not in current_level:
                        current_level[key] = {}
                    elif not isinstance(current_level[key], dict):
                         # If it's not a dict, it was likely a presence flag. Convert it.
                         current_level[key] = {'__present__': True}

                    # Assign the value to the special '__value__' key
                    current_level[key]['__value__'] = value
                    break # End processing for this line
                
                # If it's a command without a value (a presence flag)
                elif i == len(parts) - 1:
                    current_level[part] = {'__present__': True}
                    break

                # Navigate deeper
                if part not in current_level:
                    current_level[part] = {}
                
                # If the path is obstructed by a non-dictionary, log it and stop.
                # This case should be rare with the new logic but is a good safeguard.
                if not isinstance(current_level[part], dict):
                     app.logger.warning(f"Configuration conflict in line: '{line}'. Path is obstructed at '{part}'.")
                     break

                current_level = current_level[part]
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
                if services.get('ssh', {}).get('port'):
                    normalized_data['system_services'].append({
                        'name': 'ssh',
                        'port': services['ssh']['port'].get('__value__')
                    })
                if cli_config.get('system', {}).get('name-servers'):
                    normalized_data['system_services'].append({'name': 'dns', 'configured': True})

            # Map system login settings
            if cli_config.get('system', {}).get('login', {}):
                login_settings = cli_config['system']['login']
                if login_settings.get('password', {}).get('complexity'):
                    normalized_data['system_services'].append({'name': 'password-complexity', 'enabled': True})
                if login_settings.get('user'):
                    for user, user_data in login_settings.get('user').items():
                        if user_data.get('authentication', {}).get('max-attempts'):
                             normalized_data['system_services'].append({'name': 'login-attempts', 'configured': True})

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
                                'source': rule_data.get('source', {}).get('__value__', 'any'),
                                'destination': rule_data.get('destination', {}).get('__value__', 'any'),
                                'source-zone': rule_data.get('source-zone', {}).get('__value__'),
                                'destination-zone': rule_data.get('destination-zone', {}).get('__value__'),
                                'service': rule_data.get('service', {}).get('__value__', 'any'),
                                'action': rule_data.get('then', {}).get('action', {}).get('__value__', 'permit'),
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
    """Handles file upload, saves it, and initiates a background scan task."""
    if 'file' not in request.files:
        return {'error': 'No file part in the request.'}, 400
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No file selected for uploading.'}, 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        task_id = str(uuid.uuid4())
        with task_lock:
            tasks[task_id] = {
                'status': 'uploaded',
                'filename': filename,
                'filepath': filepath,
                'report_url': None,
                'findings': None,
                'error': None
            }
        app.logger.info(f"File '{filename}' uploaded. Task ID: {task_id}")
        return {'task_id': task_id, 'message': 'File uploaded successfully, awaiting scan initiation.'}, 202
    else:
        return {'error': 'Invalid file type. Please upload .txt, .json, .xml, or .cli files.'}, 400

def run_scan_task(task_id):
    """Performs the actual configuration parsing and auditing in a background thread."""
    with app.app_context(): # Needed to use Flask's app.logger and render_template
        with task_lock:
            task = tasks.get(task_id)
            if not task:
                app.logger.error(f"Task {task_id} not found for scanning.")
                return

            if task['status'] != 'uploaded':
                app.logger.warning(f"Scan for task {task_id} already initiated or completed.")
                return

            task['status'] = 'running'
            app.logger.info(f"Starting scan for task {task_id} (file: {task['filename']})...")

        try:
            filepath = task['filepath']
            filename = task['filename']

            parser = VersaConfigParser()
            parsed_data = parser.load_config(filepath)

            if not parsed_data:
                raise ValueError(f"Could not parse the configuration file '{filename}'. Please ensure it is a valid and supported format (JSON, XML, or Versa CLI).")

            normalized_config = parser.normalize_configuration()

            rules = load_rules()
            rule_engine = RuleEngine(rules)
            findings = rule_engine.evaluate(normalized_config)

            report_filename = f"audit_report_{filename}_{task_id}.html"
            report_filepath = os.path.join(REPORTS_DIR, report_filename)

            csv_report_name = write_findings_to_csv(findings, filename, report_filepath)
            
            with open(report_filepath, 'w', encoding='utf-8') as rf:
                rf.write(render_template('report.html',
                                          filename=filename,
                                          findings=findings,
                                          severity_counts=get_severity_counts(findings),
                                          total_findings=len(findings),
                                          total_rules=len(rules),
                                          csv_report_name=csv_report_name))

            with task_lock:
                task['status'] = 'completed'
                task['report_name'] = report_filename # Store only the filename
                task['findings'] = findings # Store findings if needed for other purposes
                app.logger.info(f"Scan for task {task_id} completed. Report filename: {task['report_name']}")

        except Exception as e:
            with task_lock:
                task['status'] = 'failed'
                task['error'] = str(e)
                app.logger.error(f"Scan for task {task_id} failed: {e}")

@app.route('/scan/<task_id>', methods=['POST'])
def initiate_scan(task_id):
    """Initiates the background scan for a given task ID."""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return {'error': 'Task not found.'}, 404
        if task['status'] != 'uploaded':
            return {'error': f"Scan for task {task_id} is already {task['status']}."}, 409
    
    # Start the scan in a new thread
    thread = threading.Thread(target=run_scan_task, args=(task_id,))
    thread.start()
    return {'message': 'Scan initiated.', 'task_id': task_id}, 202

@app.route('/status/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    """Returns the current status of a scan task."""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return {'error': 'Task not found.'}, 404
        
        response_data = {
            'task_id': task_id,
            'status': task['status'],
            'filename': task['filename']
        }
        if task['status'] == 'completed':
            response_data['report_name'] = task['report_name'] # Send the report name
        elif task['status'] == 'failed':
            response_data['error'] = task['error']
        
        return response_data, 200

@app.route('/reports/<report_name>')
def view_report(report_name):
    """Displays a generated audit report."""
    return send_from_directory(REPORTS_DIR, report_name)

def get_severity_counts(findings):
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'WARNING': 0, 'LOW': 0}
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
