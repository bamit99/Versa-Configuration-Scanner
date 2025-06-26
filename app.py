import os
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash, jsonify
from werkzeug.utils import secure_filename
import json
import xml.etree.ElementTree as ET
import shlex
import re
from functools import wraps
import csv
import datetime
from engine import RuleEngine, load_rules, PlatformDetector, VersaConfigParser, CiscoIOSConfigParser, JuniperJunosConfigParser, BaseConfigParser # Import new classes
import threading
import uuid
import time # For simulating long-running tasks
from database import init_db, add_scan_record, update_scan_record, get_all_scans, get_scan_by_id # Import DB functions

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

# Initialize the database on app startup
with app.app_context():
    init_db()

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Dictionary to map platform names to their respective parser classes
PARSERS = {
    'versa': VersaConfigParser,
    'cisco_ios': CiscoIOSConfigParser,
    'juniper_junos': JuniperJunosConfigParser,
}


# --- Flask Routes ---
@app.route('/')
def index():
    """Home page with file upload form."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file upload, saves it, and initiates a background scan task."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading.'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        detector = PlatformDetector()
        detected_platform = detector.detect_platform(filepath)

        if not detected_platform:
            # If auto-detection fails, return a response indicating manual selection is needed
            # Use 422 Unprocessable Entity to signal that more info is required
            return jsonify({
                'status': 'platform_unknown',
                'message': 'Could not auto-detect platform. Please select manually.',
                'filepath': filepath, # Keep filepath for later use
                'filename': filename
            }), 422 # Changed status code to 422

        # Proceed with scan initiation if platform is detected
        task_id = str(uuid.uuid4())
        with task_lock:
            tasks[task_id] = {
                'status': 'uploaded',
                'filename': filename,
                'filepath': filepath,
                'platform': detected_platform, # Store the detected platform
                'report_name': None,
                'findings': None,
                'error': None
            }
        # Add initial record to database
        add_scan_record({
            'id': task_id,
            'filename': filename,
            'platform': detected_platform,
            'status': 'uploaded'
        })
        app.logger.info(f"File '{filename}' uploaded. Detected platform: '{detected_platform}'. Task ID: {task_id}")
        return jsonify({
            'task_id': task_id,
            'message': 'File uploaded successfully, awaiting scan initiation.',
            'platform': detected_platform,
            'filepath': filepath, # Always return filepath
            'filename': filename  # Always return filename
        }), 202
    else:
        return jsonify({'error': 'Invalid file type. Please upload .txt, .json, .xml, or .cli files.'}), 400

@app.route('/initiate_scan', methods=['POST'])
def initiate_scan_manual():
    """Initiates a scan when platform is manually selected or auto-detected."""
    data = request.get_json()
    task_id = data.get('task_id')
    platform = data.get('platform')
    filepath = data.get('filepath')
    filename = data.get('filename')

    if not task_id or not platform or not filepath or not filename:
        return jsonify({'error': 'Missing task_id, platform, filepath, or filename.'}), 400

    with task_lock:
        # If task_id already exists (from auto-detection), update it
        if task_id in tasks:
            task = tasks[task_id]
            task['platform'] = platform
            task['status'] = 'uploaded' # Reset status if it was 'platform_unknown'
        else: # If task_id is new (e.g., from a manual re-upload after initial failure)
            tasks[task_id] = {
                'status': 'uploaded',
                'filename': filename,
                'filepath': filepath,
                'platform': platform,
                'report_name': None,
                'findings': None,
                'error': None
            }
            # Update or add record to database for manual initiation
            update_scan_record(task_id, 'uploaded') # Ensure status is 'uploaded'
    
    # Start the scan in a new thread
    thread = threading.Thread(target=run_scan_task, args=(task_id,))
    thread.start()
    return jsonify({'message': 'Scan initiated.', 'task_id': task_id, 'platform': platform}), 202


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
            app.logger.info(f"Starting scan for task {task_id} (file: {task['filename']}, platform: {task['platform']})...")
            # Update database record to 'running' status
            update_scan_record(task_id, 'running')

        try:
            filepath = task['filepath']
            filename = task['filename']
            platform = task['platform']

            # Dynamically get the parser based on the detected platform
            parser_class = PARSERS.get(platform)
            if not parser_class:
                raise ValueError(f"Unsupported platform: {platform}")
            
            parser: BaseConfigParser = parser_class() # Instantiate the correct parser
            parsed_data = parser.load_config(filepath)

            if not parsed_data:
                raise ValueError(f"Could not parse the configuration file '{filename}' for platform '{platform}'. Please ensure it is a valid and supported format.")

            normalized_config = parser.normalize_configuration()

            rules = load_rules(platform) # Load platform-specific rules
            rule_engine = RuleEngine(rules)
            findings = rule_engine.evaluate(normalized_config)

            report_filename = f"audit_report_{filename}_{task_id}.html"
            report_filepath = os.path.join(REPORTS_DIR, report_filename)

            csv_report_name = write_findings_to_csv(findings, filename, report_filepath)
            
            # Generate HTML report without using render_template (to avoid Flask context issues)
            html_content = generate_html_report(filename, findings, get_severity_counts(findings), len(findings), len(rules), csv_report_name)
            
            with open(report_filepath, 'w', encoding='utf-8') as rf:
                rf.write(html_content)

            with task_lock:
                task['status'] = 'completed'
                task['report_name'] = report_filename # Store only the filename
                task['findings'] = findings # Store findings if needed for other purposes
                app.logger.info(f"Scan for task {task_id} completed. Report filename: {task['report_name']}")
            
            # Update database record
            update_scan_record(task_id, 'completed', report_name=report_filename)

        except Exception as e:
            with task_lock:
                task['status'] = 'failed'
                task['error'] = str(e)
                app.logger.error(f"Scan for task {task_id} failed: {e}")
            
            # Update database record with error
            update_scan_record(task_id, 'failed', error=str(e))


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
            'filename': task['filename'],
            'platform': task.get('platform', 'unknown') # Include platform in status response
        }
        if task['status'] == 'completed':
            response_data['report_name'] = task['report_name'] # Send the report name
        elif task['status'] == 'failed':
            response_data['error'] = task['error']
        
        return jsonify(response_data), 200

@app.route('/reports/<report_name>')
def view_report(report_name):
    """Displays a generated audit report."""
    return send_from_directory(REPORTS_DIR, report_name)

@app.route('/history')
def history():
    """Displays a list of all past scan reports."""
    scans = get_all_scans()
    return render_template('history.html', scans=scans)

def get_severity_counts(findings):
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'WARNING': 0, 'LOW': 0}
    for finding in findings:
        severity = finding.get('severity', 'LOW').upper()
        if severity in counts:
            counts[severity] += 1
    return counts

def generate_html_report(filename, findings, severity_counts, total_findings, total_rules, csv_report_name):
    """Generate HTML report without using Flask's render_template to avoid context issues."""
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14', 
        'MEDIUM': '#ffc107',
        'WARNING': '#17a2b8',
        'LOW': '#28a745'
    }
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Report - {filename}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; background-color: #f4f4f4; color: #333; }}
        .container {{ max-width: 1000px; margin: 20px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #0056b3; text-align: center; }}
        .summary {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }}
        .summary-item {{ text-align: center; }}
        .summary-item h3 {{ margin: 0; font-size: 1.5em; }}
        .summary-item p {{ margin: 5px 0 0 0; font-size: 0.9em; color: #666; }}
        .findings {{ margin-top: 20px; }}
        .finding {{ border: 1px solid #ddd; border-radius: 5px; margin-bottom: 15px; padding: 15px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-weight: bold; font-size: 1.1em; }}
        .severity {{ padding: 4px 8px; border-radius: 3px; color: white; font-size: 0.8em; font-weight: bold; }}
        .finding-details {{ margin-top: 10px; }}
        .affected-config {{ background: #f8f9fa; padding: 10px; border-left: 4px solid #007bff; margin-top: 10px; font-family: monospace; }}
        .nav-links {{ text-align: center; margin-bottom: 20px; }}
        .nav-links a {{ color: #007bff; text-decoration: none; margin: 0 10px; }}
        .nav-links a:hover {{ text-decoration: underline; }}
        .download-link {{ text-align: center; margin-top: 20px; }}
        .download-link a {{ background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }}
        .download-link a:hover {{ background: #218838; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="nav-links">
            <a href="/">← Back to Scanner</a>
            <a href="/history">View History</a>
        </div>
        
        <h1>Configuration Audit Report</h1>
        <p><strong>File:</strong> {filename}</p>
        <p><strong>Scan Date:</strong> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        
        <div class="summary">
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>{total_findings}</h3>
                    <p>Total Findings</p>
                </div>
                <div class="summary-item">
                    <h3>{total_rules}</h3>
                    <p>Rules Evaluated</p>
                </div>"""
    
    for severity, count in severity_counts.items():
        if count > 0:
            color = severity_colors.get(severity, '#6c757d')
            html += f"""
                <div class="summary-item">
                    <h3 style="color: {color};">{count}</h3>
                    <p>{severity}</p>
                </div>"""
    
    html += """
            </div>
        </div>"""
    
    if csv_report_name:
        html += f"""
        <div class="download-link">
            <a href="/reports/{csv_report_name}">Download CSV Report</a>
        </div>"""
    
    html += """
        <div class="findings">"""
    
    if findings:
        for finding in findings:
            severity = finding.get('severity', 'LOW').upper()
            color = severity_colors.get(severity, '#6c757d')
            html += f"""
            <div class="finding">
                <div class="finding-header">
                    <div class="finding-title">{finding.get('description', 'No description')}</div>
                    <span class="severity" style="background-color: {color};">{severity}</span>
                </div>
                <div class="finding-details">
                    <p><strong>Rule ID:</strong> {finding.get('rule_id', 'N/A')}</p>
                    <p><strong>Details:</strong> {finding.get('details', 'No details available')}</p>"""
            
            if finding.get('affected_config'):
                html += f"""
                    <div class="affected-config">
                        <strong>Affected Configuration:</strong><br>
                        {finding.get('affected_config')}
                    </div>"""
            
            html += """
                </div>
            </div>"""
    else:
        html += """
            <div class="finding">
                <div class="finding-header">
                    <div class="finding-title">No Issues Found</div>
                    <span class="severity" style="background-color: #28a745;">CLEAN</span>
                </div>
                <div class="finding-details">
                    <p>Congratulations! No security issues or best-practice violations were detected in this configuration.</p>
                </div>
            </div>"""
    
    html += """
        </div>
    </div>
</body>
</html>"""
    
    return html

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
