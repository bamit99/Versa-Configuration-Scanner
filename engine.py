import json
from flask import current_app as app
from abc import ABC, abstractmethod
import os
import shlex
import re
import xml.etree.ElementTree as ET

# --- Platform Detection ---
class PlatformDetector:
    def detect_platform(self, filepath):
        """
        Attempts to auto-detect the platform based on file content heuristics and a scoring system.
        Returns the platform name (e.g., 'versa', 'cisco_ios', 'juniper_junos') or None if uncertain.
        """
        platform_scores = {
            'versa': 0,
            'cisco_ios': 0,
            'juniper_junos': 0
        }
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read() # Read entire file for more accurate detection

                # Heuristics for Versa
                # Check for 'set' commands (common in Versa CLI) - increased weight
                platform_scores['versa'] += len(re.findall(r'^\s*set\s+', content, re.MULTILINE)) * 3
                # More specific Versa keywords, including common CLI session starters
                if re.search(r'device-template|sd-wan|application-qos|security-policy-rule|config\s+mode|edit\s+mode', content, re.IGNORECASE):
                    platform_scores['versa'] += 7 # Increased weight
                # Check for JSON/XML structure (often used by Versa Director exports)
                if content.strip().startswith('{') or content.strip().startswith('['):
                    try:
                        json.loads(content)
                        platform_scores['versa'] += 15 # Very high confidence for JSON
                    except json.JSONDecodeError:
                        pass
                elif content.strip().startswith('<'):
                    try:
                        ET.fromstring(content)
                        platform_scores['versa'] += 15 # Very high confidence for XML
                    except ET.ParseError:
                        pass

                # Heuristics for Cisco IOS
                platform_scores['cisco_ios'] += len(re.findall(r'^\s*(interface|router|access-list|ip\s+route|line\s+vty)', content, re.MULTILINE)) * 1
                if re.search(r'hostname|enable\s+secret|crypto\s+map|snmp-server\s+community', content, re.IGNORECASE):
                    platform_scores['cisco_ios'] += 5
                if re.search(r'show\s+running-config', content, re.IGNORECASE): # Often in saved outputs
                    platform_scores['cisco_ios'] += 3

                # Heuristics for Juniper Junos
                platform_scores['juniper_junos'] += len(re.findall(r'^\s*(system|interfaces|security|policy-options|routing-options)\s*{', content, re.MULTILINE)) * 1
                if re.search(r'from-zone|to-zone|policy\s+\S+\s*{|apply-groups|root-authentication', content, re.IGNORECASE):
                    platform_scores['juniper_junos'] += 5
                if re.search(r'show\s+configuration', content, re.IGNORECASE): # Often in saved outputs
                    platform_scores['juniper_junos'] += 3

            app.logger.info(f"Platform scores for {filepath}: {platform_scores}")

            # Determine the best match
            best_platform = None
            highest_score = 0
            
            # Find the highest score
            for platform, score in platform_scores.items():
                if score > highest_score:
                    highest_score = score
            
            # Check for clear winner (confidence threshold)
            if highest_score > 0:
                # Count how many platforms have a score close to the highest
                contenders = [p for p, s in platform_scores.items() if s >= highest_score * 0.5] # Within 50% of top score
                
                if len(contenders) == 1:
                    best_platform = contenders[0]
                    app.logger.info(f"Confidently detected '{best_platform}' for {filepath} with score {highest_score}.")
                else:
                    app.logger.warning(f"Multiple platforms detected with similar scores for {filepath}: {contenders}. Cannot confidently auto-detect.")
            
            if best_platform:
                return best_platform
            else:
                app.logger.warning(f"Could not confidently auto-detect platform for {filepath}. Scores: {platform_scores}")
                return None

        except Exception as e:
            app.logger.error(f"Error during platform detection for {filepath}: {e}")
            return None

# --- Base Parser Interface ---
class BaseConfigParser(ABC):
    @abstractmethod
    def load_config(self, filepath):
        """Loads configuration data from a file."""
        pass

    @abstractmethod
    def normalize_configuration(self):
        """Normalizes the loaded configuration into a unified internal data model."""
        pass

# --- Versa Configuration Parsing Logic (adapted to new interface) ---
class VersaConfigParser(BaseConfigParser):
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

# --- Cisco IOS Parser ---
class CiscoIOSConfigParser(BaseConfigParser):
    def __init__(self):
        self.raw_config_lines = None
        self.normalized_config_data = None

    def load_config(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.raw_config_lines = f.readlines()
            app.logger.info(f"Successfully loaded Cisco IOS configuration from {filepath}")
            return self.raw_config_lines
        except FileNotFoundError:
            app.logger.error(f"Error: Cisco IOS file not found at {filepath}")
            return None
        except Exception as e:
            app.logger.error(f"Error loading Cisco IOS configuration: {e}")
            return None

    def normalize_configuration(self):
        if not self.raw_config_lines:
            app.logger.warning("No raw Cisco IOS configuration data loaded to normalize.")
            return None

        normalized_data = {
            "system_services": [],
            "security_policies": [], # For access-lists
            "interface_configs": [],
            "routing_configs": [],
            "user_auth_profiles": [],
            "raw_cli_lines": self.raw_config_lines # Store raw lines for regex checks
        }

        # --- System Services ---
        # service password-encryption
        if any("service password-encryption" in line for line in self.raw_config_lines):
            normalized_data['system_services'].append({'name': 'password-encryption', 'enabled': True})
        else:
            normalized_data['system_services'].append({'name': 'password-encryption', 'enabled': False})

        # SNMP
        snmp_communities = []
        for line in self.raw_config_lines:
            match = re.search(r"snmp-server community (\S+)\s+(RO|RW)", line)
            if match:
                snmp_communities.append({'name': match.group(1), 'permission': match.group(2)})
        if snmp_communities:
            normalized_data['system_services'].append({'name': 'snmp', 'communities': snmp_communities})

        # --- Security Policies (Access-Lists) ---
        # This logic needs to be robust for various ACL types (standard, extended, named)
        # For simplicity, let's focus on basic numbered ACLs for now
        for line in self.raw_config_lines:
            # Standard ACL: access-list 10 permit any
            acl_standard_match = re.match(r"access-list (\d+)\s+(permit|deny)\s+(.+)", line)
            if acl_standard_match:
                acl_name = acl_standard_match.group(1)
                action = acl_standard_match.group(2)
                # For standard ACLs, source is the third group, destination is implied 'any'
                source_part = acl_standard_match.group(3).strip()
                source = 'any'
                destination = 'any'
                
                # Attempt to parse source if it's not 'any'
                if not source_part.lower().startswith('any'):
                    source_match = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?", source_part)
                    if source_match:
                        source = source_match.group(1)
                        if source_match.group(2): # Wildcard mask
                            source += f" {source_match.group(2)}"
                    else: # Could be a host or other complex source
                        source = source_part # Keep as is for now

                rule = {
                    'line': line.strip(),
                    'action': action,
                    'source': source,
                    'destination': destination,
                    'service': 'any', # Standard ACLs don't specify service
                    'type': 'standard'
                }
                found_acl = next((acl for acl in normalized_data['security_policies'] if acl['name'] == acl_name), None)
                if not found_acl:
                    found_acl = {'name': acl_name, 'type': 'access-list', 'rules': []}
                    normalized_data['security_policies'].append(found_acl)
                found_acl['rules'].append(rule)

            # Extended ACL: access-list 100 permit ip any any
            acl_extended_match = re.match(r"access-list (\d+)\s+extended\s+(permit|deny)\s+(ip|tcp|udp|icmp)\s+(\S+)\s+(\S+)", line)
            if acl_extended_match:
                acl_name = acl_extended_match.group(1)
                action = acl_extended_match.group(2)
                protocol = acl_extended_match.group(3)
                source = acl_extended_match.group(4)
                destination = acl_extended_match.group(5)

                if source.lower() == 'any': source = 'any'
                if destination.lower() == 'any': destination = 'any'

                rule = {
                    'line': line.strip(),
                    'action': action,
                    'protocol': protocol,
                    'source': source,
                    'destination': destination,
                    'service': 'any', # Service might be implied by protocol or port
                    'type': 'extended'
                }
                found_acl = next((acl for acl in normalized_data['security_policies'] if acl['name'] == acl_name), None)
                if not found_acl:
                    found_acl = {'name': acl_name, 'type': 'access-list', 'rules': []}
                    normalized_data['security_policies'].append(found_acl)
                found_acl['rules'].append(rule)

        # --- Interface Configurations (for VTY lines) ---
        current_line_vty = None
        for line in self.raw_config_lines:
            vty_match = re.match(r"line vty (\d+)\s+(\d+)", line)
            if vty_match:
                line_name = f"{vty_match.group(1)} {vty_match.group(2)}"
                current_line_vty = {'name': line_name, 'type': 'vty', 'access_class_applied': False}
                normalized_data['interface_configs'].append(current_line_vty)
            elif current_line_vty and "access-class" in line:
                current_line_vty['access_class_applied'] = True
            elif current_line_vty and not line.strip(): # End of block
                current_line_vty = None
            elif current_line_vty and not line.startswith(' '): # End of block (no indentation)
                current_line_vty = None


        self.normalized_config_data = normalized_data
        app.logger.info("Cisco IOS configuration normalization process completed.")
        return self.normalized_config_data

# --- Juniper Junos Parser ---
class JuniperJunosConfigParser(BaseConfigParser):
    def __init__(self):
        self.raw_config_lines = None
        self.normalized_config_data = None

    def load_config(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.raw_config_lines = f.readlines()
            app.logger.info(f"Successfully loaded Juniper Junos configuration from {filepath}")
            return self.raw_config_lines
        except FileNotFoundError:
            app.logger.error(f"Error: Juniper Junos file not found at {filepath}")
            return None
        except Exception as e:
            app.logger.error(f"Error loading Juniper Junos configuration: {e}")
            return None

    def normalize_configuration(self):
        if not self.raw_config_lines:
            app.logger.warning("No raw Juniper Junos configuration data loaded to normalize.")
            return None

        normalized_data = {
            "system_services": [],
            "security_policies": [],
            "interface_configs": [],
            "routing_configs": [],
            "user_auth_profiles": [],
            "raw_cli_lines": self.raw_config_lines # Store raw lines for regex checks
        }

        # Simple state machine for parsing Junos
        current_path = []
        config_tree = {}
        current_level = config_tree

        for line in self.raw_config_lines:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith('#') or stripped_line.startswith('/*'):
                continue

            indent_level = len(line) - len(line.lstrip())

            # Adjust current_level based on indentation
            while len(current_path) > 0 and indent_level <= current_path[-1]['indent']:
                current_path.pop()
                current_level = config_tree
                for p in current_path:
                    current_level = current_level[p['key']]

            if stripped_line.endswith('{'):
                key = stripped_line[:-1].strip()
                if key not in current_level:
                    current_level[key] = {}
                current_level = current_level[key]
                current_path.append({'key': key, 'indent': indent_level})
            elif stripped_line.endswith(';'):
                key_value = stripped_line[:-1].strip()
                parts = shlex.split(key_value) # Use shlex to handle quoted strings
                if len(parts) > 1:
                    key = parts[0]
                    value = ' '.join(parts[1:])
                    current_level[key] = value
                else:
                    current_level[key_value] = True # Flag for presence
            else: # Assume it's a simple key without value or block
                key = stripped_line
                current_level[key] = True # Flag for presence

        # --- Map parsed Junos config to normalized data model ---
        # System Services
        system_services_config = config_tree.get('system', {}).get('services', {})
        if 'telnet' in system_services_config:
            normalized_data['system_services'].append({'name': 'telnet', 'enabled': True})
        if 'ssh' in system_services_config:
            ssh_config = system_services_config['ssh']
            normalized_data['system_services'].append({
                'name': 'ssh',
                'enabled': True,
                'root_login_enabled': 'root-login allow' in ssh_config,
                'password_authentication_enabled': 'password' in config_tree.get('system', {}).get('root-authentication', {}) # Simplified check
            })

        # Security Policies (simplified for example)
        security_policies_config = config_tree.get('security', {}).get('policies', {})
        for from_zone_key, from_zone_data in security_policies_config.items():
            if from_zone_key.startswith('from-zone'):
                for to_zone_key, to_zone_data in from_zone_data.items():
                    if to_zone_key.startswith('to-zone'):
                        for policy_name, policy_data in to_zone_data.items():
                            if 'policy' in policy_name:
                                match_data = policy_data.get('match', {})
                                normalized_data['security_policies'].append({
                                    'name': policy_name,
                                    'from_zone': from_zone_key.replace('from-zone ', ''),
                                    'to_zone': to_zone_key.replace('to-zone ', ''),
                                    'source': match_data.get('source-address', 'any'),
                                    'destination': match_data.get('destination-address', 'any'),
                                    'application': match_data.get('application', 'any'),
                                    'action': 'permit' if 'permit' in policy_data.get('then', {}) else 'deny'
                                })

        self.normalized_config_data = normalized_data
        app.logger.info("Juniper Junos configuration normalization process completed.")
        return self.normalized_config_data

# --- Rule Loading ---
def load_rules(platform='versa'):
    """Loads audit rules from a JSON file for a specific platform."""
    filepath = os.path.join('rules', platform, 'rules.json')
    try:
        with open(filepath, 'r') as f:
            rules = json.load(f)
            app.logger.info(f"Successfully loaded {len(rules)} rules for platform '{platform}' from {filepath}")
            return rules
    except FileNotFoundError:
        app.logger.error(f"Error: Rules file not found at {filepath} for platform '{platform}'.")
        return []
    except json.JSONDecodeError:
        app.logger.error(f"Error: Could not decode JSON from {filepath} for platform '{platform}'.")
        return []
    except Exception as e:
        app.logger.error(f"Error loading rules for platform '{platform}': {e}")
        return []

# --- Rule Engine and Findings ---
class RuleEngine:
    def __init__(self, rules):
        self.rules = {rule['id']: rule for rule in rules}
        self.findings = []

    def _get_value_from_path(self, data, path):
        """Safely retrieves a nested value from a dictionary using a dot-separated path."""
        parts = path.split('.')
        current_data = data
        for part in parts:
            if isinstance(current_data, dict) and part in current_data:
                current_data = current_data[part]
            elif isinstance(current_data, list) and part.isdigit(): # Allow indexing into lists
                try:
                    current_data = current_data[int(part)]
                except (IndexError, ValueError):
                    return None
            else:
                return None
        return current_data

    def _evaluate_condition(self, condition, data):
        """
        Evaluates a single condition against the given data.
        Condition structure:
        {
            "target": "path.to.field",
            "operator": "equals",
            "value": "expected_value"
        }
        OR for logical operators:
        {
            "operator": "and",
            "conditions": [...]
        }
        """
        operator = condition.get('operator')

        if operator in ['and', 'or']:
            sub_conditions = condition.get('conditions', [])
            results = [self._evaluate_condition(sub_cond, data) for sub_cond in sub_conditions]
            return all(results) if operator == 'and' else any(results)

        target_path = condition.get('target')
        target_value = self._get_value_from_path(data, target_path) if target_path else data # If no target_path, operate on data itself

        expected_value = condition.get('value')

        if operator == 'equals':
            return target_value == expected_value
        elif operator == 'not_equals':
            return target_value != expected_value
        elif operator == 'contains': # For strings or lists
            return expected_value in target_value if isinstance(target_value, (str, list)) else False
        elif operator == 'not_contains':
            return expected_value not in target_value if isinstance(target_value, (str, list)) else True
        elif operator == 'is_present':
            return target_value is not None
        elif operator == 'not_present':
            return target_value is None
        elif operator == 'in': # Checks if target_value is in a list of expected_values
            return target_value in expected_value if isinstance(expected_value, list) else False
        elif operator == 'not_in':
            return target_value not in expected_value if isinstance(expected_value, list) else True
        elif operator == 'contains_item': # For lists of dicts, checks if an item matching value exists
            if isinstance(target_value, list) and isinstance(expected_value, dict):
                for item in target_value:
                    # Check if all key-value pairs in expected_value match the item
                    if all(k in item and item[k] == v for k, v in expected_value.items()):
                        return True
                return False
            return False
        elif operator == 'not_contains_item': # For lists of dicts, checks if an item matching value does NOT exist
            if isinstance(target_value, list) and isinstance(expected_value, dict):
                for item in target_value:
                    if all(k in item and item[k] == v for k, v in expected_value.items()):
                        return False # Found a matching item, so it's NOT 'not_contains_item'
                return True # No matching item found, so it IS 'not_contains_item'
            return True # If not a list or expected_value not a dict, then it's 'not_contains_item' by default
        elif operator == 'matches_regex': # For strings, checks if target_value matches regex pattern
            if isinstance(target_value, str) and isinstance(expected_value, str):
                return re.search(expected_value, target_value) is not None
            return False
        elif operator == 'greater_than':
            return target_value > expected_value
        elif operator == 'less_than':
            return target_value < expected_value

        app.logger.warning(f"Unknown operator '{operator}' in rule condition.")
        return False

    def _add_finding(self, rule_id, affected_config_params=None):
        """Helper to append a new finding using rule data from the loaded rules."""
        rule = self.rules.get(rule_id)
        if not rule:
            app.logger.warning(f"Attempted to add a finding for a non-existent rule_id: {rule_id}")
            return

        description = rule['description']
        details = rule['details']
        affected_config = rule.get('affected_config_template', '')
        if affected_config_params:
            try:
                affected_config = affected_config.format(**affected_config_params)
            except KeyError as e:
                app.logger.warning(f"Missing parameter for affected_config_template in rule {rule_id}: {e}. Template: {affected_config}, Params: {affected_config_params}")
                affected_config = f"Error: Missing param for template. Rule: {rule_id}"


        self.findings.append({
            'rule_id': rule_id,
            'severity': rule['severity'],
            'description': description,
            'details': details,
            'affected_config': affected_config
        })

    def evaluate(self, normalized_config):
        self.findings = []
        if not normalized_config or not self.rules:
            return []

        for rule_id, rule in self.rules.items():
            check_definition = rule.get('check')
            if not check_definition:
                app.logger.warning(f"Rule {rule_id} has no 'check' definition. Skipping.")
                continue

            # Handle iterative checks (e.g., for lists of policies, services)
            if check_definition.get('operator') == 'for_each':
                target_list_path = check_definition.get('target')
                iterator_var = check_definition.get('item_var')
                inner_check = check_definition.get('inner_check')
                where_condition = check_definition.get('where') # New: Optional 'where' clause

                target_list = self._get_value_from_path(normalized_config, target_list_path)
                if not isinstance(target_list, list):
                    app.logger.warning(f"Rule {rule_id}: 'for_each' target '{target_list_path}' is not a list. Skipping.")
                    continue

                # Apply 'where' filter if present
                filtered_list = []
                if where_condition:
                    for item in target_list:
                        temp_data_context_for_where = {iterator_var: item}
                        if self._evaluate_condition(where_condition, temp_data_context_for_where):
                            filtered_list.append(item)
                else:
                    filtered_list = target_list

                for item in filtered_list: # Iterate over filtered list
                    # Create a temporary data context for inner checks, including the current item
                    temp_data_context = {iterator_var: item}
                    
                    # If there's an inner 'for_each', handle nested iteration
                    if inner_check and inner_check.get('operator') == 'for_each':
                        inner_target_list_path = inner_check.get('target')
                        inner_iterator_var = inner_check.get('item_var')
                        inner_condition = inner_check.get('condition')
                        inner_affected_params_map = inner_check.get('affected_params', {})
                        inner_where_condition = inner_check.get('where') # New: Nested 'where'

                        inner_target_list = self._get_value_from_path(temp_data_context, inner_target_list_path)
                        if not isinstance(inner_target_list, list):
                            app.logger.warning(f"Rule {rule_id}: Nested 'for_each' target '{inner_target_list_path}' is not a list. Skipping.")
                            continue
                        
                        # Apply nested 'where' filter if present
                        nested_filtered_list = []
                        if inner_where_condition:
                            for inner_item in inner_target_list:
                                innermost_data_context_for_where = {**temp_data_context, inner_iterator_var: inner_item}
                                if self._evaluate_condition(inner_where_condition, innermost_data_context_for_where):
                                    nested_filtered_list.append(inner_item)
                        else:
                            nested_filtered_list = inner_target_list

                        for inner_item in nested_filtered_list: # Iterate over nested filtered list
                            # Extend temp_data_context for the innermost item
                            innermost_data_context = {**temp_data_context, inner_iterator_var: inner_item}
                            
                            if self._evaluate_condition(inner_condition, innermost_data_context):
                                affected_params = {}
                                for param_name, param_path in inner_affected_params_map.items():
                                    affected_params[param_name] = self._get_value_from_path(innermost_data_context, param_path)
                                self._add_finding(rule_id, affected_params)
                    elif inner_check and inner_check.get('condition'):
                        # Simple condition within a single for_each loop
                        if self._evaluate_condition(inner_check['condition'], temp_data_context):
                            affected_params = {}
                            affected_params_map = inner_check.get('affected_params', {})
                            for param_name, param_path in affected_params_map.items():
                                affected_params[param_name] = self._get_value_from_path(temp_data_context, param_path)
                            self._add_finding(rule_id, affected_params)

            # Handle simple checks (non-iterative)
            elif self._evaluate_condition(check_definition, normalized_config):
                self._add_finding(rule_id)

        app.logger.info(f"Evaluated {len(self.rules)} rules, found {len(self.findings)} findings.")
        return self.findings
