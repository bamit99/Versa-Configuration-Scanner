import json
from flask import current_app as app

# --- Rule Loading ---
def load_rules(filepath='rules.json'):
    """Loads audit rules from a JSON file."""
    try:
        with open(filepath, 'r') as f:
            rules = json.load(f)
            app.logger.info(f"Successfully loaded {len(rules)} rules from {filepath}")
            return rules
    except FileNotFoundError:
        app.logger.error(f"Error: Rules file not found at {filepath}")
        return []
    except json.JSONDecodeError:
        app.logger.error(f"Error: Could not decode JSON from {filepath}")
        return []
    except Exception as e:
        app.logger.error(f"Error loading rules: {e}")
        return []

# --- Rule Engine and Findings ---
class RuleEngine:
    def __init__(self, rules):
        self.rules = {rule['id']: rule for rule in rules}
        self.findings = []

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
            affected_config = affected_config.format(**affected_config_params)

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

        # RULE_ID: VOS-MGT-001
        if 'VOS-MGT-001' in self.rules and any(service.get('name') == 'telnet' and service.get('enabled', False) for service in normalized_config.get('system_services', [])):
            self._add_finding('VOS-MGT-001')

        # RULE_ID: VOS-MGT-002
        if 'VOS-MGT-002' in self.rules:
            for service in normalized_config.get('system_services', []):
                if service.get('name') == 'web-management' and service.get('http_enabled', False):
                    self._add_finding('VOS-MGT-002')

        # RULE_ID: VOS-FW-001
        if 'VOS-FW-001' in self.rules:
            for policy in normalized_config.get('security_policies', []):
                for rule in policy.get('rules', []):
                    if rule.get('source') == 'any' and rule.get('destination') == 'any' and rule.get('service') == 'any':
                        self._add_finding('VOS-FW-001', affected_config_params={'policy_name': policy.get('name'), 'rule_id': rule.get('id')})

        # RULE_ID: VOS-FW-002
        if 'VOS-FW-002' in self.rules:
            for policy in normalized_config.get('security_policies', []):
                for rule in policy.get('rules', []):
                    if rule.get('action') in ['deny', 'reject'] and not rule.get('log', False):
                        self._add_finding('VOS-FW-002', affected_config_params={'policy_name': policy.get('name'), 'rule_id': rule.get('id')})
        
        # RULE_ID: VOS-SYS-001
        if 'VOS-SYS-001' in self.rules and not any(service.get('name') == 'ntp' and service.get('configured') for service in normalized_config.get('system_services', [])):
            self._add_finding('VOS-SYS-001')

        # RULE_ID: VOS-MGT-003
        if 'VOS-MGT-003' in self.rules:
            for service in normalized_config.get('system_services', []):
                if service.get('name') == 'snmp':
                    for community in service.get('communities', []):
                        if community in ['public', 'private']:
                            self._add_finding('VOS-MGT-003', affected_config_params={'community_name': community})
        
        # RULE_ID: VOS-AUTH-001
        if 'VOS-AUTH-001' in self.rules and not any(service.get('name') == 'password-complexity' and service.get('enabled') for service in normalized_config.get('system_services', [])):
            self._add_finding('VOS-AUTH-001')

        # RULE_ID: VOS-FW-003
        if 'VOS-FW-003' in self.rules:
            for policy in normalized_config.get('security_policies', []):
                for rule in policy.get('rules', []):
                    action = rule.get('action', 'permit')
                    source_zone = rule.get('source-zone')
                    dest_zone = rule.get('destination-zone')
                    if action == 'permit' and (not source_zone or not dest_zone):
                        self._add_finding('VOS-FW-003', affected_config_params={'policy_name': policy.get('name'), 'rule_id': rule.get('id')})
        
        # RULE_ID: VOS-MGT-006
        if 'VOS-MGT-006' in self.rules:
            for service in normalized_config.get('system_services', []):
                if service.get('name') == 'ssh' and service.get('port') == '22':
                    self._add_finding('VOS-MGT-006')

        # RULE_ID: VOS-SYS-002
        if 'VOS-SYS-002' in self.rules and not any(service.get('name') == 'dns' and service.get('configured') for service in normalized_config.get('system_services', [])):
            self._add_finding('VOS-SYS-002')

        # RULE_ID: VOS-AUTH-006
        if 'VOS-AUTH-006' in self.rules and not any(service.get('name') == 'login-attempts' and service.get('configured') for service in normalized_config.get('system_services', [])):
            self._add_finding('VOS-AUTH-006')

        app.logger.info(f"Evaluated {len(self.rules)} rules, found {len(self.findings)} findings.")
        return self.findings
