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
                    if all(item.get(k) == v for k, v in expected_value.items()):
                        return True
                return False
            return False
        elif operator == 'not_contains_item': # For lists of dicts, checks if an item matching value does NOT exist
            if isinstance(target_value, list) and isinstance(expected_value, dict):
                for item in target_value:
                    if all(item.get(k) == v for k, v in expected_value.items()):
                        return False # Found a matching item, so it's NOT 'not_contains_item'
                return True # No matching item found, so it IS 'not_contains_item'
            return True # If not a list or expected_value not a dict, then it's 'not_contains_item' by default

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

                target_list = self._get_value_from_path(normalized_config, target_list_path)
                if not isinstance(target_list, list):
                    app.logger.warning(f"Rule {rule_id}: 'for_each' target '{target_list_path}' is not a list. Skipping.")
                    continue

                for item in target_list:
                    # Create a temporary data context for inner checks, including the current item
                    temp_data_context = {iterator_var: item}
                    
                    # If there's an inner 'for_each', handle nested iteration
                    if inner_check and inner_check.get('operator') == 'for_each':
                        inner_target_list_path = inner_check.get('target')
                        inner_iterator_var = inner_check.get('item_var')
                        inner_condition = inner_check.get('condition')
                        inner_affected_params_map = inner_check.get('affected_params', {})

                        inner_target_list = self._get_value_from_path(temp_data_context, inner_target_list_path)
                        if not isinstance(inner_target_list, list):
                            app.logger.warning(f"Rule {rule_id}: Nested 'for_each' target '{inner_target_list_path}' is not a list. Skipping.")
                            continue

                        for inner_item in inner_target_list:
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