from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Инъекция команд через непроверенный пользовательский ввод

class ANS010(Rule):
    def __init__(self):
        super().__init__(
            id="ANS010",
            description="Инъекция команд через непроверенный пользовательский ввод",
            severity="HIGH"
        )
    
    def check(self, ast: List[Any]) -> List[Dict[str, Any]]:
        from src.ast_model.nodes import PlayNode, TaskNode
        
        violations = []
        for play in ast:
            if not isinstance(play, PlayNode):
                continue
                
            for task in play.tasks:
                if not isinstance(task, TaskNode):
                    continue
                
                if task.module in ['command', 'shell', 'ansible.builtin.command', 'ansible.builtin.shell']:
                    injection_issues = self._check_command_injection(task)
                    if injection_issues:
                        task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                        play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                        
                        violations.append({
                            'rule_id': self.id,
                            'description': self.description,
                            'severity': self.severity,
                            'play': play.name or None,
                            'task': task.name or None,
                            'message': (
                                f"Задача {task_phrase}{play_phrase} уязвим к инъекции команд: {injection_issues}. "
                                f"Рекомендуется использовать модули Ansible вместо сырых команд."
                            )
                        })
        
        return violations
    
    def _check_command_injection(self, task) -> str:
        issues = []
        
        command = self._get_command_string(task)
        if not command:
            return ""
        
        import re
        variable_pattern = r'\{\{\s*([^}]+)\s*\}\}'
        variables = re.findall(variable_pattern, command)
        
        for var in variables:
            var_name = var.strip()
            if '|' in var_name:
                continue
            if self._is_potential_user_input(var_name):
                issues.append(f"непроверенная переменная '{var_name}' в команде")
        
        return ", ".join(issues) if issues else ""
    
    def _get_command_string(self, task) -> str:
        if hasattr(task, 'parameters') and task.parameters:
            if isinstance(task.parameters, dict):
                return (task.parameters.get('cmd') or 
                       task.parameters.get('command') or 
                       task.parameters.get('_raw_params') or 
                       "")
            elif isinstance(task.parameters, str):
                return task.parameters
        return ""
    
    def _is_potential_user_input(self, var_name: str) -> bool:
        user_input_indicators = ['input', 'user', 'param', 'arg', 'data']
        return any(indicator in var_name.lower() for indicator in user_input_indicators)