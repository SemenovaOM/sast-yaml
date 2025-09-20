from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Использование sudo/su

class ANS004(Rule):
    def __init__(self):
        super().__init__(
            id="ANS004",
            description="Использование sudo/su",
            severity="MEDIUM"
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
                    command = self._get_command_string(task)
                    if command and self._contains_sudo_su(command):
                        task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                        play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""

                        violations.append({
                            'rule_id': self.id,
                            'description': self.description,
                            'severity': self.severity,
                            'play': play.name or None,
                            'task': task.name or None,
                            'message': (
                                f"Задача {task_phrase}{play_phrase} использует sudo/su в команде. "
                                f"Рекомендуется использовать механизм become вместо встроенных команд sudo/su. "
                            )
                        })
        return violations
    
    def _get_command_string(self, task) -> str:
        if hasattr(task, 'parameters') and task.parameters:
            if isinstance(task.parameters, dict):
                command = task.parameters.get('cmd', '') or \
                         task.parameters.get('command', '') or \
                         task.parameters.get('_raw_params', '')
                return str(command) if command else ''
            elif isinstance(task.parameters, str):
                return task.parameters
        return ''
    
    def _contains_sudo_su(self, command: str) -> bool:
        import re
        patterns = [
            r'^sudo\s+',
            r'\ssudo\s+',
            r'^su\s+',
            r'\ssu\s+',
            r'^sudo$',
            r'\ssudo$',
            r'^su$',
            r'\ssu$'
        ]
        
        command_lower = command.lower()
        for pattern in patterns:
            if re.search(pattern, command_lower):
                return True
        
        return False