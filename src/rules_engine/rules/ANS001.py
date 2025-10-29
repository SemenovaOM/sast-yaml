from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Использование модуля 'command' для управления службами вместо 'service'

class ANS001(Rule):
    def __init__(self):
        super().__init__(
            id="ANS001",
            description="Использование модуля 'command' для управления службами вместо 'service'",
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
                    
                if task.module == 'command' and self._is_service_management(task):
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""

                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': f"Задача {task_phrase}{play_phrase} использует модуль 'command' для управления службами. "
                                   f"Рекомендуется использовать модуль 'service'."
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
    
    def _is_service_management(self, task) -> bool:
        command = self._get_command_string(task)
        if not command:
            return False
            
        command_lower = command.lower()
        
        if 'status' in command_lower:
            return False
            
        if 'ln -sf' in command_lower or 'ln -s' in command_lower:
            return False
            
        if 'test' in command_lower or 'exists' in command_lower:
            return False
            
        service_management_patterns = [
            (r'systemctl\s+(start|stop|restart|enable|disable)\s+', 'systemctl команда'),
            (r'service\s+\w+\s+(start|stop|restart)', 'service команда'),
            (r'/etc/init\.d/\w+\s+(start|stop|restart)', 'init.d скрипт'),
            (r'^\s*(start|stop|restart)\s+\w+', 'прямая команда службы')
        ]
        
        import re
        for pattern, description in service_management_patterns:
            if re.search(pattern, command_lower):
                return True
        
        service_indicators = ['start ', 'stop ', 'restart ', 'enable ', 'disable ']
        system_indicators = ['systemctl', 'service ', '/etc/init.d/']
        
        has_service_action = any(indicator in command_lower for indicator in service_indicators)
        has_system_indicator = any(indicator in command_lower for indicator in system_indicators)
        
        return has_service_action and has_system_indicator