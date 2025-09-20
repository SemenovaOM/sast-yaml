from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Использования модуля command для управления службами вместо модуля service

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
    
    def _is_service_management(self, task) -> bool:
        command = task.parameters.get('_raw_params', '') if isinstance(task.parameters, dict) else str(task.parameters)
        service_commands = ['start', 'stop', 'restart', 'status', 'enable', 'disable']
        return any(cmd in command for cmd in service_commands)
