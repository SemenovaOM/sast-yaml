from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Использование устаревшего модуля raw

class ANS005(Rule):
    def __init__(self):
        super().__init__(
            id="ANS005",
            description="Использование устаревшего модуля raw",
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

                if task.module in ['raw', 'ansible.builtin.raw']:
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"Задача {task_phrase}{play_phrase} использует устаревший модуль raw. "
                            f"Рекомендуется использовать модули command/shell."
                        )
                    })
        return violations