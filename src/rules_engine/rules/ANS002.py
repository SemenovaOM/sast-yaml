from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Использование 'changed_when' без 'when'

class ANS002(Rule):
    def __init__(self):
        super().__init__(
            id="ANS002",
            description="Использование 'changed_when' без 'when'",
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
                
                has_changed_when = task.changed_when is not None  
                has_when = task.when is not None and task.when != []  
                
                if has_changed_when and not has_when:
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""

                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"Задача {task_phrase}{play_phrase} использует 'changed_when', но не имеет 'when'. "
                            f"Рекомендуется добавить условие 'when' для контроля выполнения задачи."
                        )
                    })
        return violations