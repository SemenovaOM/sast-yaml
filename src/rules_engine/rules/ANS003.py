from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Отсутствие имени (name) у задачи

class ANS003(Rule):
    def __init__(self):
        super().__init__(
            id="ANS003",
            description="Задача не имеет имени",
            severity="LOW"
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
                
                if not task.name or task.name.strip() == "":
                    play_phrase = ""
                    if play.name and play.name.strip():
                        play_phrase = f" в плейбуке '{play.name.strip()}'"
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': f"Задача{play_phrase} не имеет имени. "
                                   f"Рекомендуется добавить 'name' для лучшей читаемости и отладки."
                    })
        return violations