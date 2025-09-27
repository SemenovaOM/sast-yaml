from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Отсутствие указания владельца и прав доступа к файловым объектам

class ANS006(Rule):
    def __init__(self):
        super().__init__(
            id="ANS006",
            description="Создание или изменение файлов без указания owner, group и mode",
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
                
                if self._is_file_management_module(task.module):
                    if self._missing_permissions(task):
                        task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                        play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                        
                        violations.append({
                            'rule_id': self.id,
                            'description': self.description,
                            'severity': self.severity,
                            'play': play.name or None,
                            'task': task.name or None,
                            'message': (
                                f"Задача {task_phrase}{play_phrase} создает/изменяет файлы без указания owner, group или mode. "
                                f"Рекомендуется явно задавать права доступа."
                            )
                        })
        return violations
    
    def _is_file_management_module(self, module: str) -> bool:
        file_modules = [
            'copy', 'template', 'file', 'lineinfile', 'blockinfile',
            'ansible.builtin.copy', 'ansible.builtin.template', 
            'ansible.builtin.file', 'ansible.builtin.lineinfile',
            'ansible.builtin.blockinfile'
        ]
        return module in file_modules
    
    def _missing_permissions(self, task) -> bool:
        if not hasattr(task, 'parameters'):
            return False
        
        params = task.parameters
        if not isinstance(params, dict):
            return False
        
        owner = params.get('owner')
        group = params.get('group')
        mode = params.get('mode')
        
        if owner is None and group is None and mode is None:
            return True
        
        if mode and self._is_dangerous_mode(mode):
            return True
            
        return False
    
    def _is_dangerous_mode(self, mode: Any) -> bool:
        if isinstance(mode, str):
            mode_str = str(mode).strip().replace('"', '').replace("'", "")
            
            dangerous_modes = ['0777', '0775', '0666', '0664', '0770', '0660']
            if mode_str in dangerous_modes:
                return True
            
            if 'rwxrwxrwx' in mode_str or 'a+rwx' in mode_str:
                return True
        
        return False