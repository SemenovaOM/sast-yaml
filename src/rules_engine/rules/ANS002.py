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
                    if self._is_safe_changed_when_usage(task):
                        continue
                    
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
    
    def _is_safe_changed_when_usage(self, task) -> bool:
        if task.changed_when is False or str(task.changed_when).strip().lower() == 'false':
            return True
            
        if self._is_check_task(task):
            return True
            
        if self._is_idempotent_command(task):
            return True
            
        if self._is_database_migration(task):
            return True
            
        return False
    
    def _is_check_task(self, task) -> bool:
        check_indicators = [
            'status', 'version', 'info', 'check', 'verify', 
            'test', 'validate', 'health', 'ping'
        ]
        
        task_name = (task.name or '').lower()
        task_module = (task.module or '').lower()
        
        if any(indicator in task_name for indicator in check_indicators):
            return True
            
        if task_module in ['stat', 'wait_for', 'assert', 'fail']:
            return True
            
        return False
    
    def _is_idempotent_command(self, task) -> bool:
        if task.module != 'command':
            return False
            
        command = self._get_command_string(task)
        if not command:
            return False
            
        command_lower = command.lower()
        
        idempotent_commands = [
            'echo', 'cat', 'grep', 'find', 'ls', 'pwd', 'whoami',
            'date', 'uname', 'hostname', 'which', 'type', 'command -v'
        ]
        
        return any(cmd in command_lower for cmd in idempotent_commands)
    
    def _is_database_migration(self, task) -> bool:
        migration_indicators = [
            'migrate', 'migration', 'db_schema', 'alembic', 'liquibase',
            'flyway', 'django', 'makemigrations', 'manage.py'
        ]
        
        task_name = (task.name or '').lower()
        command = self._get_command_string(task)
        command_lower = (command or '').lower()
        
        if any(indicator in task_name for indicator in migration_indicators):
            return True
            
        if any(indicator in command_lower for indicator in migration_indicators):
            return True
            
        return False
    
    def _get_command_string(self, task) -> str:
        if not hasattr(task, 'parameters') or not task.parameters:
            return ""
        
        if isinstance(task.parameters, dict):
            return (task.parameters.get('cmd') or 
                   task.parameters.get('command') or 
                   task.parameters.get('_raw_params') or 
                   "")
        elif isinstance(task.parameters, str):
            return task.parameters
        
        return ""