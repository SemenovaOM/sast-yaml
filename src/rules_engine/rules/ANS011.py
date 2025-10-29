from typing import List, Dict, Any
from src.rules_engine.rule import Rule

class ANS011(Rule):
    def __init__(self):
        super().__init__(
            id="ANS011",
            description="Небезопасная обработка временных файлов",
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
                
                issues = self._check_temp_file_issues(task)
                if issues:
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"TЗадача {task_phrase}{play_phrase} содержит небезопасную работу с временными файлами: {issues}. "
                            f"Рекомендуется использовать безопасные методы для временных файлов."
                        )
                    })
        
        return violations
    
    def _check_temp_file_issues(self, task) -> str:
        """Простая проверка проблем с временными файлами"""
        issues = []
        
        # Проверка модулей, создающих файлы
        if task.module in ['file', 'copy', 'template', 'tempfile']:
            issues.extend(self._check_file_modules(task))
        
        # Проверка команд с временными файлами
        if task.module in ['command', 'shell']:
            issues.extend(self._check_command_modules(task))
        
        return ", ".join(issues) if issues else ""
    
    def _check_file_modules(self, task) -> List[str]:
        """Проверка модулей файлов"""
        issues = []
        
        if not hasattr(task, 'parameters') or not task.parameters:
            return issues
        
        params = task.parameters
        path = str(params.get('dest') or params.get('path') or '')
        
        # Проверяем только явные временные пути
        if not self._is_clear_temp_path(path):
            return issues
        
        # Проверка опасных разрешений
        mode = params.get('mode')
        if mode and self._is_world_writable(mode):
            issues.append(f"временный файл с правами {mode}")
        
        # Проверка чувствительных данных
        content = params.get('content', '')
        if self._has_secrets(str(content)):
            issues.append("временный файл содержит секреты")
        
        return issues
    
    def _check_command_modules(self, task) -> List[str]:
        """Проверка команд на работу с временными файлами"""
        issues = []
        
        if not hasattr(task, 'parameters'):
            return issues
        
        command = self._get_command_string(task)
        if not command:
            return issues
        
        command_str = str(command).lower()
        
        # Простые проверки
        if '/tmp/' in command_str:
            if 'chmod 777' in command_str or 'chmod 666' in command_str:
                issues.append("команда устанавливает опасные права для /tmp файла")
            
            if 'password' in command_str or 'secret' in command_str:
                issues.append("команда записывает секреты в /tmp")
        
        return issues
    
    def _is_clear_temp_path(self, path: str) -> bool:
        """Простая проверка временных путей"""
        if not path:
            return False
        
        path_lower = path.lower()
        return any(temp in path_lower for temp in ['/tmp/', '/var/tmp/', '/dev/shm/'])
    
    def _is_world_writable(self, mode: Any) -> bool:
        """Проверка world-writable прав"""
        if not mode:
            return False
        
        mode_str = str(mode).strip()
        
        # Простые проверки
        world_writable_modes = ['0777', '0666', '1777', '2777', '777', '666']
        if mode_str in world_writable_modes:
            return True
        
        # Проверка последней цифры
        if mode_str.isdigit() and len(mode_str) == 4:
            return mode_str[-1] in ['6', '7']
        
        return False
    
    def _has_secrets(self, text: str) -> bool:
        """Проверка на наличие секретов"""
        secrets = ['password=', 'secret=', 'key=', 'token=', 'PRIVATE KEY']
        return any(secret in text.upper() for secret in secrets)
    
    def _get_command_string(self, task) -> str:
        """Получение команды из задачи"""
        if not hasattr(task, 'parameters'):
            return ""
        
        if isinstance(task.parameters, dict):
            return (task.parameters.get('cmd') or 
                   task.parameters.get('command') or 
                   task.parameters.get('_raw_params') or 
                   "")
        elif isinstance(task.parameters, str):
            return task.parameters
        
        return ""