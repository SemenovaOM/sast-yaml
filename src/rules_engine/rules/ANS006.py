from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Создание/изменение файлов без указания owner, group и mode

class ANS006(Rule):
    def __init__(self):
        super().__init__(
            id="ANS006",
            description="Создание/изменение файлов без указания owner, group и mode",
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
                
                if self._is_file_creation_module(task):
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
                                f"Задача {task_phrase}{play_phrase} создает файлы без указания owner, group или mode. "
                                f"Рекомендуется явно задавать права доступа."
                            )
                        })
        return violations
    
    def _is_file_creation_module(self, task) -> bool:
        file_creation_modules = [
            'copy', 'template', 'file',
            'ansible.builtin.copy', 'ansible.builtin.template', 'ansible.builtin.file'
        ]
        
        if task.module in ['file', 'ansible.builtin.file']:
            params = task.parameters if hasattr(task, 'parameters') else {}
            if isinstance(params, dict):
                state = params.get('state', 'file')
                if state in ['absent', 'link', 'hard']:
                    return False
        
        return task.module in file_creation_modules
    
    def _missing_permissions(self, task) -> bool:
        if not hasattr(task, 'parameters') or not task.parameters:
            return False
            
        params = task.parameters
        if not isinstance(params, dict):
            return False
        
        dest = params.get('dest', '') or params.get('path', '')
        if self._is_temporary_path(str(dest)):
            return False
            
        if params.get('remote_src') and not params.get('force', True):
            return False
            
        owner = params.get('owner')
        group = params.get('group')
        mode = params.get('mode')
        
        if owner is None and group is None and mode is None:
            return True
            
        if mode and self._is_dangerous_mode(mode):
            return True

        if task.module in ['template', 'ansible.builtin.template']:
            return False
        
        dest = params.get('dest', '') or params.get('path', '')
        if self._is_system_config(dest):
            return False
        
        return owner is None and group is None and mode is None

    def _is_system_config(self, path: str) -> bool:
        system_configs = [
            '/etc/', '/usr/lib/', '/lib/', '/opt/',
            'service', 'config', 'conf', 'ini', 'yml', 'yaml'
        ]
        return any(config in str(path).lower() for config in system_configs)
    
    def _is_temporary_path(self, path: str) -> bool:
        if not path:
            return False
            
        path_lower = path.lower()
        temporary_indicators = [
            '/tmp/', '/var/tmp/', '/dev/shm/', 
            '/tmp\\', '/var/tmp\\',
            'temp', 'tmp', 'cache'
        ]
        
        for indicator in temporary_indicators:
            if indicator in path_lower:
                if any(sys_conf in path_lower for sys_conf in ['/tmp/.ssh/', '/tmp/secret', '/tmp/config']):
                    return False
                return True
                
        return False
    
    def _is_dangerous_mode(self, mode: Any) -> bool:
        if not mode:
            return False
            
        mode_str = str(mode).strip().replace('"', '').replace("'", "")
        
        dangerous_numeric_modes = [
            '0777', '777', '0775', '775', 
            '0666', '666', '0664', '664',
            '0770', '770', '0660', '660'
        ]
        
        if mode_str in dangerous_numeric_modes:
            return True
        
        dangerous_symbolic_modes = [
            'a+rwx', 'a+rw', 'ugo+rwx', 'ugo+rw',
            'rwxrwxrwx', 'rw-rw-rw-', 'rw-r--r--'
        ]
        
        if any(dangerous in mode_str for dangerous in dangerous_symbolic_modes):
            return True
            
        if mode_str.isdigit():
            if len(mode_str) == 4 and mode_str[-1] in ['6', '7']:
                return True
            elif len(mode_str) == 3 and mode_str[0] in ['6', '7']:
                return True
        
        return False