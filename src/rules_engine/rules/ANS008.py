from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Установка пакетов без фиксации версий

class ANS008(Rule):
    def __init__(self):
        super().__init__(
            id="ANS008",
            description="Установка пакетов без фиксации версий",
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
                
                if self._is_package_management_task(task):
                    if self._has_unversioned_package_install(task):
                        task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                        play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                        
                        violations.append({
                            'rule_id': self.id,
                            'description': self.description,
                            'severity': self.severity,
                            'play': play.name or None,
                            'task': task.name or None,
                            'message': (
                                f"Задача {task_phrase}{play_phrase} устанавливает пакеты без фиксации версий. "
                                f"Рекомендуется явно указывать версии пакетов."
                            )
                        })
        return violations
    
    def _is_package_management_task(self, task) -> bool:
        package_modules = [
            'package', 'apt', 'yum', 'dnf', 'pacman', 'zypper',
            'ansible.builtin.package', 'ansible.builtin.apt', 
            'ansible.builtin.yum', 'ansible.builtin.dnf',
            'ansible.builtin.pacman', 'ansible.builtin.zypper',
            'pip', 'ansible.builtin.pip'
        ]
        return task.module in package_modules
    
    def _has_unversioned_package_install(self, task) -> bool:
        if not hasattr(task, 'parameters') or not isinstance(task.parameters, dict):
            return False
        
        params = task.parameters
        
        if 'name' in params:
            package_spec = params['name']
            if isinstance(package_spec, str):
                if '=' in package_spec or '-' in package_spec:
                    return False
                return True
            elif isinstance(package_spec, list):
                # Для списка пакетов
                for package in package_spec:
                    if isinstance(package, str) and ('=' in package or '-' in package):
                        continue
                    else:
                        return True
                return False
        
        if 'requirements' in params:
            return False
            
        if 'name' in params and task.module in ['pip', 'ansible.builtin.pip']:
            package_spec = params['name']
            if isinstance(package_spec, str):
                return '==' not in package_spec and '>=' not in package_spec and '<=' not in package_spec
        
        return False