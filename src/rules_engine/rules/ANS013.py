from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Небезопасная загрузка и выполнение кода

class ANS013(Rule):
    def __init__(self):
        super().__init__(
            id="ANS013",
            description="Небезопасная загрузка и выполнение кода",
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
                
                download_issues = self._check_download_execute(task)
                if download_issues:
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"Task {task_phrase}{play_phrase} содержит небезопасную загрузку и выполнение: {download_issues}. "
                            f"Рекомендуется избегать паттернов загрузки и выполнения."
                        )
                    })
        
        return violations
    
    def _check_download_execute(self, task) -> str:
        issues = []
        
        if task.module in ['get_url', 'ansible.builtin.get_url']:
            issues.extend(self._check_get_url_module(task))
        
        if task.module in ['command', 'shell', 'ansible.builtin.command', 'ansible.builtin.shell']:
            issues.extend(self._check_download_patterns(task))
        
        return ", ".join(issues) if issues else ""
    
    def _check_get_url_module(self, task) -> List[str]:
        issues = []
        
        if not hasattr(task, 'parameters') or not task.parameters:
            return issues
        
        params = task.parameters
        dest = params.get('dest', '')
        url = params.get('url', '')
        
        if self._is_executable_file(str(dest)):
            if not self._is_verified_source(str(url)):
                issues.append("загрузка исполняемого файла без проверки")
            
            if 'checksum' not in params:
                issues.append("отсутствует проверка контрольной суммы")
        
        return issues
    
    def _check_download_patterns(self, task) -> List[str]:
        issues = []
        
        command = self._get_command_string(task)
        if not command:
            return issues
        
        dangerous_patterns = [
            ('curl.*\\|.*sh', 'curl | sh pattern'),
            ('wget.*\\|.*sh', 'wget | sh pattern'),
            ('curl.*\\|.*bash', 'curl | bash pattern'),
            ('wget.*-O.*sh', 'wget -O script execution'),
        ]
        
        import re
        for pattern, description in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                issues.append(description)
        
        return issues
    
    def _is_executable_file(self, filename: str) -> bool:
        executable_extensions = ['.sh', '.py', '.pl', '.rb', '.exe', '.bin']
        import os
        base_name = os.path.basename(filename)
        _, ext = os.path.splitext(base_name)
        return ext in executable_extensions
    
    def _is_verified_source(self, url: str) -> bool:
        verified_indicators = ['https://', 'sha256:', 'checksum=']
        return any(indicator in url.lower() for indicator in verified_indicators)
    
    def _get_command_string(self, task) -> str:
        if hasattr(task, 'parameters') and task.parameters:
            if isinstance(task.parameters, dict):
                return (task.parameters.get('cmd') or 
                       task.parameters.get('command') or 
                       task.parameters.get('_raw_params') or 
                       "")
            elif isinstance(task.parameters, str):
                return task.parameters
        return ""