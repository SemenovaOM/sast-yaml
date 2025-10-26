from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Небезопасное выполнение скриптов из непроверенных источников

class ANS012(Rule):
    def __init__(self):
        super().__init__(
            id="ANS012",
            description="Небезопасное выполнение скриптов из непроверенных источников",
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
                
                if task.module in ['script', 'ansible.builtin.script']:
                    script_issues = self._check_script_execution(task)
                    if script_issues:
                        task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                        play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                        
                        violations.append({
                            'rule_id': self.id,
                            'description': self.description,
                            'severity': self.severity,
                            'play': play.name or None,
                            'task': task.name or None,
                            'message': (
                                f"Task {task_phrase}{play_phrase} содержит небезопасное выполнение скриптов: {script_issues}. "
                                f"Рекомендуется проверять источники и контрольные суммы скриптов."
                            )
                        })
        
        return violations
    
    def _check_script_execution(self, task) -> str:
        issues = []
        
        if not hasattr(task, 'parameters') or not task.parameters:
            return ""
        
        params = task.parameters
        
        if 'src' in params:
            src = str(params['src'])
            if self._is_untrusted_source(src):
                issues.append("скрипт из непроверенного источника")
        
        if 'args' in params:
            args = str(params['args'])
            if self._contains_unvalidated_input(args):
                issues.append("невалидированные аргументы скрипта")
        
        if 'checksum' not in params:
            issues.append("отсутствует проверка контрольной суммы")
        
        return ", ".join(issues) if issues else ""
    
    def _is_untrusted_source(self, source: str) -> bool:
        untrusted_indicators = [
            'http://', 'ftp://', 
            'raw.githubusercontent.com',
            'pastebin.com', 'gist.'
        ]
        return any(indicator in source.lower() for indicator in untrusted_indicators)
    
    def _contains_unvalidated_input(self, text: str) -> bool:
        input_indicators = ['{{', 'vars.', 'hostvars.']
        return any(indicator in text for indicator in input_indicators)