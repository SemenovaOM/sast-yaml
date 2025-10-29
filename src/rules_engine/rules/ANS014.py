from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Использование опасных функций выполнения кода

class ANS014(Rule):
    def __init__(self):
        super().__init__(
            id="ANS014",
            description="Использование опасных функций выполнения кода",
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
                
                function_issues = self._check_dangerous_functions(task)
                if function_issues:
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"Задача {task_phrase}{play_phrase} использует опасные функции: {function_issues}. "
                            f"Рекомендуется избегать динамического выполнения кода."
                        )
                    })
        
        return violations
    
    def _check_dangerous_functions(self, task) -> str:
        issues = []
        all_params = self._get_all_parameters_string(task)
        
        dangerous_functions = [
            'eval(', 'exec(', 'compile(', 'execfile(', 'input()',
            'subprocess.call', 'subprocess.Popen', 'os.system',
            'popen(', 'spawn(', 'execve(', 'reload(', '__import__'
        ]
        
        for func in dangerous_functions:
            if func in all_params.lower():
                issues.append(f"использование {func}")
        
        return ", ".join(issues) if issues else ""
    
    def _get_all_parameters_string(self, task) -> str:
        if not hasattr(task, 'parameters') or not task.parameters:
            return ""
        
        if isinstance(task.parameters, dict):
            return " ".join([f"{k}={v}" for k, v in task.parameters.items()])
        else:
            return str(task.parameters)