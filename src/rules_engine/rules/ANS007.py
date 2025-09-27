from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Отключение проверки SSL/TLS сертификатов

class ANS007(Rule):
    def __init__(self):
        super().__init__(
            id="ANS007",
            description="Отключение проверки SSL/TLS сертификатов",
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
                
                if self._has_disabled_ssl_verification(task):
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"Задача {task_phrase}{play_phrase} отключает проверку SSL/TLS сертификатов. "
                            f"Рекомендуется использовать валидные сертификаты и не отключать проверку."
                        )
                    })
        return violations
    
    def _has_disabled_ssl_verification(self, task) -> bool:
        if not hasattr(task, 'parameters') or not isinstance(task.parameters, dict):
            return False
        
        params = task.parameters
        
        validate_certs = params.get('validate_certs')
        tls_verify = params.get('tls_verify')
        skip_tls_verify = params.get('skip_tls_verify')
        insecure = params.get('insecure')
        
        url = params.get('url') or params.get('src') or params.get('image')
        
        if self._is_falsey(validate_certs) or \
           self._is_falsey(tls_verify) or \
           self._is_truthy(skip_tls_verify) or \
           self._is_truthy(insecure):
            return True
        
        if url and self._has_insecure_scheme(str(url)):
            return True
            
        return False
    
    def _is_falsey(self, value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return not value
        elif isinstance(value, str):
            return value.lower() in ['false', 'no', '0', 'off']
        elif isinstance(value, int):
            return value == 0
        return False
    
    def _is_truthy(self, value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            return value.lower() in ['true', 'yes', '1', 'on']
        elif isinstance(value, int):
            return value != 0
        return False
    
    def _has_insecure_scheme(self, url: str) -> bool:
        insecure_schemes = ['http://', 'ftp://', 'tcp://']
        return any(url.startswith(scheme) for scheme in insecure_schemes)