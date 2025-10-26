from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Правило: Небезопасная конфигурация SSH сервера

class ANS009(Rule):
    def __init__(self):
        super().__init__(
            id="ANS009",
            description="Небезопасная конфигурация SSH сервера",
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
                
                ssh_issues = self._check_ssh_configuration(task)
                if ssh_issues:
                    task_phrase = f"'{task.name.strip()}'" if task.name and task.name.strip() else ""
                    play_phrase = f" в плейбуке '{play.name.strip()}'" if play.name and play.name.strip() else ""
                    
                    violations.append({
                        'rule_id': self.id,
                        'description': self.description,
                        'severity': self.severity,
                        'play': play.name or None,
                        'task': task.name or None,
                        'message': (
                            f"Task {task_phrase}{play_phrase} содержит небезопасные настройки SSH: {ssh_issues}. "
                        )
                    })
        
        return violations
    
    def _check_ssh_configuration(self, task) -> str:
        issues = []
        
        if task.module in ['lineinfile', 'blockinfile', 'copy', 'template', 
                          'ansible.builtin.lineinfile', 'ansible.builtin.blockinfile',
                          'ansible.builtin.copy', 'ansible.builtin.template']:
            
            if self._is_ssh_config_task(task):
                ssh_issues = self._analyze_ssh_settings(task)
                issues.extend(ssh_issues)
        
        return ", ".join(issues) if issues else ""
    
    def _is_ssh_config_task(self, task) -> bool:
        if not hasattr(task, 'parameters') or not task.parameters:
            return False
        
        params = task.parameters
        path = params.get('path', '')
        dest = params.get('dest', '')
        content = params.get('content', '')
        
        ssh_indicators = [
            '/etc/ssh/sshd_config',
            'sshd_config',
            'PermitRootLogin',
            'PasswordAuthentication',
            'Protocol'
        ]
        
        target_path = str(path) + str(dest) + str(content)
        return any(indicator in target_path for indicator in ssh_indicators)
    
    def _analyze_ssh_settings(self, task) -> List[str]:
        issues = []
        
        if not hasattr(task, 'parameters') or not task.parameters:
            return issues
        
        params = task.parameters
        content = params.get('content', '')
        line = params.get('line', '')
        regexp = params.get('regexp', '')
        
        config_content = str(content) + str(line)
        
        insecure_settings = {
            'PermitRootLogin yes': 'разрешение входа root (должно быть no или without-password)',
            'PasswordAuthentication yes': 'аутентификация по паролю (рекомендуется no)',
            'Protocol 1': 'использование устаревшего SSHv1 (должен быть 2)',
            'X11Forwarding yes': 'проброс X11 (рекомендуется no)',
            'PermitEmptyPasswords yes': 'разрешение пустых паролей (должно быть no)',
            'ChallengeResponseAuthentication yes': 'challenge-response аутентификация (рекомендуется no)',
            'UsePAM no': 'отключение PAM (рекомендуется yes)',
        }
        
        for setting, description in insecure_settings.items():
            if setting.lower() in config_content.lower():
                issues.append(description)
        
        if regexp and 'PermitRootLogin' in str(regexp):
            if 'yes' in str(line).lower():
                issues.append('ослабление политики входа root')
        
        return issues