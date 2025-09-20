from typing import List, Dict, Any
from src.rules_engine.rule import Rule

# Движок для выполнения проверок правил на AST

class RulesEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
    
    def run(self, ast: List[Any]) -> List[Dict[str, Any]]:
        violations = []
        for rule in self.rules:
            violations.extend(rule.check(ast))
        return violations
