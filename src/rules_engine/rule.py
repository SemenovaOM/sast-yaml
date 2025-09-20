from abc import ABC, abstractmethod
from typing import List, Dict, Any

# Базовый класс для правил анализа кода

class Rule(ABC):
    def __init__(self, id: str, description: str, severity: str):
        self.id = id
        self.description = description
        self.severity = severity  # 'HIGH', 'MEDIUM', 'LOW'
    
    @abstractmethod
    
    # Проверка AST на соответствие правилу. 

    def check(self, ast: List[Any]) -> List[Dict[str, Any]]:
        pass
    
    def __str__(self):
        return f"{self.id}: {self.description} ({self.severity})"
