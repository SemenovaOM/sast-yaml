from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union

@dataclass
class Node:
    """Базовый класс для всех узлов AST"""
    line: int = 0
    column: int = 0

@dataclass
class PlayNode(Node):
    """Узел, представляющий плейбук (play)"""
    name: str = ""
    hosts: str = ""
    vars: Dict[str, Any] = field(default_factory=dict)
    tasks: List['TaskNode'] = field(default_factory=list)
    handlers: List['TaskNode'] = field(default_factory=list)

@dataclass
class TaskNode(Node):
    """Узел, представляющий задачу (task)"""
    name: str = ""
    module: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    when: Optional['ExpressionNode'] = None
    changed_when: Optional['ExpressionNode'] = None
    loop: Optional['ExpressionNode'] = None
    register: Optional[str] = None
    notify: List[str] = field(default_factory=list)

@dataclass
class ExpressionNode(Node):
    """Узел, представляющий выражение (например, условие when)"""
    # Все поля должны иметь значения по умолчанию
    expression_type: str = ""  # 'variable', 'literal', 'comparison', 'logical'
    value: Any = None
    left: Optional['ExpressionNode'] = None
    right: Optional['ExpressionNode'] = None
    operator: Optional[str] = None

@dataclass
class VariableNode(Node):
    """Узел, представляющий переменную"""
    name: str = ""
    value: Any = None

# Псевдоним для типов выражений
Expression = Union[ExpressionNode, VariableNode, str, int, float, bool]
