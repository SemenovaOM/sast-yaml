import os
import sys
from typing import Any, Dict, List
from .nodes import PlayNode, TaskNode, ExpressionNode, VariableNode

class ASTBuilder:
    """Класс для построения AST из данных, полученных от парсера YAML"""
    
    def __init__(self):
        self.current_line = 0
        self.current_column = 0
    
    def build_ast(self, parsed_data: List[Dict[str, Any]]) -> List[PlayNode]:
        """
        Основной метод для построения AST из распарсенных данных
        
        :param parsed_data: Данные, полученные от ruamel.yaml парсера
        :return: Список узлов PlayNode (AST)
        """
        plays = []
        
        for play_data in parsed_data:
            play_node = self._build_play(play_data)
            plays.append(play_node)
        
        return plays
    
    def _build_play(self, play_data: Dict[str, Any]) -> PlayNode:
        """Строит узел плейбука из данных"""
        play_node = PlayNode()
        
        if 'name' in play_data:
            play_node.name = play_data['name']
        
        if 'hosts' in play_data:
            play_node.hosts = play_data['hosts']
        
        if 'vars' in play_data:
            play_node.vars = self._build_variables(play_data['vars'])
        
        if 'tasks' in play_data:
            play_node.tasks = self._build_tasks(play_data['tasks'])
        
        if 'handlers' in play_data:
            play_node.handlers = self._build_tasks(play_data['handlers'])
        
        return play_node
    
    def _build_tasks(self, tasks_data: List[Dict[str, Any]]) -> List[TaskNode]:
        """Строит список узлов задач из данных"""
        tasks = []
        
        for task_data in tasks_data:
            task_node = TaskNode()
            
            if 'name' in task_data:
                task_node.name = task_data['name']
            
            # Определяем модуль и его параметры
            for key, value in task_data.items():
                if key not in ['name', 'when', 'loop', 'register', 'notify']:
                    task_node.module = key
                    task_node.parameters = value
                    break
            
            if 'when' in task_data:
                task_node.when = self._build_expression(task_data['when'])

            if 'changed_when' in task_data:
                task_node.changed_when = self._build_expression(task_data['changed_when'])
            
            if 'loop' in task_data:
                task_node.loop = self._build_expression(task_data['loop'])
            
            if 'register' in task_data:
                task_node.register = task_data['register']
            
            if 'notify' in task_data:
                task_node.notify = task_data['notify'] if isinstance(task_data['notify'], list) else [task_data['notify']]
            
            tasks.append(task_node)
        
        return tasks
    
    def _build_expression(self, expression_data: Any) -> ExpressionNode:
        """Строит узел выражения из данных"""
        if isinstance(expression_data, (str, int, float, bool)):
            # Простой литерал
            return ExpressionNode(
                expression_type='literal',
                value=expression_data
            )
        elif isinstance(expression_data, dict):
            # Сложное выражение
            return ExpressionNode(
                expression_type='complex',
                value=str(expression_data)
            )
        elif isinstance(expression_data, list):
            # Список выражений
            return ExpressionNode(
                expression_type='list',
                value=[self._build_expression(item) for item in expression_data]
            )
        else:
            # Неизвестный тип выражения
            return ExpressionNode(
                expression_type='unknown',
                value=str(expression_data)
            )
    
    def _build_variables(self, vars_data: Dict[str, Any]) -> Dict[str, VariableNode]:
        """Строит словарь переменных из данных"""
        variables = {}
        
        for name, value in vars_data.items():
            variables[name] = VariableNode(
                name=name,
                value=value
            )
        
        return variables

def print_ast(ast_nodes: List[PlayNode], indent: int = 0):
    """Рекурсивная функция для печати AST"""
    for play in ast_nodes:
        print('  ' * indent + f"Play: {play.name}")
        print('  ' * (indent + 1) + f"Hosts: {play.hosts}")
        
        if play.vars:
            print('  ' * (indent + 1) + "Variables:")
            for var_name, var_node in play.vars.items():
                print('  ' * (indent + 2) + f"{var_name}: {var_node.value}")
        
        if play.tasks:
            print('  ' * (indent + 1) + "Tasks:")
            for task in play.tasks:
                print('  ' * (indent + 2) + f"Task: {task.name}")
                print('  ' * (indent + 3) + f"Module: {task.module}")
                print('  ' * (indent + 3) + f"Parameters: {task.parameters}")
                
                if task.when:
                    print('  ' * (indent + 3) + f"When: {task.when.value}")

                if task.changed_when:
                    print('  ' * (indent + 3) + f"Changed_when: {task.changed_when.value}")
                
                if task.register:
                    print('  ' * (indent + 3) + f"Register: {task.register}")
        
        if play.handlers:
            print('  ' * (indent + 1) + "Handlers:")
            for handler in play.handlers:
                print('  ' * (indent + 2) + f"Handler: {handler.name}")
