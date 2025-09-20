import os
import importlib
import sys
from typing import List

# Загрузка правил из папки rules
def load_all_rules():
    rules = []
    rules_dir = os.path.dirname(__file__)
    
    for filename in os.listdir(rules_dir):
        if filename.startswith('ANS') and filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            
            try:
                full_module_path = f"src.rules_engine.rules.{module_name}"
                module = importlib.import_module(full_module_path)
                
                rule_class = getattr(module, module_name, None)
                if rule_class:
                    rule_instance = rule_class()
                    rules.append(rule_instance)
                else:
                    print(f"Класс {module_name} не найден в модуле {filename}")
                        
            except Exception as e:
                print(f"Ошибка загрузки {filename}: {e}")
                import traceback
                traceback.print_exc()
    
    return rules

__all__ = ['load_all_rules']
