import os
import sys
from ruamel.yaml import YAML
from ruamel.yaml.composer import ComposerError
from ruamel.yaml.parser import ParserError
from ruamel.yaml.scanner import ScannerError

class RuamelYAMLParser:
    """
    Парсер YAML-файлов на основе ruamel.yaml
    """
    
    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.allow_duplicate_keys = False
    
    def parse(self, yaml_text: str):
        """
        Парсит YAML-текст и возвращает структуру данных Python
        
        :param yaml_text: Строка с YAML-содержимым
        :return: Распарсенная структура данных
        :raises: Exception при ошибках парсинга
        """
        try:
            return self.yaml.load(yaml_text)
        except (ComposerError, ParserError, ScannerError) as e:
            print(f"Ошибка парсинга YAML: {e}")
            raise
        except Exception as e:
            print(f"Неизвестная ошибка: {e}")
            raise
    
    def parse_file(self, file_path: str):
        """
        Парсит YAML-файл и возвращает структуру данных Python
        
        :param file_path: Путь к YAML-файлу
        :return: Распарсенная структура данных
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return self.yaml.load(f)
        except FileNotFoundError:
            print(f"Файл не найден: {file_path}")
            raise
        except (ComposerError, ParserError, ScannerError) as e:
            print(f"Ошибка парсинга YAML в файле {file_path}: {e}")
            raise
        except Exception as e:
            print(f"Неизвестная ошибка при чтении файла {file_path}: {e}")
            raise

def print_structure(data, indent=0):
    """
    Рекурсивно печатает структуру YAML-документа
    
    :param data: Данные для печати
    :param indent: Текущий уровень отступа
    """
    if isinstance(data, dict):
        for key, value in data.items():
            print('  ' * indent + f"{key}:")
            print_structure(value, indent + 1)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            print('  ' * indent + f"- [{i}]")
            print_structure(item, indent + 1)
    else:
        print('  ' * indent + f"{type(data).__name__}: {str(data)[:50]}{'...' if len(str(data)) > 50 else ''}")

if __name__ == "__main__":
    parser = RuamelYAMLParser()
    
    # Тестирование парсинга из файла
    try:
        result = parser.parse_file('/root/sast/test_playbook.yml')
        print("Парсинг из файла прошел успешно.")
        print("\nСтруктура данных:")
        print_structure(result)
        
        # Дополнительная информация о структуре
        print("\nДополнительная информация:")
        if isinstance(result, list) and len(result) > 0:
            first_item = result[0]
            if isinstance(first_item, dict):
                print(f"Название: {first_item.get('name', 'unnamed')}")
                print(f"Хосты: {first_item.get('hosts', 'не указаны')}")
                print(f"Количество задач: {len(first_item.get('tasks', []))}")
                
    except Exception as e:
        print(f"Ошибка при парсинге файла: {e}")
        print("\nСоздайте файл test_playbook.yml для тестирования.")
