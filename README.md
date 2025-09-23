# Статический анализатор уязвимостей в инфраструктурном коде
Статический анализатор выявляет потенциальные уязвимости и антипаттерны в плебуках Ansible.

## Возможности анализатора
- Статический анализ YAML-файлов без выполнения кода
- Построение AST (Abstract Syntax Tree) для глубокого анализа
- Расширяемая система правил с поддержкой пользовательских правил
- Вывод отчета в разных форматах
- Интеграция с VSCode через плагин

## Установка анализатора
### Требования
- Python 3.8+
- pip
- ruamel.yaml

### Активация виртуального окружения и установка зависимости
```bash
python -m venv venv
source venv/bin/activate
pip install ruamel.yaml
```

## Запуск анализатора
### Анализ плейбука test_playbook.yml с выводом текстового отчета в терминал
```bash
# с выводом AST-дерева
python -m src.main tests/test_playbook.yml
# без вывода AST-дерева
python -m src.main tests/test_playbook.yml --no-ast
```

### Анализ плейбука test_playbook.yml с выводом текстового отчета в файл
```bash
# с автоименем файла
python -m src.main tests/test_playbook.yml --format text --output
# с указанием имени файла
python -m src.main tests/test_playbook.yml --format text --output report.txt
```

### Анализ плейбука test_playbook.yml с выводом JSON-отчета в терминал
```bash
# с выводом AST-дерева
python -m src.main tests/test_playbook.yml --format json
# без вывода AST-дерева
python -m src.main tests/test_playbook.yml --format json --no-ast
```

### Анализ плейбука test_playbook.yml с выводом JSON-отчета в файл
```bash
# с выводом AST-дерева
python -m src.main tests/test_playbook.yml --format json --output
# без вывода AST-дерева
python -m src.main tests/test_playbook.yml --format json --output report.json
```

## Расширение анализатора
### Структуры проекта
```text
sast-yaml/
├── src/                   # Исходный код анализатора
│   ├── ast_model/         # Модель AST-дерева
│   ├── lexer_parser/      # Парсер YAML-файлов
│   ├── reports/           # Генератор отчетов
│   └── rules_engine/      # Движок правил анализа
├── tests/                 # Тестовые плейбуки
├── vscode-extension/      # Плагин для VSCode
└── venv/                  # Виртуальное окружение
```

### Добавление нового правила
1. Создайте файл в src/rules_engine/rules/ с префиксом ANSXXX.py
2. Реализуйте класc, наследующий от Rule
3. Зарегистрируйте правило в системе

## Поддержка
По вопросам использования и разработки обращайтесь к автору проекта.

Примечание: Анализатор предназначен для выявления потенциальных проблем. Все найденные нарушения должны быть проверены вручную перед принятием решений о исправлениях.

