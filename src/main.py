import os
import sys
import argparse
import json
from datetime import datetime
from src.lexer_parser.ruamel_parser import RuamelYAMLParser
from src.ast_model.builder import ASTBuilder, print_ast
from src.rules_engine.engine import RulesEngine
from src.rules_engine.rules import load_all_rules
from src.reports import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description='SAST-анализ плейбуков')
    parser.add_argument('playbook_path', help='Путь к YAML-файлу плейбука для анализа')
    parser.add_argument('--format', '-f', choices=['text', 'json'],
                        default='text', help='Формат отчета (по умолчанию text)')
    parser.add_argument('--output', '-o', nargs='?', const=True, default=None,
                        help='Сохранить отчет в файл')
    parser.add_argument('--no-ast', action='store_true', help='Не выводить структуру AST-дерева')

    args = parser.parse_args()

    print("🔄 Запуск SAST-анализатора", file=sys.stderr)

    parser_obj = RuamelYAMLParser()
    try:
        parsed_data = parser_obj.parse_file(args.playbook_path)
        print("✅ YAML успешно распарсен", file=sys.stderr)
    except Exception as e:
        print(f"❌ Ошибка при парсинге YAML: {str(e)}", file=sys.stderr)
        sys.exit(1)

    ast_builder = ASTBuilder()
    try:
        ast = ast_builder.build_ast(parsed_data)
        print("✅ AST успешно построен", file=sys.stderr)
    except Exception as e:
        print(f"❌ Ошибка при построении AST: {str(e)}", file=sys.stderr)
        sys.exit(1)

    if not args.no_ast:
        print("Структура AST:", file=sys.stderr)
        print_ast(ast)

    rules = load_all_rules()
    print(f"\n📋 Загружено правил: {len(rules)}", file=sys.stderr)

    engine = RulesEngine(rules)
    violations = engine.run(ast)

    save_to_file = args.output is not None
    output_file = None

    if args.output is True:
        output_file = None
    elif isinstance(args.output, str):
        output_file = args.output

    report_generator = ReportGenerator()

    if args.format == 'json':
        report = report_generator.generate_json_report(violations, output_file if save_to_file else None)
    else:
        report = report_generator.generate_text_report(violations, output_file if save_to_file else None)

    if not save_to_file:
        print(report)

if __name__ == "__main__":
    main()
