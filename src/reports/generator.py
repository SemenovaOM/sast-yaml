import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

class ReportGenerator:
    @staticmethod

    # Генерация пути для сохранения отчета
    def _get_output_path(output_file: Optional[str], format: str) -> str:
        if output_file:
            if os.path.isabs(output_file):
                return output_file
            return os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports', output_file)
        
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
        os.makedirs(reports_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"report_{timestamp}.{format}"
        return os.path.join(reports_dir, filename)

    @staticmethod

    # JSON-отчет
    def generate_json_report(violations: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "analyzer_version": "1.0.0",
                "report_format": "json",
                "total_violations": len(violations)
            },
            "summary": {
                "by_severity": {
                    "HIGH": 0,
                    "MEDIUM": 0, 
                    "LOW": 0
                },
                "by_rule": {}
            },
            "violations": violations
        }
        
        for violation in violations:
            report["summary"]["by_severity"][violation["severity"]] += 1
            
            rule_id = violation["rule_id"]
            if rule_id not in report["summary"]["by_rule"]:
                report["summary"]["by_rule"][rule_id] = {
                    "count": 0,
                    "description": violation.get("description", ""),
                    "severity": violation["severity"]
                }
            report["summary"]["by_rule"][rule_id]["count"] += 1
        
        report_json = json.dumps(report, ensure_ascii=False, indent=2, default=str)
        
        if output_file is not None:
            output_path = ReportGenerator._get_output_path(output_file, 'json')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_json)
            print(f"📄 JSON отчет сохранен: {output_path}")
        
        return report_json

    @staticmethod

    # Отчет в консоли
    def generate_text_report(violations, output_file=None):
        report_lines = []

        if violations:
            report_lines.append("\n🔍 РЕЗУЛЬТАТЫ SAST-АНАЛИЗА")

            by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for v in violations:
                by_severity[v['severity']].append(v)

            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                if by_severity[severity]:
                    report_lines.append(f"\n🔴 {severity} ({len(by_severity[severity])}):")
                    for violation in by_severity[severity]:
                        report_lines.append(f"   ⚡ {violation['rule_id']}: {violation['message']}")

        else:
            report_lines.append("\n✅ Нарушений не обнаружено!\n")

        report_lines.append(f"\nВсего нарушений: {len(violations)}")
        
        report_text = "\n".join(report_lines)

        if output_file is not None:
            output_path = ReportGenerator._get_output_path(output_file, 'txt')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"📄 Текстовый отчет сохранен: {output_path}")
        
        return report_text

