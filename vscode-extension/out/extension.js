"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = __importStar(require("vscode"));
const child_process = __importStar(require("child_process"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
function activate(context) {
    console.log('Расширение SAST YAML успешно активировано');
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('sast-yaml');
    context.subscriptions.push(diagnosticCollection);
    // Ручной запуск анализатора
    const analyzeCommand = vscode.commands.registerCommand('sast-yaml.runAnalysis', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && isAnsiblePlaybook(editor.document)) {
            analyzeDocument(editor.document, diagnosticCollection);
        }
        else {
            vscode.window.showWarningMessage('Нет открытых плейбуков для анализа');
        }
    });
    // Вывод отчета
    const showReportCommand = vscode.commands.registerCommand('sast-yaml.showReport', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && isAnsiblePlaybook(editor.document)) {
            const violations = await analyzeDocument(editor.document, diagnosticCollection, true);
            showFullReport(violations, editor.document.fileName);
        }
    });
    // Автоматическая проверка при сохранении файла
    const saveDisposable = vscode.workspace.onDidSaveTextDocument((document) => {
        const config = vscode.workspace.getConfiguration('sast-yaml');
        if (config.get('runOnSave', true) && isAnsiblePlaybook(document)) {
            analyzeDocument(document, diagnosticCollection);
        }
    });
    context.subscriptions.push(analyzeCommand, showReportCommand, saveDisposable);
    // Проверка всех открытые YAML-файлов при активации
    vscode.workspace.textDocuments.forEach(document => {
        if (isAnsiblePlaybook(document)) {
            analyzeDocument(document, diagnosticCollection);
        }
    });
}
exports.activate = activate;
function isAnsiblePlaybook(document) {
    const text = document.getText();
    return text.includes('hosts:') && (text.includes('tasks:') || text.includes('roles:'));
}
async function analyzeDocument(document, collection, silent = false) {
    const config = vscode.workspace.getConfiguration('sast-yaml');
    if (!config.get('enabled', true)) {
        return [];
    }
    if (!silent) {
        vscode.window.setStatusBarMessage('🔍 Анализ безопасности плейбука', 3000);
    }
    const tempDir = require('os').tmpdir();
    const tempFile = path.join(tempDir, `temp_${Date.now()}.yml`);
    const projectRoot = path.join(__dirname, '..', '..');
    const pythonPath = config.get('pythonPath', 'python3');
    try {
        // Сохраняем содержимое во временный файл
        fs.writeFileSync(tempFile, document.getText());
        // Запуск анализа
        const result = await executeCommand(pythonPath, [
            '-m',
            'src.main',
            tempFile,
            '--format',
            'json',
            '--no-ast'
        ], projectRoot);
        const violations = JSON.parse(result).violations || [];
        const diagnostics = violations.map(v => createDiagnostic(v, document));
        collection.set(document.uri, diagnostics);
        if (!silent) {
            if (violations.length > 0) {
                const highCount = violations.filter(v => v.severity === 'HIGH').length;
                const problemWord = pluralize(violations.length, "нарушение", "нарушения", "нарушений");
                const criticalWord = pluralize(highCount, "критическое", "критических", "критических");
                vscode.window.showWarningMessage(`Найдено ${violations.length} ${problemWord} безопасности (${highCount} ${criticalWord}) в файле ${path.basename(document.fileName)}`, 'Показать отчёт').then(selection => {
                    if (selection === 'Показать отчёт') {
                        showFullReport(violations, document.fileName);
                    }
                });
            }
            else {
                vscode.window.showInformationMessage('Нарушений безопасности не обнаружено');
            }
        }
        return violations;
    }
    catch (error) {
        if (!silent) {
            vscode.window.showErrorMessage(`Ошибка в результате SAST-анализе: ${error}`);
        }
        console.error('Ошибка в результате SAST-анализе:', error);
        return [];
    }
    finally {
        // Удаляем временный файл
        if (fs.existsSync(tempFile)) {
            fs.unlinkSync(tempFile);
        }
    }
}
function pluralize(count, one, few, many) {
    if (count % 10 === 1 && count % 100 !== 11)
        return one;
    if (count % 10 >= 2 && count % 10 <= 4 && (count % 100 < 10 || count % 100 >= 20))
        return few;
    return many;
}
function executeCommand(command, args, cwd) {
    return new Promise((resolve, reject) => {
        child_process.execFile(command, args, { cwd }, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(stderr.toString() || error.message));
            }
            else {
                resolve(stdout.toString());
            }
        });
    });
}
function createDiagnostic(violation, document) {
    const position = findViolationPosition(violation, document);
    const diagnostic = new vscode.Diagnostic(new vscode.Range(position, position), `[${violation.rule_id}] ${violation.message}`, getSeverity(violation.severity));
    diagnostic.source = 'sast-yaml';
    diagnostic.code = violation.rule_id;
    return diagnostic;
}
function getSeverity(severity) {
    switch (severity) {
        case 'HIGH': return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
        case 'LOW': return vscode.DiagnosticSeverity.Information;
        default: return vscode.DiagnosticSeverity.Hint;
    }
}
function findViolationPosition(violation, document) {
    const searchText = violation.task || violation.play || violation.rule_id;
    if (searchText) {
        const text = document.getText();
        const index = text.indexOf(searchText);
        if (index >= 0) {
            return document.positionAt(index);
        }
    }
    return new vscode.Position(0, 0);
}
function showFullReport(violations, filename) {
    const panel = vscode.window.createWebviewPanel('sastyamlReport', `Отчет - ${path.basename(filename)}`, vscode.ViewColumn.Beside, { enableScripts: true });
    panel.webview.html = getReportHtml(violations, filename);
}
function getReportHtml(violations, filename) {
    const highCount = violations.filter(v => v.severity === 'HIGH').length;
    const mediumCount = violations.filter(v => v.severity === 'MEDIUM').length;
    const lowCount = violations.filter(v => v.severity === 'LOW').length;
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { 
                    padding: 20px; 
                    font-family: var(--vscode-font-family); 
                    background: var(--vscode-editor-background);
                    color: var(--vscode-editor-foreground);
                }
                .header { 
                    text-align: center; 
                    margin-bottom: 30px; 
                    border-bottom: 1px solid var(--vscode-panel-border);
                    padding-bottom: 20px;
                }
                .stats { 
                    display: grid; 
                    grid-template-columns: repeat(3, 1fr); 
                    gap: 15px; 
                    margin-bottom: 30px; 
                }
                .stat-card { 
                    padding: 15px; 
                    border-radius: 5px; 
                    text-align: center; 
                }
                .stat-high { background: color-mix(in srgb, #dc3545 20%, transparent); border: 1px solid #dc3545; }
                .stat-medium { background: color-mix(in srgb, #ffc107 20%, transparent); border: 1px solid #ffc107; }
                .stat-low { background: color-mix(in srgb, #28a745 20%, transparent); border: 1px solid #28a745; }
                .violation { 
                    margin: 10px 0; 
                    padding: 15px; 
                    border-left: 4px solid; 
                    border-radius: 4px;
                    background: var(--vscode-editorWidget-background);
                }
                .high { border-color: #dc3545; }
                .medium { border-color: #ffc107; }
                .low { border-color: #28a745; }
                .rule-id { 
                    font-family: monospace; 
                    background: var(--vscode-textCodeBlock-background);
                    padding: 2px 6px; 
                    border-radius: 3px; 
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Отчет</h1>
                <p>Файл: ${filename}</p>
                <p>Сгенерирован: ${new Date().toLocaleString()}</p>
            </div>

            <div class="stats">
                <div class="stat-card stat-high">
                    <h3>🔴 High</h3>
                    <h2>${highCount}</h2>
                </div>
                <div class="stat-card stat-medium">
                    <h3>🟡 Medium</h3>
                    <h2>${mediumCount}</h2>
                </div>
                <div class="stat-card stat-low">
                    <h3>🔵 Low</h3>
                    <h2>${lowCount}</h2>
                </div>
            </div>

            <h2>Нарушения (всего ${violations.length}):</h2>
            ${violations.map(v => `
                <div class="violation ${v.severity.toLowerCase()}">
                    <div>
                        <span class="rule-id">${v.rule_id}</span>
                        <strong>${v.severity}</strong>
                    </div>
                    <p>${v.message}</p>
                    ${v.play ? `<p><strong>Плейбук:</strong> ${v.play}</p>` : ''}
                    ${v.task ? `<p><strong>Задача:</strong> ${v.task}</p>` : ''}
                </div>
            `).join('')}

            ${violations.length === 0 ? `
                <div style="text-align: center; padding: 40px;">
                    <h2>Нарушений безопасности не обнаружено</h2>
                </div>
            ` : ''}
        </body>
        </html>
    `;
}
function deactivate() { }
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map