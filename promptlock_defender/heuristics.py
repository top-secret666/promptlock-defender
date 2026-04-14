"""
Эвристический анализатор:
- Анализ энтропии файлов (обнаружение шифрования/обфускации)
- AST-анализ Python-кода (обнаружение вредоносных конструкций)
- Поведенческие цепочки (API chaining)
"""

import ast
import logging
import math
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.heuristics")

# Порог энтропии: обычный текст ~4.5, сжатый/зашифрованный ~7.5+
ENTROPY_THRESHOLD_HIGH = 7.5
ENTROPY_THRESHOLD_SUSPICIOUS = 7.1

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 МБ


# =====================================================================
# Энтропийный анализ
# =====================================================================

def calculate_entropy(data: bytes) -> float:
    """Вычисление энтропии Шеннона для байтовой последовательности."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy


class EntropyAnalyzer:
    """Анализ энтропии файлов для обнаружения зашифрованных/обфусцированных данных."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def scan_directory(self, target_dir: str) -> int:
        target = Path(target_dir)
        if not target.exists():
            return 0

        alerts_before = len(self.engine.alerts)
        high_entropy_files = []

        for root, _, files in os.walk(target):
            for filename in files:
                filepath = Path(root) / filename
                try:
                    size = filepath.stat().st_size
                    if size == 0 or size > MAX_FILE_SIZE:
                        continue
                    data = filepath.read_bytes()
                except OSError:
                    continue

                entropy = calculate_entropy(data)

                if entropy >= ENTROPY_THRESHOLD_HIGH:
                    high_entropy_files.append((filepath, entropy))
                    office_exts = {'.docx', '.pdf', '.pptx', '.xlsx', '.xls', '.odt', '.ods', '.odp', '.rtf'}
                    ext = filepath.suffix.lower()
                    if ext in office_exts:
                        sev = Severity.LOW
                    else:
                        sev = Severity.HIGH
                    self.engine.add_alert(Alert(
                        timestamp=datetime.now(),
                        category=ThreatCategory.FILE_ENCRYPTION,
                        severity=sev,
                        description=(
                            f"Высокая энтропия ({entropy:.2f}/8.0) — "
                            f"вероятно зашифрованный или обфусцированный файл."
                        ),
                        source_path=str(filepath),
                        details={"entropy": round(entropy, 3), "size": size},
                    ))
                elif entropy >= ENTROPY_THRESHOLD_SUSPICIOUS:
                    # Подозрительно только для текстовых файлов
                    if filepath.suffix.lower() in {".txt", ".py", ".lua", ".js", ".sh", ".md"}:
                        self.engine.add_alert(Alert(
                            timestamp=datetime.now(),
                            category=ThreatCategory.FILE_ENCRYPTION,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Повышенная энтропия ({entropy:.2f}/8.0) для текстового файла — "
                                f"возможна обфускация."
                            ),
                            source_path=str(filepath),
                            details={"entropy": round(entropy, 3)},
                        ))

        return len(self.engine.alerts) - alerts_before


# =====================================================================
# AST-анализ Python
# =====================================================================

# Подозрительные паттерны в AST
_DANGEROUS_MODULES = {"subprocess", "os", "shutil", "ctypes", "socket"}
_DANGEROUS_FUNCS = {
    ("os", "remove"), ("os", "unlink"), ("os", "rename"),
    ("shutil", "rmtree"), ("shutil", "move"),
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
}


class _MaliciousPatternVisitor(ast.NodeVisitor):
    """AST visitor для обнаружения подозрительных конструкций в Python-коде."""

    def __init__(self):
        self.findings: List[Tuple[str, int, str]] = []  # (category, lineno, description)
        self._imports: Set[str] = set()
        self._file_opens: List[int] = []
        self._file_removes: List[int] = []
        self._subprocess_calls: List[int] = []
        self._exec_eval: List[int] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._imports.add(alias.name.split(".")[0])
            if alias.name.split(".")[0] in _DANGEROUS_MODULES:
                self.findings.append((
                    "dangerous_import", node.lineno,
                    f"Импорт опасного модуля: {alias.name}"
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            base = node.module.split(".")[0]
            self._imports.add(base)
            if base in _DANGEROUS_MODULES:
                self.findings.append((
                    "dangerous_import", node.lineno,
                    f"Импорт из опасного модуля: {node.module}"
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # os.remove, subprocess.run и т.д.
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                if pair in _DANGEROUS_FUNCS:
                    self.findings.append((
                        "dangerous_call", node.lineno,
                        f"Вызов {pair[0]}.{pair[1]}()"
                    ))
                if pair == ("os", "remove") or pair == ("os", "unlink"):
                    self._file_removes.append(node.lineno)
                if pair[0] == "subprocess":
                    self._subprocess_calls.append(node.lineno)

            # io.open / open (файловые операции)
            if node.func.attr == "open":
                self._file_opens.append(node.lineno)

        # Встроенные вызовы
        if isinstance(node.func, ast.Name):
            if node.func.id == "open":
                self._file_opens.append(node.lineno)
            if node.func.id in ("exec", "eval", "compile"):
                self._exec_eval.append(node.lineno)
                self.findings.append((
                    "dynamic_exec", node.lineno,
                    f"Динамическое выполнение кода: {node.func.id}()"
                ))

        # requests.post к LLM
        if isinstance(node.func, ast.Attribute) and node.func.attr == "post":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                # Проверяем аргументы на LLM URL
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if "11434" in arg.value or "api/generate" in arg.value:
                            self.findings.append((
                                "llm_request", node.lineno,
                                f"HTTP-запрос к LLM API: {arg.value}"
                            ))

        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Обнаружение циклов по директориям (os.walk, os.listdir, glob)."""
        if isinstance(node.iter, ast.Call):
            if isinstance(node.iter.func, ast.Attribute):
                if node.iter.func.attr in ("walk", "listdir", "scandir", "glob", "rglob"):
                    self.findings.append((
                        "dir_traversal", node.lineno,
                        f"Обход директории: {node.iter.func.attr}()"
                    ))
        self.generic_visit(node)

    def get_chain_alerts(self) -> List[Tuple[str, str]]:
        """Обнаружение поведенческих цепочек (API chaining)."""
        chains = []

        # Цепочка: открытие файла + удаление оригинала = ransomware-паттерн
        if self._file_opens and self._file_removes:
            chains.append((
                "ransomware_chain",
                f"Обнаружена цепочка: открытие файлов (строки {self._file_opens[:3]}) "
                f"→ удаление оригиналов (строки {self._file_removes[:3]})"
            ))

        # Цепочка: subprocess + file_remove = выполнение внешнего кода
        if self._subprocess_calls and self._file_removes:
            chains.append((
                "exec_and_destroy",
                f"Цепочка: запуск подпроцесса (строки {self._subprocess_calls[:3]}) "
                f"+ удаление файлов (строки {self._file_removes[:3]})"
            ))

        # Цепочка: exec/eval + imports = динамическое выполнение
        if self._exec_eval and "requests" in self._imports:
            chains.append((
                "dynamic_remote_exec",
                "Цепочка: динамическое выполнение кода + HTTP-запросы (загрузка и выполнение)"
            ))

        return chains


class ASTAnalyzer:
    """AST-анализ Python-файлов для обнаружения вредоносных паттернов."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def scan_directory(self, target_dir: str) -> int:
        target = Path(target_dir)
        if not target.exists():
            return 0

        alerts_before = len(self.engine.alerts)

        for root, _, files in os.walk(target):
            for filename in files:
                if filename.endswith(".py"):
                    filepath = Path(root) / filename
                    self._analyze_file(filepath)

        return len(self.engine.alerts) - alerts_before

    def analyze_file(self, filepath: str) -> int:
        alerts_before = len(self.engine.alerts)
        self._analyze_file(Path(filepath))
        return len(self.engine.alerts) - alerts_before

    def _analyze_file(self, filepath: Path):
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            return

        visitor = _MaliciousPatternVisitor()
        visitor.visit(tree)

        fstr = str(filepath)

        # Отдельные находки
        if len(visitor.findings) >= 5:
            severity = Severity.HIGH
        elif len(visitor.findings) >= 2:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        if visitor.findings:
            sample = [f"  L{ln}: {desc}" for cat, ln, desc in visitor.findings[:8]]
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=severity,
                description=(
                    f"AST-анализ: {len(visitor.findings)} подозрительных конструкций."
                ),
                source_path=fstr,
                details={
                    "findings": [
                        {"category": c, "line": ln, "desc": d}
                        for c, ln, d in visitor.findings
                    ],
                    "summary": "\n".join(sample),
                },
            ))

        # Поведенческие цепочки
        chains = visitor.get_chain_alerts()
        for chain_type, description in chains:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.CRITICAL if "ransomware" in chain_type else Severity.HIGH,
                description=f"ЦЕПОЧКА API: {description}",
                source_path=fstr,
                details={"chain_type": chain_type},
            ))
