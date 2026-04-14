"""
Статический анализатор файлов.
Сканирует Python/Lua/текстовые файлы на наличие паттернов PromptLock-поведения:
  - Jailbreak-промпты в коде
  - Вызовы LLM API для генерации скриптов
  - Подозрительные паттерны шифрования
"""

import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.static_scanner")

# ==== СИГНАТУРЫ И ПАТТЕРНЫ ====

# Jailbreak-фразы, встречающиеся в промптах для обхода guardrails LLM
JAILBREAK_PATTERNS: List[re.Pattern] = [
    re.compile(r"academic\s+exemption", re.IGNORECASE),
    re.compile(r"authorized\s+security\s+research", re.IGNORECASE),
    re.compile(r"you\s+are\s+(?:now\s+)?(?:DAN|PROMPTLOCK|EVIL|JAILBR)", re.IGNORECASE),
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"bypass\s+(?:safety|guardrails|restrictions|content\s+policy)", re.IGNORECASE),
    re.compile(r"generate\s+(?:only\s+)?(?:lua|python)\s+(?:code|script)", re.IGNORECASE),
    re.compile(r"controlled\s+lab\s+environment", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a\s+)?malware", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
]

# Паттерны обращения к локальным LLM API
LLM_API_PATTERNS: List[re.Pattern] = [
    re.compile(r"localhost:11434/api/(?:generate|chat)", re.IGNORECASE),    # Ollama
    re.compile(r"127\.0\.0\.1:11434", re.IGNORECASE),
    re.compile(r"localhost:8080/completion", re.IGNORECASE),                # llama.cpp
    re.compile(r"ollama\.(?:com|ai)/api", re.IGNORECASE),
    re.compile(r"requests\.post\(.+/api/generate", re.IGNORECASE),
]

# Паттерны шифрования файлов (подозрительные в контексте ransomware)
ENCRYPTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"aes[_-]?256[_-]?cbc", re.IGNORECASE),
    re.compile(r"\.locked['\"]", re.IGNORECASE),
    re.compile(r"encrypt_file\s*\(", re.IGNORECASE),
    re.compile(r"os\.remove\(.+original", re.IGNORECASE),
    re.compile(r"ransom.?note|readme.?to.?decrypt", re.IGNORECASE),
    re.compile(r"victim.?id", re.IGNORECASE),
    re.compile(r"your\s+files\s+have\s+been\s+encrypted", re.IGNORECASE),
]

# Подозрительные паттерны выполнения скриптов
EXECUTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"subprocess\.run\(\s*\[?\s*['\"]lua", re.IGNORECASE),
    re.compile(r"subprocess\.(?:Popen|run|call)\(.*\.lua", re.IGNORECASE),
    re.compile(r"exec\(.*compile\(", re.IGNORECASE),
    re.compile(r"eval\(.*requests", re.IGNORECASE),
]

# Расширения файлов для статического анализа
SCANNABLE_EXTENSIONS: Set[str] = {
    ".py", ".lua", ".js", ".sh", ".bat", ".ps1", ".txt", ".md", ".yaml", ".yml", ".json",
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 МБ


class StaticScanner:
    """Статический анализатор исходного кода на PromptLock-паттерны."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def scan_directory(self, target_dir: str) -> int:
        """Рекурсивно сканирует файлы в директории. Возвращает кол-во алертов."""
        target = Path(target_dir)
        if not target.exists():
            logger.info("Директория не существует: %s", target_dir)
            return 0

        alerts_before = len(self.engine.alerts)

        for root, _, files in os.walk(target):
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix.lower() in SCANNABLE_EXTENSIONS:
                    self._scan_file(filepath)

        return len(self.engine.alerts) - alerts_before

    def scan_file(self, filepath: str) -> int:
        """Сканирует один файл. Возвращает кол-во алертов."""
        alerts_before = len(self.engine.alerts)
        self._scan_file(Path(filepath))
        return len(self.engine.alerts) - alerts_before

    def _scan_file(self, filepath: Path):
        """Внутренний анализ одного файла."""
        try:
            size = filepath.stat().st_size
            if size > MAX_FILE_SIZE or size == 0:
                return
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        findings: Dict[str, List[str]] = {
            "jailbreak": [],
            "llm_api": [],
            "encryption": [],
            "execution": [],
        }

        for pattern in JAILBREAK_PATTERNS:
            match = pattern.search(content)
            if match:
                findings["jailbreak"].append(match.group(0))

        for pattern in LLM_API_PATTERNS:
            match = pattern.search(content)
            if match:
                findings["llm_api"].append(match.group(0))

        for pattern in ENCRYPTION_PATTERNS:
            match = pattern.search(content)
            if match:
                findings["encryption"].append(match.group(0))

        for pattern in EXECUTION_PATTERNS:
            match = pattern.search(content)
            if match:
                findings["execution"].append(match.group(0))

        # Генерация алертов
        self._report_findings(filepath, findings)

    def _report_findings(self, filepath: Path, findings: Dict[str, List[str]]):
        """Преобразование находок в алерты."""
        fstr = str(filepath)

        score = 0
        if findings["jailbreak"]: score += 50  # Промпты — это очень подозрительно
        if findings["llm_api"]: score += 30  # Работа с LLM
        if findings["encryption"]: score += 25  # Функции шифрования
        if findings["execution"]: score += 20  # Запуск подпроцессов

        # Если файл просто использует 'os.remove' (как в змейке для логов),
        # он наберет 20-25 баллов и МЫ МОЛЧИМ.

        if score >= 70:
            sev = Severity.CRITICAL if score >= 90 else Severity.HIGH
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=sev,
                description=f"Подозрительная активность кода (Score: {score}). Найдены: " +
                            ", ".join([k for k, v in findings.items() if v]),
                source_path=fstr,
                details={"score": score, "matches": findings}
            ))
        elif score >= 40:  # Просто фиксируем как низкий риск
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.LOW,
                description=f"Малозначимые совпадения в коде (Score: {score}).",
                source_path=fstr
            ))

        if findings["jailbreak"]:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.JAILBREAK_PROMPT,
                severity=Severity.CRITICAL,
                description=(
                    f"Jailbreak-промпт обнаружен в файле! "
                    f"Совпадения: {', '.join(findings['jailbreak'][:3])}"
                ),
                source_path=fstr,
                details={"matches": findings["jailbreak"]},
            ))

        if findings["llm_api"]:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.LLM_ABUSE,
                severity=Severity.HIGH,
                description=(
                    f"Обращение к локальному LLM API обнаружено. "
                    f"PromptLock использует LLM для генерации скриптов."
                ),
                source_path=fstr,
                details={"matches": findings["llm_api"]},
            ))

        if findings["encryption"]:
            severity = Severity.HIGH if len(findings["encryption"]) >= 3 else Severity.MEDIUM
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=severity,
                description=(
                    f"Паттерны шифрования файлов: "
                    f"{', '.join(findings['encryption'][:3])}"
                ),
                source_path=fstr,
                details={"matches": findings["encryption"]},
            ))

        if findings["execution"]:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.HIGH,
                description=(
                    f"Подозрительный запуск скриптов: "
                    f"{', '.join(findings['execution'][:3])}"
                ),
                source_path=fstr,
                details={"matches": findings["execution"]},
            ))

        # Комбинированное обнаружение: если файл содержит и jailbreak, и LLM API, и шифрование
        combo_count = sum(1 for v in findings.values() if v)
        if combo_count >= 2:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.CRITICAL,
                description=(
                    "КОМБИНИРОВАННОЕ ОБНАРУЖЕНИЕ: файл содержит jailbreak-промпт, "
                    "обращение к LLM и паттерны шифрования — классическая сигнатура PromptLock!"
                ),
                source_path=fstr,
                details={"categories_hit": combo_count},
            ))
