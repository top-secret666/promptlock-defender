"""
Анализатор бинарных файлов (ELF / PE / EXE).
Целевой сканер ТОЛЬКО на PromptLock — НЕ ругается на обычные программы.

Логика обнаружения:
  1. SHA256 совпадение с базой известных образцов → CRITICAL
  2. Строка "promptlock" внутри бинарника → CRITICAL
  3. КОМБИНАЦИЯ специфичных маркеров (минимум 2 из 3 категорий) → HIGH
  4. Одиночные маркеры НЕ генерируют алерт (чтобы не ругаться на игры/браузеры)

Что НЕ вызывает алерт (в отличие от прошлой версии):
  - Просто openssl/libcrypto в exe (есть в любой программе с HTTPS)
  - Просто высокая энтропия (у игр всегда высокая из-за ресурсов)
  - Просто строка ".locked" (используется для file locking повсеместно)
  - Просто aes-256 (нормальное шифрование)
  - Просто lua/luajit (используется в играх повсюду)
"""

import hashlib
import logging
import math
import os
import re
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.binary_scanner")

# ── Известные хэши PromptLock (из MalwareBazaar, публичные данные) ────

KNOWN_PROMPTLOCK_HASHES: Set[str] = {
    "b43e7d481c4fdc9217e17",
    "1612ab799df51a7f1169d",
    "09bf891b7b35b2081d3e",
    "7bbb06479a2e554e450b",
    "e24fe0dd0bf8d3943d9c4",
    "1458b6dc98a878f237bfb",
    "2755e1ec1e4c3c0cd94eb",
}

# ── Паттерны по категориям ──
# Алерт ТОЛЬКО при совпадении 2+ категорий или прямом маркере "promptlock".
# Одиночная категория = НЕТ алерта (слишком общие строки).

# Категория A: Прямые маркеры PromptLock (одного хватит для CRITICAL)
PROMPTLOCK_DIRECT: List[re.Pattern] = [
    re.compile(rb"promptlock", re.IGNORECASE),
]

# Категория B: Ransomware-записки и строки (НЕ общие крипто-библиотеки)
RANSOM_MARKERS: List[re.Pattern] = [
    re.compile(rb"README_TO_DECRYPT", re.IGNORECASE),
    re.compile(rb"HOW_TO_DECRYPT", re.IGNORECASE),
    re.compile(rb"your\s+files\s+have\s+been\s+encrypted", re.IGNORECASE),
    re.compile(rb"ransom[\x00-\x20_-]?note", re.IGNORECASE),
    re.compile(rb"encrypt_file\s*\(", re.IGNORECASE),
]

# Категория C: LLM/Ollama API (специфика AI-ransomware)
LLM_MARKERS: List[re.Pattern] = [
    re.compile(rb"localhost:11434/api/(?:generate|chat)"),
    re.compile(rb"127\.0\.0\.1:11434"),
    re.compile(rb"ollama[./]", re.IGNORECASE),
    re.compile(rb"jailbreak[\x00-\x20_-]?prompt", re.IGNORECASE),
    re.compile(rb"bypass[\x00-\x20_-]?(?:safety|guardrail)", re.IGNORECASE),
]

# Категория D: LuaFileSystem (PromptLock ходит по FS через Lua)
LUA_CRYPTO_MARKERS: List[re.Pattern] = [
    re.compile(rb"lfs\.dir|lfs\.attributes"),  # LuaFileSystem API
]

MAX_BINARY_SIZE = 50 * 1024 * 1024  # 50 MB


class BinaryScanner:
    """Целевой анализатор бинарников на PromptLock.

    НЕ ругается на обычные программы. Алерт только при:
    - Совпадении SHA256 с базой
    - Прямой строке "promptlock" в бинарнике
    - Комбинации 2+ специфичных категорий маркеров
    """

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def scan_directory(self, target_dir: str) -> int:
        """Рекурсивно сканирует бинарные файлы. Возвращает кол-во алертов."""
        target = Path(target_dir)
        if not target.exists():
            return 0

        alerts_before = len(self.engine.alerts)

        for root, _, files in os.walk(target):
            for filename in files:
                filepath = Path(root) / filename
                if self._is_binary_candidate(filepath):
                    self._scan_file(filepath)

        return len(self.engine.alerts) - alerts_before

    def scan_file(self, filepath: str) -> int:
        """Сканирует один файл."""
        alerts_before = len(self.engine.alerts)
        self._scan_file(Path(filepath))
        return len(self.engine.alerts) - alerts_before

    def _is_binary_candidate(self, filepath: Path) -> bool:
        """Проверяет, стоит ли анализировать файл."""
        ext = filepath.suffix.lower()
        if ext in {".exe", ".elf", ".bin", ".scr", ".out"}:
            return True

        # Файлы без расширения — проверяем magic bytes
        if not ext:
            try:
                with open(filepath, "rb") as f:
                    magic = f.read(4)
                    return magic == b"\x7fELF" or magic[:2] == b"MZ"
            except OSError:
                pass

        return False

    def _scan_file(self, filepath: Path):
        """Анализ одного бинарного файла."""
        try:
            size = filepath.stat().st_size
            if size > MAX_BINARY_SIZE or size == 0:
                return
        except OSError:
            return

        try:
            data = filepath.read_bytes()
        except OSError:
            return

        fstr = str(filepath)
        file_type = self._detect_type(data)
        sha256 = hashlib.sha256(data).hexdigest()

        # Шаг 1: проверка по базе хэшей (однозначное совпадение)
        if self._check_known_hash(sha256, fstr, file_type):
            return

        # Шаг 2: поиск строковых маркеров по категориям
        cats = self._match_categories(data)

        # Шаг 3: принятие решения — алерт только при веских основаниях
        self._evaluate(fstr, file_type, sha256, cats)

    def _detect_type(self, data: bytes) -> str:
        if len(data) < 4:
            return "unknown"
        if data[:4] == b"\x7fELF":
            return "ELF"
        if data[:2] == b"MZ":
            if len(data) > 0x3C + 4:
                pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
                if pe_offset < len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                    return "PE/EXE"
            return "MZ/DOS"
        return "unknown"

    def _check_known_hash(self, sha256: str, filepath: str, file_type: str) -> bool:
        """Проверка по базе. Возвращает True если найден."""
        for known in KNOWN_PROMPTLOCK_HASHES:
            if sha256.startswith(known) or known in sha256:
                self.engine.add_alert(Alert(
                    timestamp=datetime.now(),
                    category=ThreatCategory.SUSPICIOUS_SCRIPT,
                    severity=Severity.CRITICAL,
                    description=(
                        f"СОВПАДЕНИЕ ХЭША с известным PromptLock образцом! "
                        f"SHA256: {sha256[:16]}... [{file_type}]"
                    ),
                    source_path=filepath,
                    details={"sha256": sha256, "file_type": file_type, "matched_prefix": known},
                ))
                return True
        return False

    def _match_categories(self, data: bytes) -> Dict[str, List[str]]:
        """Ищет маркеры по категориям."""
        result: Dict[str, List[str]] = {
            "promptlock": [],
            "ransom": [],
            "llm": [],
            "lua_crypto": [],
        }

        for pat in PROMPTLOCK_DIRECT:
            for m in pat.finditer(data):
                result["promptlock"].append(m.group(0).decode("utf-8", errors="replace"))

        for pat in RANSOM_MARKERS:
            for m in pat.finditer(data):
                result["ransom"].append(m.group(0).decode("utf-8", errors="replace"))

        for pat in LLM_MARKERS:
            for m in pat.finditer(data):
                result["llm"].append(m.group(0).decode("utf-8", errors="replace"))

        for pat in LUA_CRYPTO_MARKERS:
            for m in pat.finditer(data):
                result["lua_crypto"].append(m.group(0).decode("utf-8", errors="replace"))

        return result

    def _evaluate(self, filepath: str, file_type: str, sha256: str,
                  cats: Dict[str, List[str]]):
        """Решение: алерт или нет.

        - "promptlock" в бинарнике → CRITICAL
        - 2+ категории из {ransom, llm, lua_crypto} → HIGH
        - 1 или 0 категорий → НЕТ АЛЕРТА (обычная программа)
        """

        # Прямое упоминание PromptLock — однозначно
        if cats["promptlock"]:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.CRITICAL,
                description=(
                    f"Бинарник [{file_type}] содержит строку 'PromptLock'! "
                    f"SHA256: {sha256[:16]}..."
                ),
                source_path=filepath,
                details={"matches": cats["promptlock"][:5], "sha256": sha256},
            ))
            return

        # Считаем сколько СПЕЦИФИЧНЫХ категорий совпали
        specific_cats = {k: v for k, v in cats.items() if k != "promptlock" and v}
        hit_count = len(specific_cats)

        if hit_count >= 2:
            all_matches = []
            for matches in specific_cats.values():
                all_matches.extend(matches[:3])

            severity = Severity.CRITICAL if hit_count >= 3 else Severity.HIGH
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=severity,
                description=(
                    f"Бинарник [{file_type}] содержит {hit_count}/3 категорий "
                    f"маркеров PromptLock: {', '.join(specific_cats.keys())} "
                    f"SHA256: {sha256[:16]}..."
                ),
                source_path=filepath,
                details={
                    "sha256": sha256,
                    "categories": list(specific_cats.keys()),
                    "sample_matches": all_matches[:10],
                },
            ))

        # hit_count < 2 → НЕТ АЛЕРТА
        # openssl, aes, lua, .locked по отдельности = нормальная программа
