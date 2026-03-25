"""
Модуль мониторинга файловой системы.
Обнаруживает признаки шифрования, переименования и создания ransom-записок.
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Set

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.fs_monitor")

# Расширения, которые добавляет PromptLock-подобное ПО
LOCKED_EXTENSIONS: Set[str] = {
    ".locked", ".encrypted", ".enc", ".crypted", ".crypt",
    ".promptlock", ".locky", ".wcry", ".wncry",
}

# Имена файлов-записок с требованием выкупа
RANSOM_NOTE_PATTERNS: Set[str] = {
    "readme_to_decrypt.txt",
    "how_to_decrypt.txt",
    "decrypt_instructions.txt",
    "ransom_note.txt",
    "your_files_are_encrypted.txt",
    "restore_files.txt",
    "readme.locked.txt",
    "help_decrypt.html",
}

# Расширения целевых файлов (типичные цели ransomware)
TARGETED_EXTENSIONS: Set[str] = {
    ".txt", ".docx", ".doc", ".pdf", ".jpg", ".jpeg", ".png",
    ".xlsx", ".xls", ".pptx", ".py", ".js", ".html", ".csv",
    ".sql", ".db", ".zip", ".rar", ".mp3", ".mp4",
}


class FileSystemScanner:
    """Сканер файловой системы на признаки PromptLock-подобной активности."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def scan_directory(self, target_dir: str) -> int:
        """
        Рекурсивный скан директории. Возвращает количество найденных алертов.
        """
        target = Path(target_dir)
        if not target.exists():
            logger.info("Директория не существует: %s", target_dir)
            return 0

        alerts_before = len(self.engine.alerts)

        locked_files: List[Path] = []
        ransom_notes: List[Path] = []
        orphaned_locked: List[Path] = []

        for root, dirs, files in os.walk(target):
            root_path = Path(root)
            for filename in files:
                filepath = root_path / filename
                lower_name = filename.lower()

                # 1. Проверка на зашифрованные файлы (.locked и т.д.)
                if any(lower_name.endswith(ext) for ext in LOCKED_EXTENSIONS):
                    locked_files.append(filepath)

                    # Проверяем, есть ли оригинал (если нет — признак шифрования)
                    original = filepath.with_suffix("")
                    if not original.exists():
                        orphaned_locked.append(filepath)

                # 2. Проверка на ransom-записки
                if lower_name in RANSOM_NOTE_PATTERNS:
                    ransom_notes.append(filepath)

        # Генерация алертов на основе находок
        self._analyze_locked_files(locked_files, orphaned_locked)
        self._analyze_ransom_notes(ransom_notes)
        self._check_mass_modification(target)

        return len(self.engine.alerts) - alerts_before

    def _analyze_locked_files(self, locked: List[Path], orphaned: List[Path]):
        """Анализ зашифрованных файлов."""
        if not locked:
            return

        if len(locked) >= 10:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=Severity.CRITICAL,
                description=f"Обнаружено {len(locked)} зашифрованных файлов!",
                details={"count": len(locked), "sample": [str(f) for f in locked[:5]]},
            ))
        elif len(locked) >= 3:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=Severity.HIGH,
                description=f"Обнаружено {len(locked)} файлов с подозрительным расширением.",
                details={"count": len(locked), "files": [str(f) for f in locked]},
            ))
        else:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.EXTENSION_RENAME,
                severity=Severity.MEDIUM,
                description=f"Найдены файлы с расширением .locked: {len(locked)} шт.",
                details={"files": [str(f) for f in locked]},
            ))

        if orphaned:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=Severity.HIGH,
                description=(
                    f"{len(orphaned)} зашифрованных файлов без оригиналов — "
                    "оригиналы удалены (типичное поведение ransomware)."
                ),
                details={"orphaned": [str(f) for f in orphaned[:10]]},
            ))

    def _analyze_ransom_notes(self, notes: List[Path]):
        """Анализ ransom-записок."""
        for note_path in notes:
            content = ""
            try:
                content = note_path.read_text(encoding="utf-8", errors="replace")[:2048]
            except OSError:
                pass

            # Проверяем содержимое на ключевые слова
            keywords = ["encrypt", "locked", "decrypt", "victim", "bitcoin", "ransom", "pay"]
            hits = [kw for kw in keywords if kw in content.lower()]

            severity = Severity.CRITICAL if len(hits) >= 3 else Severity.HIGH

            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.RANSOM_NOTE,
                severity=severity,
                description=f"Обнаружена записка с требованием выкупа: {note_path.name}",
                source_path=str(note_path),
                details={"keyword_hits": hits, "preview": content[:200]},
            ))

    def _check_mass_modification(self, target: Path):
        """
        Проверяет признаки массового изменения файлов за короткий промежуток.
        Если много файлов изменены почти одновременно — это подозрительно.
        """
        mtimes = []
        for root, _, files in os.walk(target):
            for f in files:
                fp = Path(root) / f
                try:
                    mtimes.append(fp.stat().st_mtime)
                except OSError:
                    continue

        if len(mtimes) < 5:
            return

        mtimes.sort()
        # Если 80%+ файлов изменены в пределах 60 секунд
        window = mtimes[-1] - mtimes[0]
        if window < 60 and len(mtimes) >= 10:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=Severity.HIGH,
                description=(
                    f"{len(mtimes)} файлов изменены в пределах {window:.0f} сек — "
                    "признак автоматического массового шифрования."
                ),
                details={"file_count": len(mtimes), "time_window_sec": round(window, 1)},
            ))
