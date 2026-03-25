"""
Песочница для динамического анализа подозрительных файлов.
Запускает файл в изолированной среде (Docker) и отслеживает поведение.
"""

import logging
import os
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.sandbox")

# Dockerfile для изолированного запуска Python-скриптов
_DOCKERFILE_CONTENT = """\
FROM python:3.11-slim
RUN useradd -m sandbox && apt-get update && apt-get install -y strace --no-install-recommends && rm -rf /var/lib/apt/lists/*
WORKDIR /sandbox
COPY target_script.py .
USER sandbox
ENTRYPOINT ["strace", "-f", "-e", "trace=open,openat,unlink,rename,connect,socket", "-o", "/tmp/trace.log", "python3", "target_script.py"]
"""


class Sandbox:
    """
    Динамический анализ подозрительных файлов в Docker-контейнере.
    Записывает системные вызовы через strace и анализирует поведение.
    """

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.system = platform.system()
        self._docker_available: Optional[bool] = None

    def is_available(self) -> bool:
        """Проверка доступности Docker."""
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, text=True, timeout=10,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False
        return self._docker_available

    def analyze_file(self, filepath: str, timeout: int = 30) -> Dict:
        """
        Анализ файла в песочнице.
        Возвращает словарь с результатами: syscalls, network, file_ops и т.д.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            return {"error": "Файл не найден"}

        if not filepath.suffix == ".py":
            return {"error": "Песочница поддерживает только .py файлы"}

        if not self.is_available():
            logger.warning("Docker недоступен — используем упрощённый анализ.")
            return self._fallback_analysis(filepath)

        return self._docker_analysis(filepath, timeout)

    def _docker_analysis(self, filepath: Path, timeout: int) -> Dict:
        """Запуск в Docker с strace."""
        results: Dict = {
            "file_ops": [], "network": [], "suspicious": [],
            "exit_code": None, "timed_out": False,
        }

        with tempfile.TemporaryDirectory(prefix="pldefender_") as tmpdir:
            tmppath = Path(tmpdir)

            # Копируем файл
            shutil.copy2(filepath, tmppath / "target_script.py")

            # Пишем Dockerfile
            (tmppath / "Dockerfile").write_text(_DOCKERFILE_CONTENT)

            image_tag = "promptlock-sandbox:latest"

            # Собираем образ
            try:
                subprocess.run(
                    ["docker", "build", "-t", image_tag, "."],
                    cwd=str(tmppath), capture_output=True, text=True, timeout=60,
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                return {"error": f"Не удалось собрать Docker-образ: {e}"}

            # Запускаем контейнер
            container_name = f"plsandbox_{os.getpid()}"
            try:
                result = subprocess.run(
                    [
                        "docker", "run", "--rm",
                        "--name", container_name,
                        "--network", "none",          # Без сети
                        "--memory", "256m",            # Лимит памяти
                        "--cpus", "0.5",               # Лимит CPU
                        "--read-only",                 # Read-only FS
                        "--tmpfs", "/tmp:size=64m",    # Только /tmp для записи
                        image_tag,
                    ],
                    capture_output=True, text=True, timeout=timeout,
                )
                results["exit_code"] = result.returncode
                results["stdout"] = result.stdout[:2048]
                results["stderr"] = result.stderr[:2048]
            except subprocess.TimeoutExpired:
                results["timed_out"] = True
                # Принудительная остановка
                subprocess.run(
                    ["docker", "kill", container_name],
                    capture_output=True, timeout=5,
                )

            # Извлечение strace-лога (если контейнер вернул)
            strace_output = results.get("stderr", "")
            results.update(self._parse_strace(strace_output))

        self._generate_alerts(filepath, results)
        return results

    def _fallback_analysis(self, filepath: Path) -> Dict:
        """Упрощённый анализ без Docker: статический + AST."""
        results: Dict = {"mode": "fallback", "suspicious": []}

        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {"error": "Не удалось прочитать файл"}

        # Ищем подозрительные паттерны в тексте
        dangerous_keywords = [
            ("os.remove", "Удаление файлов"),
            ("subprocess.run", "Запуск подпроцессов"),
            ("subprocess.Popen", "Запуск подпроцессов"),
            (".locked", "Расширение .locked"),
            ("encrypt", "Шифрование"),
            ("ransom", "Ransomware-ключевое слово"),
            ("11434", "Порт Ollama"),
            ("api/generate", "LLM API"),
        ]

        for keyword, desc in dangerous_keywords:
            if keyword in source.lower():
                results["suspicious"].append(f"{desc}: найдено '{keyword}'")

        self._generate_alerts(filepath, results)
        return results

    def _parse_strace(self, output: str) -> Dict:
        """Разбор strace-вывода для обнаружения подозрительного поведения."""
        parsed: Dict = {"file_ops": [], "network": [], "suspicious": []}

        for line in output.split("\n"):
            # Файловые операции
            if "unlink(" in line or "rename(" in line:
                parsed["file_ops"].append(line.strip())
                if ".locked" in line or "README_TO_DECRYPT" in line:
                    parsed["suspicious"].append(f"Подозрительная файловая операция: {line.strip()}")

            # Сетевые операции
            if "connect(" in line or "socket(" in line:
                parsed["network"].append(line.strip())
                if "11434" in line:
                    parsed["suspicious"].append(f"Соединение с LLM-портом: {line.strip()}")

        return parsed

    def _generate_alerts(self, filepath: Path, results: Dict):
        """Генерация алертов по результатам динамического анализа."""
        suspicious = results.get("suspicious", [])

        if len(suspicious) >= 3:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.CRITICAL,
                description=(
                    f"SANDBOX: {len(suspicious)} подозрительных действий "
                    f"при динамическом анализе!"
                ),
                source_path=str(filepath),
                details={"findings": suspicious[:10]},
            ))
        elif suspicious:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.SUSPICIOUS_SCRIPT,
                severity=Severity.HIGH,
                description=f"SANDBOX: Обнаружена подозрительная активность.",
                source_path=str(filepath),
                details={"findings": suspicious},
            ))

        if results.get("timed_out"):
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.PROCESS_ANOMALY,
                severity=Severity.MEDIUM,
                description="SANDBOX: Скрипт превысил таймаут выполнения.",
                source_path=str(filepath),
            ))
