"""
Модуль мониторинга процессов и сетевых соединений.
Обнаруживает подозрительные обращения к локальным LLM (Ollama) и запуск Lua-скриптов.
"""

import logging
import os
import platform
import subprocess
from datetime import datetime
from typing import List, Tuple

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.proc_monitor")

# Подозрительные имена процессов, связанные с PromptLock-поведением
SUSPICIOUS_PROCESS_NAMES = {
    "lua", "lua5.3", "lua5.4", "luajit",  # Lua — PromptLock использует Lua-скрипты
}

# Порты, которые слушают локальные LLM
LLM_PORTS = {
    11434,  # Ollama
    8080,   # LM Studio, llama.cpp server
    5000,   # Некоторые LLM-серверы
}


class ProcessMonitor:
    """Мониторинг процессов и сетевой активности."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.system = platform.system()

    def scan(self) -> int:
        """Запуск всех проверок. Возвращает количество новых алертов."""
        alerts_before = len(self.engine.alerts)

        self._check_suspicious_processes()
        self._check_llm_server_running()
        self._check_suspicious_network_connections()

        return len(self.engine.alerts) - alerts_before

    def _get_process_list(self) -> List[Tuple[str, str]]:
        """Получение списка процессов: [(pid, name), ...]"""
        processes = []
        try:
            if self.system == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        processes.append((parts[1], parts[0].lower()))
            else:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append((parts[1], parts[10].lower()))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Не удалось получить список процессов: %s", e)
        return processes

    def _check_suspicious_processes(self):
        """Поиск подозрительных процессов (Lua runtime и т.д.)."""
        processes = self._get_process_list()

        for pid, name in processes:
            basename = os.path.basename(name).replace(".exe", "")
            if basename in SUSPICIOUS_PROCESS_NAMES:
                self.engine.add_alert(Alert(
                    timestamp=datetime.now(),
                    category=ThreatCategory.PROCESS_ANOMALY,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Обнаружен подозрительный процесс: {basename} (PID: {pid}). "
                        "PromptLock использует Lua для выполнения сгенерированных скриптов."
                    ),
                    details={"pid": pid, "process": name},
                ))

    def _check_llm_server_running(self):
        """Проверяет, запущен ли локальный LLM-сервер (Ollama и т.д.)."""
        for pid, name in self._get_process_list():
            basename = os.path.basename(name).replace(".exe", "")
            if basename in ("ollama", "ollama_llama_server", "llama-server", "lmstudio"):
                self.engine.add_alert(Alert(
                    timestamp=datetime.now(),
                    category=ThreatCategory.LLM_ABUSE,
                    severity=Severity.LOW,
                    description=(
                        f"Обнаружен локальный LLM-сервер: {basename} (PID: {pid}). "
                        "Сам по себе не опасен, но может быть использован PromptLock."
                    ),
                    details={"pid": pid, "process": name},
                ))

    def _check_suspicious_network_connections(self):
        """Проверка активных сетевых соединений к известным LLM-портам."""
        connections = []
        try:
            if self.system == "Windows":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, timeout=10,
                )
            else:
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True, text=True, timeout=10,
                )
            connections = result.stdout.strip().split("\n")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Не удалось проверить сетевые соединения: %s", e)
            return

        llm_connections = 0
        for line in connections:
            for port in LLM_PORTS:
                # Ищем соединения к localhost:<LLM_PORT>
                if f"127.0.0.1:{port}" in line or f"localhost:{port}" in line:
                    if "ESTABLISHED" in line or "ESTAB" in line:
                        llm_connections += 1

        if llm_connections >= 3:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.LLM_ABUSE,
                severity=Severity.HIGH,
                description=(
                    f"Множественные активные соединения к локальному LLM ({llm_connections} шт). "
                    "PromptLock использует LLM для генерации вредоносных скриптов."
                ),
                details={"connection_count": llm_connections},
            ))
        elif llm_connections >= 1:
            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.LLM_ABUSE,
                severity=Severity.MEDIUM,
                description=(
                    f"Активное соединение к локальному LLM-серверу (порт из {LLM_PORTS})."
                ),
                details={"connection_count": llm_connections},
            ))
