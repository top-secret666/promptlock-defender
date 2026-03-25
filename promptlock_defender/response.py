"""
Модуль автоматической реакции на угрозы:
- Завершение подозрительных процессов
- Блокировка сетевых портов LLM
- Перемещение зашифрованных файлов в карантин
"""

import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.response")

QUARANTINE_DIR_NAME = "promptlock_quarantine"


class AutoResponse:
    """Автоматическая реакция при превышении порога угрозы."""

    def __init__(self, engine: DetectionEngine, quarantine_base: Optional[str] = None):
        self.engine = engine
        self.system = platform.system()
        self.quarantine_dir = Path(quarantine_base or Path.home() / QUARANTINE_DIR_NAME)
        self._killed_pids: Set[int] = set()
        self._blocked_ports: Set[int] = set()
        self.actions_log: List[str] = []

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def evaluate_and_respond(self, threshold: int = 50) -> bool:
        """
        Оценить уровень угрозы и при превышении порога запустить автоматическую реакцию.
        Возвращает True, если действия были предприняты.
        """
        score = self.engine.threat_score
        if score < threshold:
            return False

        self._log(f"⚠️  Уровень угрозы {score}/100 >= порог {threshold}. Запуск реакции...")

        self.kill_suspicious_processes()
        self.block_llm_ports()
        self.quarantine_locked_files()

        self._log("✅ Автоматическая реакция завершена.")
        return True

    def kill_suspicious_processes(self):
        """Завершение подозрительных процессов (lua, подозрительные интерпретаторы)."""
        if psutil is None:
            self._log("psutil не установлен — пропуск завершения процессов.")
            return

        suspicious_names = {"lua", "lua5.3", "lua5.4", "luajit"}

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            pid = proc.info["pid"]
            name = (proc.info.get("name") or "").lower().replace(".exe", "")

            if name in suspicious_names and pid not in self._killed_pids:
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                    self._killed_pids.add(pid)
                    self._log(f"🔪 Завершён процесс: {name} (PID: {pid})")

                    self.engine.add_alert(Alert(
                        timestamp=datetime.now(),
                        category=ThreatCategory.PROCESS_ANOMALY,
                        severity=Severity.HIGH,
                        description=f"RESPONSE: Процесс '{name}' (PID: {pid}) завершён.",
                        details={"pid": pid, "action": "terminated"},
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self._log(f"Не удалось завершить {name} (PID: {pid}): {e}")

    def block_llm_ports(self, ports: Optional[List[int]] = None):
        """Блокировка исходящих соединений на LLM-порты через фаервол."""
        ports = ports or [11434, 8080]

        for port in ports:
            if port in self._blocked_ports:
                continue
            try:
                if self.system == "Windows":
                    subprocess.run(
                        [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name=PromptLock_Block_{port}",
                            "dir=out", "action=block", "protocol=tcp",
                            f"remoteport={port}",
                        ],
                        capture_output=True, text=True, timeout=10,
                    )
                else:
                    subprocess.run(
                        [
                            "iptables", "-A", "OUTPUT",
                            "-p", "tcp", "--dport", str(port), "-j", "DROP",
                        ],
                        capture_output=True, text=True, timeout=10,
                    )
                self._blocked_ports.add(port)
                self._log(f"🚫 Заблокирован исходящий порт: {port}")
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                self._log(f"Не удалось заблокировать порт {port}: {e}")

    def unblock_llm_ports(self):
        """Снятие блокировки портов (после устранения угрозы)."""
        for port in list(self._blocked_ports):
            try:
                if self.system == "Windows":
                    subprocess.run(
                        [
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name=PromptLock_Block_{port}",
                        ],
                        capture_output=True, text=True, timeout=10,
                    )
                else:
                    subprocess.run(
                        [
                            "iptables", "-D", "OUTPUT",
                            "-p", "tcp", "--dport", str(port), "-j", "DROP",
                        ],
                        capture_output=True, text=True, timeout=10,
                    )
                self._blocked_ports.discard(port)
                self._log(f"✅ Разблокирован порт: {port}")
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                self._log(f"Не удалось разблокировать порт {port}: {e}")

    def quarantine_locked_files(self, source_dir: Optional[str] = None):
        """Перемещение .locked файлов в карантин."""
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        moved = 0
        # Перебираем алерты и находим пути зашифрованных файлов
        for alert in self.engine.alerts:
            if alert.category != ThreatCategory.FILE_ENCRYPTION:
                continue
            if not alert.source_path:
                continue

            src = Path(alert.source_path)
            if not src.exists():
                continue
            if not any(src.name.lower().endswith(ext) for ext in
                       {".locked", ".encrypted", ".enc", ".crypted"}):
                continue

            dest = self.quarantine_dir / src.name
            # Избегаем перезаписи
            if dest.exists():
                dest = self.quarantine_dir / f"{src.stem}_{moved}{src.suffix}"

            try:
                shutil.move(str(src), str(dest))
                moved += 1
            except OSError as e:
                self._log(f"Не удалось переместить {src}: {e}")

        if moved:
            self._log(f"📦 В карантин перемещено файлов: {moved} → {self.quarantine_dir}")

            self.engine.add_alert(Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=Severity.MEDIUM,
                description=f"RESPONSE: {moved} зашифрованных файлов перемещены в карантин.",
                details={"quarantine_dir": str(self.quarantine_dir), "count": moved},
            ))

    # ------------------------------------------------------------------
    # Внутренние
    # ------------------------------------------------------------------

    def _log(self, message: str):
        self.actions_log.append(f"[{datetime.now():%H:%M:%S}] {message}")
        logger.info(message)
        print(message)

    def get_actions_summary(self) -> str:
        if not self.actions_log:
            return "Никаких действий не предпринято."
        return "\n".join(self.actions_log)
