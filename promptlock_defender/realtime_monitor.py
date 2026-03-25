"""
Модуль мониторинга в реальном времени.
Использует watchdog для файловой системы и psutil для процессов/сети.
"""

import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent, FileModifiedEvent
except ImportError:
    Observer = None
    FileSystemEventHandler = object

from .engine import Alert, DetectionEngine, Severity, ThreatCategory
from .fs_monitor import LOCKED_EXTENSIONS, RANSOM_NOTE_PATTERNS

logger = logging.getLogger("promptlock_defender.realtime")

# Подозрительные имена процессов
SUSPICIOUS_PROCS = {"lua", "lua5.3", "lua5.4", "luajit"}
LLM_PROCS = {"ollama", "ollama_llama_server", "llama-server", "lmstudio"}
LLM_PORTS = {11434, 8080, 5000}


class _FSHandler(FileSystemEventHandler):
    """Обработчик событий файловой системы."""

    def __init__(self, engine: DetectionEngine, on_alert: Optional[Callable] = None):
        super().__init__()
        self.engine = engine
        self.on_alert = on_alert
        self._locked_burst: list = []
        self._burst_lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        name = os.path.basename(path).lower()

        # Ransom note
        if name in RANSOM_NOTE_PATTERNS:
            alert = Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.RANSOM_NOTE,
                severity=Severity.CRITICAL,
                description=f"REALTIME: Создана записка с требованием выкупа: {name}",
                source_path=path,
            )
            self.engine.add_alert(alert)
            if self.on_alert:
                self.on_alert(alert)
            return

        # Locked file
        if any(name.endswith(ext) for ext in LOCKED_EXTENSIONS):
            with self._burst_lock:
                self._locked_burst.append((datetime.now(), path))

            alert = Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.FILE_ENCRYPTION,
                severity=Severity.HIGH,
                description=f"REALTIME: Создан зашифрованный файл: {os.path.basename(path)}",
                source_path=path,
            )
            self.engine.add_alert(alert)
            if self.on_alert:
                self.on_alert(alert)

            # Проверяем burst: много .locked за короткое время
            self._check_burst()

    def on_moved(self, event):
        dest = event.dest_path
        name = os.path.basename(dest).lower()
        if any(name.endswith(ext) for ext in LOCKED_EXTENSIONS):
            alert = Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.EXTENSION_RENAME,
                severity=Severity.HIGH,
                description=f"REALTIME: Файл переименован в зашифрованный: {os.path.basename(dest)}",
                source_path=dest,
            )
            self.engine.add_alert(alert)
            if self.on_alert:
                self.on_alert(alert)

    def _check_burst(self):
        """Если за 30 сек создано 5+ .locked файлов — массовое шифрование."""
        with self._burst_lock:
            now = datetime.now()
            recent = [(t, p) for t, p in self._locked_burst if (now - t).total_seconds() < 30]
            self._locked_burst = recent

            if len(recent) >= 5:
                alert = Alert(
                    timestamp=now,
                    category=ThreatCategory.FILE_ENCRYPTION,
                    severity=Severity.CRITICAL,
                    description=(
                        f"REALTIME: Массовое шифрование! {len(recent)} файлов "
                        f"зашифрованы за последние 30 секунд!"
                    ),
                    details={"count": len(recent), "files": [p for _, p in recent[:10]]},
                )
                self.engine.add_alert(alert)
                if self.on_alert:
                    self.on_alert(alert)
                self._locked_burst.clear()


class RealTimeMonitor:
    """
    Мониторинг в реальном времени:
    - Файловая система (watchdog)
    - Процессы (psutil)
    - Сетевые соединения (psutil)
    """

    def __init__(self, engine: DetectionEngine, watch_dir: str,
                 on_alert: Optional[Callable] = None):
        self.engine = engine
        self.watch_dir = watch_dir
        self.on_alert = on_alert
        self._running = False
        self._known_pids: Set[int] = set()
        self._observer: Optional[Observer] = None

    def start(self):
        """Запуск мониторинга (блокирующий). Для фонового запуска используйте start_background()."""
        self._running = True
        self._check_dependencies()

        print(f"🛡️  REALTIME MONITOR запущен")
        print(f"   Наблюдаемая директория: {self.watch_dir}")
        print(f"   Нажмите Ctrl+C для остановки\n")

        # Запуск watchdog
        self._start_fs_watcher()

        # Инициализация известных процессов
        if psutil:
            for proc in psutil.process_iter(["pid"]):
                self._known_pids.add(proc.info["pid"])

        try:
            while self._running:
                self._poll_processes()
                self._poll_network()
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n⏹️  Мониторинг остановлен.")
        finally:
            self.stop()

    def start_background(self) -> threading.Thread:
        """Запуск мониторинга в фоновом потоке."""
        thread = threading.Thread(target=self.start, daemon=True)
        thread.start()
        return thread

    def stop(self):
        """Остановка мониторинга."""
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)

    def _check_dependencies(self):
        if Observer is None:
            logger.warning("watchdog не установлен: pip install watchdog")
        if psutil is None:
            logger.warning("psutil не установлен: pip install psutil")

    def _start_fs_watcher(self):
        if Observer is None:
            return
        handler = _FSHandler(self.engine, on_alert=self.on_alert)
        self._observer = Observer()
        self._observer.schedule(handler, path=self.watch_dir, recursive=True)
        self._observer.start()
        logger.info("Watchdog запущен для: %s", self.watch_dir)

    def _poll_processes(self):
        """Периодическая проверка новых процессов."""
        if psutil is None:
            return

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            pid = proc.info["pid"]
            if pid in self._known_pids:
                continue
            self._known_pids.add(pid)

            name = (proc.info.get("name") or "").lower().replace(".exe", "")
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()

            # Lua runtime
            if name in SUSPICIOUS_PROCS:
                alert = Alert(
                    timestamp=datetime.now(),
                    category=ThreatCategory.PROCESS_ANOMALY,
                    severity=Severity.HIGH,
                    description=(
                        f"REALTIME: Запущен Lua-процесс '{name}' (PID: {pid}). "
                        f"PromptLock использует Lua для шифрования."
                    ),
                    details={"pid": pid, "cmdline": cmdline},
                )
                self.engine.add_alert(alert)
                if self.on_alert:
                    self.on_alert(alert)

            # LLM server
            elif name in LLM_PROCS:
                alert = Alert(
                    timestamp=datetime.now(),
                    category=ThreatCategory.LLM_ABUSE,
                    severity=Severity.MEDIUM,
                    description=f"REALTIME: Обнаружен LLM-сервер '{name}' (PID: {pid}).",
                    details={"pid": pid},
                )
                self.engine.add_alert(alert)
                if self.on_alert:
                    self.on_alert(alert)

            # Lua in command line (e.g. python running lua subprocess)
            elif ".lua" in cmdline and name not in ("code", "explorer", "notepad"):
                alert = Alert(
                    timestamp=datetime.now(),
                    category=ThreatCategory.SUSPICIOUS_SCRIPT,
                    severity=Severity.HIGH,
                    description=f"REALTIME: Процесс '{name}' запустил .lua скрипт (PID: {pid}).",
                    details={"pid": pid, "cmdline": cmdline},
                )
                self.engine.add_alert(alert)
                if self.on_alert:
                    self.on_alert(alert)

    def _poll_network(self):
        """Периодическая проверка сетевых соединений к LLM-портам."""
        if psutil is None:
            return

        active_llm_conns = 0
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != "ESTABLISHED":
                    continue
                if conn.raddr and conn.raddr.port in LLM_PORTS:
                    active_llm_conns += 1
        except (psutil.AccessDenied, OSError):
            return

        if active_llm_conns >= 3:
            alert = Alert(
                timestamp=datetime.now(),
                category=ThreatCategory.LLM_ABUSE,
                severity=Severity.HIGH,
                description=(
                    f"REALTIME: {active_llm_conns} активных соединений к LLM-портам! "
                    "Возможна массовая генерация вредоносного кода."
                ),
                details={"connections": active_llm_conns},
            )
            self.engine.add_alert(alert)
            if self.on_alert:
                self.on_alert(alert)
