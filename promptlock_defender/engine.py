"""
Ядро обнаружения — движок правил и агрегация алертов.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional

logger = logging.getLogger("promptlock_defender")


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(Enum):
    FILE_ENCRYPTION = "Массовое шифрование файлов"
    RANSOM_NOTE = "Создание записки с требованием выкупа"
    LLM_ABUSE = "Злоупотребление локальной LLM"
    JAILBREAK_PROMPT = "Jailbreak-промпт в запросе к LLM"
    SUSPICIOUS_SCRIPT = "Подозрительный скрипт (Lua/Python)"
    PROCESS_ANOMALY = "Аномальный процесс"
    EXTENSION_RENAME = "Массовое переименование расширений"


@dataclass
class Alert:
    """Единичное срабатывание детектора."""
    timestamp: datetime
    category: ThreatCategory
    severity: Severity
    description: str
    source_path: Optional[str] = None
    details: dict = field(default_factory=dict)

    def __str__(self):
        icon = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}
        s = icon.get(self.severity.value, "⚪")
        return (
            f"{s} [{self.severity.value}] {self.category.value}\n"
            f"   {self.description}\n"
            f"   Источник: {self.source_path or 'N/A'}\n"
            f"   Время: {self.timestamp:%Y-%m-%d %H:%M:%S}"
        )


class DetectionEngine:
    """Агрегатор алертов от всех модулей обнаружения."""

    def __init__(self):
        self.alerts: List[Alert] = []
        self.is_running = True
        self.scan_start_time: Optional[float] = None
        self.first_alert_time: Optional[float] = None

    def start_scan(self):
        """Запомнить момент начала сканирования (для бенчмарков)."""
        import time
        self.scan_start_time = time.perf_counter()
        self.first_alert_time = None

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)
        if self.scan_start_time is not None and self.first_alert_time is None:
            import time
            self.first_alert_time = time.perf_counter() - self.scan_start_time
        logger.warning("ALERT: %s — %s", alert.severity.value, alert.description)

    def get_alerts(self, min_severity: Severity = Severity.LOW) -> List[Alert]:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_idx = order.index(min_severity)
        return [a for a in self.alerts if order.index(a.severity) >= min_idx]

    @property
    def threat_score(self) -> int:
        """Расчёт общего уровня угрозы (0-100)."""
        weights = {Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}
        score = sum(weights[a.severity] for a in self.alerts)
        return min(score, 100)

    def summary(self) -> str:
        if not self.alerts:
            return "✅ Угроз не обнаружено."

        score = self.threat_score
        total = len(self.alerts)
        by_sev = {}
        for a in self.alerts:
            by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1

        lines = [
            "=" * 55,
            "  PROMPTLOCK DEFENDER — ОТЧЁТ",
            "=" * 55,
            f"  Уровень угрозы: {score}/100",
            f"  Всего алертов:  {total}",
        ]
        for sev, count in sorted(by_sev.items()):
            lines.append(f"    {sev}: {count}")
        lines.append("=" * 55)

        for a in sorted(self.alerts, key=lambda x: x.timestamp):
            lines.append(str(a))
            lines.append("")

        if score >= 50:
            lines.append("🚨 РЕКОМЕНДАЦИЯ: Немедленно изолировать систему и проверить процессы!")
        elif score >= 20:
            lines.append("⚠️  РЕКОМЕНДАЦИЯ: Проверить подозрительную активность вручную.")
        else:
            lines.append("ℹ️  РЕКОМЕНДАЦИЯ: Незначительные находки, продолжайте мониторинг.")

        return "\n".join(lines)
