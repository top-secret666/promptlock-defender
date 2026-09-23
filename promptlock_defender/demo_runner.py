#!/usr/bin/env python3
"""
PromptLock Defender — Демо-оркестратор для конференции.

Автоматический сценарий:
  1. Генерация безопасных тестовых артефактов (имитация следов атаки)
  2. Запуск антивирусного сканирования с замером времени
  3. Визуализация времени реакции (ASCII-график)
  4. Сравнение с ClamAV (если установлен)
  5. Демонстрация авто-реакции (карантин, kill, block)
  6. Live-лог: вывод алертов в реальном времени + запись в файл
  7. Экспорт HTML-отчёта

Запуск:
    python demo_runner.py                 — полный демо-сценарий
    python demo_runner.py --skip-clamav   — без сравнения с ClamAV
    python demo_runner.py --fast          — без задержек между артефактами
    python demo_runner.py --no-cleanup    — не удалять тестовые файлы
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Добавляем родительскую директорию в sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from promptlock_defender.engine import DetectionEngine, Severity
from promptlock_defender.fs_monitor import FileSystemScanner
from promptlock_defender.static_scanner import StaticScanner
from promptlock_defender.heuristics import EntropyAnalyzer, ASTAnalyzer
from promptlock_defender.ml_classifier import MLClassifier
from promptlock_defender.proc_monitor import ProcessMonitor
from promptlock_defender.binary_scanner import BinaryScanner
from promptlock_defender.response import AutoResponse
from promptlock_defender.report import ReportExporter
from promptlock_defender.test_artifacts import TestArtifactGenerator


# ── Цвета для терминала ──────────────────────────────────────────────

class C:
    """ANSI-цвета (безопасный fallback для Windows CMD без VT100)."""
    _enabled = True

    @classmethod
    def disable(cls):
        cls._enabled = False

    @classmethod
    def _w(cls, code, text):
        return f"\033[{code}m{text}\033[0m" if cls._enabled else text

    @classmethod
    def red(cls, t):    return cls._w("91", t)
    @classmethod
    def green(cls, t):  return cls._w("92", t)
    @classmethod
    def yellow(cls, t): return cls._w("93", t)
    @classmethod
    def cyan(cls, t):   return cls._w("96", t)
    @classmethod
    def bold(cls, t):   return cls._w("1", t)
    @classmethod
    def dim(cls, t):    return cls._w("2", t)
    @classmethod
    def magenta(cls, t): return cls._w("95", t)


# ── Утилиты ──────────────────────────────────────────────────────────

def separator(title: str = ""):
    width = 60
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'═' * pad} {C.bold(title)} {'═' * pad}")
    else:
        print("═" * width)


def phase(num: int, total: int, title: str):
    """Заголовок фазы демо."""
    print(f"\n{C.cyan(f'[{num}/{total}]')} {C.bold(title)}")
    print(f"    {'─' * 50}")


# ── Live-лог ─────────────────────────────────────────────────────────

class LiveLogger:
    """Записывает алерты в файл + выводит в терминал в реальном времени."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.log_path, "w", encoding="utf-8")
        self._fh.write(f"# PromptLock Defender — Live Log\n")
        self._fh.write(f"# Начало: {datetime.now().isoformat()}\n\n")
        self.alert_count = 0

    def log_alert(self, alert):
        self.alert_count += 1
        sev = alert.severity.value
        ts = alert.timestamp.strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] [{sev:8}] {alert.description}"
        if alert.source_path:
            line += f"  ← {alert.source_path}"

        # Цвет по severity
        color_fn = {
            "LOW": C.yellow, "MEDIUM": C.yellow,
            "HIGH": C.red, "CRITICAL": C.magenta,
        }.get(sev, C.dim)

        print(f"    {color_fn(line)}")
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self):
        self._fh.write(f"\n# Конец: {datetime.now().isoformat()}\n")
        self._fh.write(f"# Всего алертов: {self.alert_count}\n")
        self._fh.close()


# ── Тайминг ──────────────────────────────────────────────────────────

class TimingTracker:
    """Замеряет время каждого этапа сканирования."""

    def __init__(self):
        self.records: list = []
        self._start: float = 0
        self.first_alert_time: float = None
        self.demo_start: float = 0

    def start_phase(self, name: str):
        self._start = time.perf_counter()
        self._current_name = name

    def end_phase(self):
        elapsed = time.perf_counter() - self._start
        self.records.append((self._current_name, elapsed))
        return elapsed

    def mark_first_alert(self):
        if self.first_alert_time is None:
            self.first_alert_time = time.perf_counter() - self.demo_start

    def total(self) -> float:
        return sum(t for _, t in self.records)

    def visualize(self) -> str:
        """ASCII-график времени по этапам."""
        if not self.records:
            return "Нет данных."

        max_time = max(t for _, t in self.records) or 0.001
        bar_width = 40
        lines = [
            "",
            C.bold("  ⏱  ВИЗУАЛИЗАЦИЯ ВРЕМЕНИ РЕАКЦИИ"),
            f"  {'─' * 55}",
        ]

        for name, elapsed in self.records:
            bar_len = int((elapsed / max_time) * bar_width)
            bar = "█" * bar_len + "░" * (bar_width - bar_len)

            if elapsed < 0.5:
                col = C.green
            elif elapsed < 2.0:
                col = C.yellow
            else:
                col = C.red

            lines.append(
                f"  {name:<22} {col(bar)} {elapsed:>6.3f}s"
            )

        lines.append(f"  {'─' * 55}")
        lines.append(f"  {'ИТОГО':<22} {'':>40} {C.bold(f'{self.total():>6.3f}s')}")

        if self.first_alert_time is not None:
            lines.append(
                f"  {'Первый алерт через':<22} {'':>40} {C.cyan(f'{self.first_alert_time:>6.3f}s')}"
            )

        lines.append("")
        return "\n".join(lines)


# ── ClamAV сравнение ─────────────────────────────────────────────────

def run_clamav_comparison(test_dir: str) -> dict:
    """
    Запускает clamscan на тестовой директории и возвращает результаты.
    Возвращает dict: {available, infected, scanned, time_sec, raw_output}
    """
    result = {"available": False, "infected": 0, "scanned": 0, "time_sec": 0, "raw_output": ""}

    # Ищем clamscan
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return result

    result["available"] = True
    start = time.perf_counter()

    try:
        proc = subprocess.run(
            [clamscan, "-r", "--no-summary", test_dir],
            capture_output=True, text=True, timeout=120
        )
        elapsed = time.perf_counter() - start
        result["time_sec"] = elapsed
        result["raw_output"] = proc.stdout

        # Парсим вывод clamscan
        for line in proc.stdout.splitlines():
            result["scanned"] += 1
            if "FOUND" in line:
                result["infected"] += 1

        # Пробуем получить summary
        proc2 = subprocess.run(
            [clamscan, "-r", test_dir],
            capture_output=True, text=True, timeout=120
        )
        for line in proc2.stdout.splitlines():
            if "Infected files:" in line:
                try:
                    result["infected"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass
            if "Scanned files:" in line:
                try:
                    result["scanned"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        result["available"] = False

    return result


def format_clamav_comparison(clamav: dict, defender_alerts: int, defender_time: float) -> str:
    """Форматирует сравнительную таблицу."""
    lines = [
        "",
        C.bold("  📊 СРАВНЕНИЕ: PromptLock Defender vs ClamAV"),
        f"  {'─' * 55}",
        f"  {'Метрика':<25} {'Defender':>14} {'ClamAV':>14}",
        f"  {'─' * 55}",
    ]

    if clamav["available"]:
        infected = clamav["infected"]
        clam_time = clamav["time_sec"]
        lines.append(f"  {'Обнаружено угроз':<25} {C.red(f'{defender_alerts:>14}')} {infected:>14}")
        lines.append(f"  {'Время сканирования':<25} {C.green(f'{defender_time:>13.3f}s')} {clam_time:>13.3f}s")
        lines.append(f"  {'AI-специфика':<25} {C.green('Да'):>14} {'Нет':>14}")
        lines.append(f"  {'Энтропия-анализ':<25} {C.green('Да'):>14} {'Нет':>14}")
        lines.append(f"  {'AST поведенческий':<25} {C.green('Да'):>14} {'Нет':>14}")
        lines.append(f"  {'ML-классификатор':<25} {C.green('Да'):>14} {'Нет':>14}")
    else:
        lines.append(f"  ⚠️  ClamAV не установлен (clamscan не найден в PATH)")
        lines.append(f"  ℹ️  Установка: sudo apt install clamav / choco install clamav")
        lines.append(f"  ")
        lines.append(f"  {'Defender обнаружил':<25} {C.red(f'{defender_alerts} угроз')} за {C.green(f'{defender_time:.3f}s')}")
        lines.append(f"  ClamAV НЕ обнаружил бы AI-специфические угрозы:")
        lines.append(f"    • Jailbreak-промпты в LLM")
        lines.append(f"    • Обращения к localhost:11434 (Ollama)")
        lines.append(f"    • Поведенческие цепочки (шифрование + удаление + LLM)")
        lines.append(f"    • Массовое появление .locked файлов")

    lines.append(f"  {'─' * 55}")
    lines.append("")
    return "\n".join(lines)


# ── Авто-реакция (демо-режим) ────────────────────────────────────────

def demo_auto_response(engine: DetectionEngine, test_dir: str) -> list:
    """
    Демонстрирует авто-реакцию В БЕЗОПАСНОМ РЕЖИМЕ:
    - Карантин .locked файлов (перенос в подпапку quarantine)
    - НЕ убивает процессы (демо-режим)
    - НЕ блокирует порты (демо-режим)
    Возвращает список выполненных действий.
    """
    actions = []
    score = engine.threat_score

    print(f"\n    Уровень угрозы: {C.bold(str(score))}/100")

    if score < 30:
        print(f"    {C.green('Порог не превышен, автоматическая реакция не требуется.')}")
        return actions

    # Карантин .locked файлов
    quarantine_dir = Path(test_dir) / "_quarantine"
    quarantine_dir.mkdir(exist_ok=True)
    moved = 0

    for root, dirs, files in os.walk(test_dir):
        if "_quarantine" in root:
            continue
        for f in files:
            if f.endswith(".locked"):
                src = Path(root) / f
                dst = quarantine_dir / f
                shutil.move(str(src), str(dst))
                moved += 1

    if moved:
        actions.append(f"Карантин: {moved} файлов .locked → {quarantine_dir}")
        print(f"    {C.yellow(f'🔒 Перемещено в карантин: {moved} файлов .locked')}")

    # Демо: показываем что МОГЛИ бы сделать (без реального действия)
    critical_alerts = engine.get_alerts(min_severity=Severity.HIGH)
    if critical_alerts:
        actions.append(f"[demo] Могут быть завершены подозрительные процессы (ollama, lua)")
        print(f"    {C.dim('[demo] Завершение подозрительных процессов: ollama, lua — ПРОПУЩЕНО (демо)')}")
        actions.append(f"[demo] Могут быть заблокированы порты: 11434, 8080, 5000")
        print(f"    {C.dim('[demo] Блокировка LLM-портов: 11434, 8080, 5000 — ПРОПУЩЕНО (демо)')}")

    return actions


# ── Главный сценарий ─────────────────────────────────────────────────

def run_demo(args):
    """Полный демо-сценарий для конференции."""

    TOTAL_PHASES = 7
    test_dir_path = Path(args.test_dir)
    log_path = Path(args.log_file)
    report_base = Path(args.report)

    # Включить/выключить ANSI-цвета
    if args.no_color:
        C.disable()

    # ── Баннер ────────────────────────────────────────────────────
    print(C.cyan(r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║     PromptLock Defender — КОНФЕРЕНЦ-ДЕМО v2.0            ║
  ║     Автоматический сценарий обнаружения AI-ransomware    ║
  ╚═══════════════════════════════════════════════════════════╝
    """))
    print(f"  Дата/время: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"  Тестовая директория: {test_dir_path}")
    print(f"  Live-лог:           {log_path}")
    print(f"  Отчёт:              {report_base}.html / .json")
    separator()

    timing = TimingTracker()
    timing.demo_start = time.perf_counter()
    live_log = LiveLogger(str(log_path))

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 1: Генерация тестовых артефактов
    # ══════════════════════════════════════════════════════════════
    phase(1, TOTAL_PHASES, "Генерация безопасных тестовых артефактов")
    timing.start_phase("Генерация артефактов")

    gen = TestArtifactGenerator(str(test_dir_path))
    delay = 0 if args.fast else 0.3
    gen.generate_all(count=args.file_count, delay=delay)

    gen_time = timing.end_phase()
    print(f"\n    Создано файлов: {len(gen.created_files)}")
    print(f"    Время: {gen_time:.3f}s")

    # Небольшая пауза для наглядности
    if not args.fast:
        print(f"\n    {C.dim('Ожидание 1с перед запуском антивируса...')}")
        time.sleep(1)

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 2: Полный антивирусный скан
    # ══════════════════════════════════════════════════════════════
    phase(2, TOTAL_PHASES, "Запуск антивирусного сканирования")
    engine = DetectionEngine()

    # Патчим engine чтобы ловить момент первого алерта
    _original_add = engine.add_alert
    def _patched_add(alert):
        _original_add(alert)
        timing.mark_first_alert()
        live_log.log_alert(alert)
    engine.add_alert = _patched_add

    scan_modules = [
        ("Файловая система", lambda: FileSystemScanner(engine).scan_directory(str(test_dir_path))),
        ("Статический анализ", lambda: StaticScanner(engine).scan_directory(str(test_dir_path))),
        ("Бинарный анализ", lambda: BinaryScanner(engine).scan_directory(str(test_dir_path))),
        ("AST + поведение", lambda: ASTAnalyzer(engine).scan_directory(str(test_dir_path))),
        ("Энтропия файлов", lambda: EntropyAnalyzer(engine).scan_directory(str(test_dir_path))),
        ("ML-классификатор", None),  # отдельная обработка
        ("Процессы и сеть", lambda: ProcessMonitor(engine).scan()),
    ]

    total_alerts_by_module = {}

    for mod_name, scan_fn in scan_modules:
        timing.start_phase(mod_name)

        if mod_name == "ML-классификатор":
            ml = MLClassifier(engine)
            ml.train()
            count = ml.scan_directory(str(test_dir_path))
        else:
            count = scan_fn()

        elapsed = timing.end_phase()
        total_alerts_by_module[mod_name] = count
        print(f"    ✓ {mod_name:<22} → {count:>3} алертов  [{elapsed:.3f}s]")

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 3: Визуализация времени реакции
    # ══════════════════════════════════════════════════════════════
    phase(3, TOTAL_PHASES, "Визуализация времени реакции")
    print(timing.visualize())

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 4: Сравнение с ClamAV
    # ══════════════════════════════════════════════════════════════
    phase(4, TOTAL_PHASES, "Сравнение с ClamAV")

    if args.skip_clamav:
        print(f"    {C.dim('Пропущено (--skip-clamav)')}")
        clamav_result = {"available": False}
    else:
        print(f"    Запуск clamscan на {test_dir_path}...")
        timing.start_phase("ClamAV")
        clamav_result = run_clamav_comparison(str(test_dir_path))
        if clamav_result["available"]:
            timing.end_phase()

    print(format_clamav_comparison(
        clamav_result,
        defender_alerts=len(engine.alerts),
        defender_time=timing.total(),
    ))

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 5: Демонстрация авто-реакции
    # ══════════════════════════════════════════════════════════════
    phase(5, TOTAL_PHASES, "Автоматическая реакция (безопасный режим)")
    timing.start_phase("Авто-реакция")
    response_actions = demo_auto_response(engine, str(test_dir_path))
    timing.end_phase()

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 6: Итоговый отчёт
    # ══════════════════════════════════════════════════════════════
    phase(6, TOTAL_PHASES, "Генерация отчёта")
    timing.start_phase("Экспорт отчёта")

    exporter = ReportExporter(engine)
    json_path = str(report_base) + ".json"
    html_path = str(report_base) + ".html"
    exporter.to_json(json_path)
    exporter.to_html(html_path)

    timing.end_phase()
    print(f"    📄 JSON: {json_path}")
    print(f"    📄 HTML: {html_path}")

    # ══════════════════════════════════════════════════════════════
    # ФАЗА 7: Итоги
    # ══════════════════════════════════════════════════════════════
    phase(7, TOTAL_PHASES, "Итоги демонстрации")

    total_time = time.perf_counter() - timing.demo_start
    live_log.close()

    separator("РЕЗУЛЬТАТЫ")

    score = engine.threat_score
    if score >= 50:
        score_str = C.red(f"🚨 {score}/100 — ВЫСОКАЯ УГРОЗА")
    elif score >= 20:
        score_str = C.yellow(f"⚠️  {score}/100 — ПОДОЗРИТЕЛЬНО")
    else:
        score_str = C.green(f"✅ {score}/100 — НИЗКИЙ РИСК")

    print(f"""
    Уровень угрозы:     {score_str}
    Всего алертов:      {C.bold(str(len(engine.alerts)))}
    Время полного скана: {C.bold(f'{timing.total():.3f}s')}
    Время от старта до первого алерта: {C.cyan(f'{timing.first_alert_time:.3f}s') if timing.first_alert_time else 'N/A'}
    Общее время демо:   {total_time:.1f}s
    Live-лог:           {log_path} ({live_log.alert_count} записей)
    Авто-реакция:       {len(response_actions)} действий выполнено
    """)

    # Алерты по модулям
    print(C.bold("    Алерты по модулям:"))
    for mod, cnt in total_alerts_by_module.items():
        bar = "█" * min(cnt, 30)
        print(f"      {mod:<22} {cnt:>3}  {C.yellow(bar)}")

    separator()

    # ── Очистка ───────────────────────────────────────────────
    if not args.no_cleanup:
        print(f"\n    {C.dim('Очистка тестовых артефактов...')}")
        gen.cleanup()
        # Также удаляем карантин если остался
        q_dir = test_dir_path / "_quarantine"
        if q_dir.exists():
            shutil.rmtree(q_dir)
        if test_dir_path.exists():
            shutil.rmtree(test_dir_path, ignore_errors=True)
        print(f"    {C.green('Тестовые файлы удалены.')}")
    else:
        print(f"\n    {C.dim(f'Тестовые файлы сохранены в: {test_dir_path}')}")

    print(f"\n{C.green('Демонстрация завершена!')} 🎉\n")
    return engine.threat_score


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="demo_runner",
        description="PromptLock Defender — демо-оркестратор для конференции",
    )
    parser.add_argument(
        "--test-dir",
        default=str(Path.home() / "promptlock_demo_test"),
        help="Директория для тестовых артефактов (по умолчанию ~/promptlock_demo_test)",
    )
    parser.add_argument(
        "--file-count", type=int, default=10,
        help="Количество .locked файлов для генерации (по умолчанию 10)",
    )
    parser.add_argument(
        "--log-file",
        default="demo_live.log",
        help="Путь для live-лога (по умолчанию demo_live.log)",
    )
    parser.add_argument(
        "--report",
        default="demo_report",
        help="Базовое имя для отчёта (создаст .json и .html)",
    )
    parser.add_argument("--skip-clamav", action="store_true", help="Пропустить сравнение с ClamAV")
    parser.add_argument("--fast", action="store_true", help="Без задержек между артефактами")
    parser.add_argument("--no-cleanup", action="store_true", help="Не удалять тестовые файлы после демо")
    parser.add_argument("--no-color", action="store_true", help="Отключить ANSI-цвета")

    args = parser.parse_args()
    sys.exit(0 if run_demo(args) < 100 else 1)


if __name__ == "__main__":
    main()
