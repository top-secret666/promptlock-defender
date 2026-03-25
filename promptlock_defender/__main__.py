#!/usr/bin/env python3
"""
PromptLock Defender — CLI-интерфейс антивируса-детектора.

Команды:
    scan <dir>          — полный скан (ФС + код + эвристики + ML + процессы)
    scan-fs <dir>       — только файловая система
    scan-static <dir>   — статический анализ кода
    scan-ast <dir>      — AST + эвристический анализ
    scan-ml <dir>       — ML-классификатор скриптов
    scan-proc           — мониторинг процессов
    monitor <dir>       — мониторинг в реальном времени
    dashboard <dir>     — запуск веб-дашборда с live-мониторингом
    sandbox <file>      — динамический анализ файла в песочнице
    report <dir>        — скан + экспорт отчёта (JSON/HTML)
"""

import argparse
import logging
import sys
from pathlib import Path

from .engine import DetectionEngine, Severity
from .fs_monitor import FileSystemScanner
from .proc_monitor import ProcessMonitor
from .static_scanner import StaticScanner
from .heuristics import EntropyAnalyzer, ASTAnalyzer
from .ml_classifier import MLClassifier
from .binary_scanner import BinaryScanner
from .response import AutoResponse
from .report import ReportExporter


BANNER = r"""
  ____                       _   _               _
 |  _ \ _ __ ___  _ __ ___ | |_| |    ___   ___| | __
 | |_) | '__/ _ \| '_ ` _ \| __| |   / _ \ / __| |/ /
 |  __/| | | (_) | | | | | | |_| |__| (_) | (__|   <
 |_|   |_|  \___/|_| |_| |_|\__|_____\___/ \___|_|\_\
       ____        __                _
      |  _ \  ___ / _| ___ _ __  __| | ___ _ __
      | | | |/ _ \ |_ / _ \ '_ \/ _` |/ _ \ '__|
      | |_| |  __/  _|  __/ | | \__,_|  __/ |
      |____/ \___|_|  \___|_| |_|___,_|\___|_|   v2.0
"""


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_full_scan(args):
    """Полный скан: ФС + статика + AST + энтропия + ML + процессы + автореакция."""
    engine = DetectionEngine()
    steps = 7

    print(f"\n[1/{steps}] Сканирование файловой системы: {args.directory}")
    fs = FileSystemScanner(engine)
    fs_count = fs.scan_directory(args.directory)
    print(f"         Алертов: {fs_count}")

    print(f"\n[2/{steps}] Статический анализ кода (сигнатуры)...")
    static = StaticScanner(engine)
    st_count = static.scan_directory(args.directory)
    print(f"         Алертов: {st_count}")

    print(f"\n[3/{steps}] Анализ бинарных файлов (ELF/PE)...")
    binary = BinaryScanner(engine)
    bin_count = binary.scan_directory(args.directory)
    print(f"         Алертов: {bin_count}")

    print(f"\n[4/{steps}] AST-анализ + поведенческие цепочки...")
    ast_analyzer = ASTAnalyzer(engine)
    ast_count = ast_analyzer.scan_directory(args.directory)
    print(f"         Алертов: {ast_count}")

    print(f"\n[5/{steps}] Анализ энтропии файлов...")
    entropy = EntropyAnalyzer(engine)
    ent_count = entropy.scan_directory(args.directory)
    print(f"         Алертов: {ent_count}")

    print(f"\n[6/{steps}] ML-классификатор скриптов...")
    ml = MLClassifier(engine)
    ml.train()
    ml_count = ml.scan_directory(args.directory)
    print(f"         Алертов: {ml_count}")

    print(f"\n[7/{steps}] Мониторинг процессов и сети...")
    proc = ProcessMonitor(engine)
    pr_count = proc.scan()
    print(f"         Алертов: {pr_count}")

    print("\n" + engine.summary())

    # Автоматическая реакция
    if args.auto_respond:
        responder = AutoResponse(engine)
        responder.evaluate_and_respond(threshold=args.threshold)

    # Экспорт отчёта
    if args.output:
        exporter = ReportExporter(engine)
        if args.output.endswith(".json"):
            exporter.to_json(args.output)
        else:
            exporter.to_html(args.output)
        print(f"\n📄 Отчёт сохранён: {args.output}")

    return engine.threat_score


def cmd_scan_fs(args):
    """Только файловая система."""
    engine = DetectionEngine()
    count = FileSystemScanner(engine).scan_directory(args.directory)
    print(f"Алертов: {count}")
    print("\n" + engine.summary())
    return engine.threat_score


def cmd_scan_static(args):
    """Только статический анализ."""
    engine = DetectionEngine()
    count = StaticScanner(engine).scan_directory(args.directory)
    print(f"Алертов: {count}")
    print("\n" + engine.summary())
    return engine.threat_score


def cmd_scan_ast(args):
    """AST + энтропия + поведенческие цепочки."""
    engine = DetectionEngine()

    print("AST-анализ...")
    ast_count = ASTAnalyzer(engine).scan_directory(args.directory)
    print(f"  AST алертов: {ast_count}")

    print("Анализ энтропии...")
    ent_count = EntropyAnalyzer(engine).scan_directory(args.directory)
    print(f"  Энтропия алертов: {ent_count}")

    print("\n" + engine.summary())
    return engine.threat_score


def cmd_scan_ml(args):
    """ML-классификация скриптов."""
    engine = DetectionEngine()
    ml = MLClassifier(engine)
    ml.train()
    count = ml.scan_directory(args.directory)
    print(f"Алертов: {count}")
    print("\n" + engine.summary())
    return engine.threat_score


def cmd_scan_proc(args):
    """Только процессы и сеть."""
    engine = DetectionEngine()
    count = ProcessMonitor(engine).scan()
    print(f"Алертов: {count}")
    print("\n" + engine.summary())
    return engine.threat_score


def cmd_monitor(args):
    """Real-time мониторинг файловой системы + процессов."""
    from .realtime_monitor import RealTimeMonitor

    engine = DetectionEngine()

    def on_alert(alert):
        print(f"\n{alert}\n")

    monitor = RealTimeMonitor(engine, watch_dir=args.directory, on_alert=on_alert)
    try:
        monitor.start()
    except KeyboardInterrupt:
        pass
    finally:
        print("\n" + engine.summary())
    return engine.threat_score


def cmd_dashboard(args):
    """Веб-дашборд + real-time мониторинг."""
    from .realtime_monitor import RealTimeMonitor
    from .dashboard import Dashboard

    engine = DetectionEngine()
    port = args.port

    # Запускаем мониторинг в фоне
    monitor = RealTimeMonitor(engine, watch_dir=args.directory)
    monitor.start_background()

    # Запускаем дашборд (блокирующий)
    dash = Dashboard(engine)
    try:
        dash.run(host="127.0.0.1", port=port)
    except KeyboardInterrupt:
        monitor.stop()
    return engine.threat_score


def cmd_sandbox(args):
    """Динамический анализ файла в песочнице."""
    from .sandbox import Sandbox

    engine = DetectionEngine()
    sb = Sandbox(engine)

    print(f"🔬 Анализ файла в песочнице: {args.file}")
    results = sb.analyze_file(args.file, timeout=args.timeout)

    if "error" in results:
        print(f"❌ Ошибка: {results['error']}")
    else:
        print(f"   Режим: {results.get('mode', 'docker')}")
        suspicious = results.get("suspicious", [])
        if suspicious:
            print(f"   ⚠️  Подозрительные действия: {len(suspicious)}")
            for s in suspicious:
                print(f"      - {s}")
        else:
            print("   ✅ Подозрительных действий не обнаружено.")

    print("\n" + engine.summary())
    return engine.threat_score


def cmd_report(args):
    """Полный скан + экспорт отчёта."""
    engine = DetectionEngine()

    FileSystemScanner(engine).scan_directory(args.directory)
    StaticScanner(engine).scan_directory(args.directory)
    BinaryScanner(engine).scan_directory(args.directory)
    ASTAnalyzer(engine).scan_directory(args.directory)
    EntropyAnalyzer(engine).scan_directory(args.directory)
    ml = MLClassifier(engine)
    ml.train()
    ml.scan_directory(args.directory)
    ProcessMonitor(engine).scan()

    exporter = ReportExporter(engine)

    json_path = args.output.replace(".html", "") + ".json"
    html_path = args.output.replace(".json", "") + ".html"

    exporter.to_json(json_path)
    exporter.to_html(html_path)

    print(f"\n📄 JSON-отчёт: {json_path}")
    print(f"📄 HTML-отчёт: {html_path}")
    print("\n" + engine.summary())
    return engine.threat_score


def cmd_demo(args):
    """Конференц-демо: автоматический запуск через demo_runner."""
    import importlib.util
    demo_path = Path(__file__).resolve().parent.parent / "demo_runner.py"
    if not demo_path.exists():
        print(f"❌ Не найден demo_runner.py: {demo_path}")
        print("   Запустите напрямую: python demo_runner.py")
        return 0

    spec = importlib.util.spec_from_file_location("demo_runner", demo_path)
    demo_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo_mod)
    return demo_mod.run_demo(args)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="promptlock_defender",
        description="PromptLock Defender — антивирус для AI-powered ransomware угроз.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный вывод")

    sub = parser.add_subparsers(dest="command", help="Команды")

    # --- scan (полный) ---
    p_scan = sub.add_parser("scan", help="Полный скан (все модули)")
    p_scan.add_argument("directory", help="Директория для сканирования")
    p_scan.add_argument("-o", "--output", help="Путь для отчёта (.json или .html)")
    p_scan.add_argument("--auto-respond", action="store_true",
                        help="Автоматическая реакция при превышении порога")
    p_scan.add_argument("--threshold", type=int, default=50,
                        help="Порог угрозы для автореакции (по умолчанию 50)")
    p_scan.set_defaults(func=cmd_full_scan)

    # --- scan-fs ---
    p_fs = sub.add_parser("scan-fs", help="Сканирование файловой системы")
    p_fs.add_argument("directory", help="Директория для сканирования")
    p_fs.set_defaults(func=cmd_scan_fs)

    # --- scan-static ---
    p_st = sub.add_parser("scan-static", help="Статический анализ кода (сигнатуры)")
    p_st.add_argument("directory", help="Директория для сканирования")
    p_st.set_defaults(func=cmd_scan_static)

    # --- scan-ast ---
    p_ast = sub.add_parser("scan-ast", help="AST-анализ + эвристики + энтропия")
    p_ast.add_argument("directory", help="Директория для сканирования")
    p_ast.set_defaults(func=cmd_scan_ast)

    # --- scan-ml ---
    p_ml = sub.add_parser("scan-ml", help="ML-классификатор скриптов")
    p_ml.add_argument("directory", help="Директория для сканирования")
    p_ml.set_defaults(func=cmd_scan_ml)

    # --- scan-proc ---
    p_pr = sub.add_parser("scan-proc", help="Мониторинг процессов и сети")
    p_pr.set_defaults(func=cmd_scan_proc)

    # --- monitor (real-time) ---
    p_mon = sub.add_parser("monitor", help="Мониторинг в реальном времени (Ctrl+C для остановки)")
    p_mon.add_argument("directory", help="Директория для наблюдения")
    p_mon.set_defaults(func=cmd_monitor)

    # --- dashboard ---
    p_dash = sub.add_parser("dashboard", help="Веб-дашборд + live-мониторинг")
    p_dash.add_argument("directory", help="Директория для наблюдения")
    p_dash.add_argument("-p", "--port", type=int, default=5050, help="Порт дашборда (по умолчанию 5050)")
    p_dash.set_defaults(func=cmd_dashboard)

    # --- sandbox ---
    p_sb = sub.add_parser("sandbox", help="Динамический анализ файла в песочнице")
    p_sb.add_argument("file", help="Путь к файлу для анализа")
    p_sb.add_argument("-t", "--timeout", type=int, default=30, help="Таймаут песочницы (сек)")
    p_sb.set_defaults(func=cmd_sandbox)

    # --- report ---
    p_rep = sub.add_parser("report", help="Полный скан + экспорт JSON/HTML отчёта")
    p_rep.add_argument("directory", help="Директория для сканирования")
    p_rep.add_argument("-o", "--output", default="report", help="Базовое имя файла отчёта")
    p_rep.set_defaults(func=cmd_report)

    # --- demo ---
    p_demo = sub.add_parser("demo", help="Конференц-демо (генерация артефактов → скан → отчёт)")
    p_demo.add_argument("--test-dir", default=None,
                        help="Директория для артефактов (по умолчанию ~/promptlock_demo_test)")
    p_demo.add_argument("--file-count", type=int, default=10, help="Количество .locked файлов")
    p_demo.add_argument("--fast", action="store_true", help="Без задержек")
    p_demo.add_argument("--skip-clamav", action="store_true", help="Пропустить сравнение с ClamAV")
    p_demo.add_argument("--no-cleanup", action="store_true", help="Не удалять тестовые файлы")
    p_demo.add_argument("--no-color", action="store_true", help="Без ANSI-цветов")
    p_demo.add_argument("--log-file", default="demo_live.log", help="Путь для live-лога")
    p_demo.add_argument("-o", "--report", default="demo_report", help="Базовое имя отчёта")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    setup_logging(args.verbose)

    score = args.func(args)

    # Exit code: 0 = чисто, 1 = угрозы найдены
    sys.exit(1 if score >= 20 else 0)


if __name__ == "__main__":
    main()
