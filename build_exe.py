"""
Скрипт сборки PromptLock Defender в standalone EXE.

Требования:
    pip install pyinstaller

Сборка:
    python build_exe.py             — собрать в папку (рекомендуется)
    python build_exe.py --onefile   — собрать в один EXE (медленнее запуск)

Результат:
    dist/PromptLockDefender/        (по умолчанию, --onedir)
    dist/PromptLockDefender.exe     (--onefile)

После сборки:
    Запустить installer.iss через Inno Setup → получите Setup_PromptLockDefender.exe
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFENDER_PKG = ROOT / "promptlock_defender"
ENTRY_POINT = DEFENDER_PKG / "gui.py"
ICON_PATH = ROOT / "icon.ico"

APP_NAME = "PromptLockDefender"
APP_VERSION = "2.0"


def build(onefile: bool = False):
    """Запуск PyInstaller."""

    # Проверяем PyInstaller
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("⚠️  PyInstaller не установлен. Устанавливаю...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", APP_NAME,
        "--noconfirm",
        "--clean",
        "--windowed",  # без консольного окна (GUI)
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    # Иконка (если есть)
    if ICON_PATH.exists():
        cmd.extend(["--icon", str(ICON_PATH)])

    # Скрытые импорты (модули, которые PyInstaller может не найти)
    hidden = [
        "promptlock_defender",
        "promptlock_defender.engine",
        "promptlock_defender.fs_monitor",
        "promptlock_defender.static_scanner",
        "promptlock_defender.heuristics",
        "promptlock_defender.ml_classifier",
        "promptlock_defender.proc_monitor",
        "promptlock_defender.response",
        "promptlock_defender.report",
        "promptlock_defender.binary_scanner",
        "promptlock_defender.test_artifacts",
        "promptlock_defender.realtime_monitor",
        "promptlock_defender.sandbox",
        "promptlock_defender.dashboard",
    ]
    for h in hidden:
        cmd.extend(["--hidden-import", h])

    # Добавляем весь пакет как data (чтобы __init__.py и всё остальное попало)
    cmd.extend(["--add-data", f"{DEFENDER_PKG}{os.pathsep}promptlock_defender"])

    # Точка входа
    cmd.append(str(ENTRY_POINT))

    mode = "onefile" if onefile else "onedir"
    print(f"\n🔧 Команда сборки:\n   {' '.join(cmd)}\n")
    print("=" * 60)
    print(f"  Сборка {APP_NAME} v{APP_VERSION}")
    print(f"  Режим: {mode}")
    print(f"  Точка входа: {ENTRY_POINT}")
    print("=" * 60)

    result = subprocess.run(cmd, cwd=str(ROOT))

    if result.returncode == 0:
        if onefile:
            exe_path = ROOT / "dist" / f"{APP_NAME}.exe"
        else:
            exe_path = ROOT / "dist" / APP_NAME / f"{APP_NAME}.exe"

        print(f"\n✅ Сборка завершена!")
        print(f"   EXE: {exe_path}")
        size_mb = exe_path.stat().st_size / (1024 * 1024) if exe_path.exists() else 0
        print(f"   Размер: {size_mb:.1f} MB")

        if not onefile:
            dist_dir = ROOT / "dist" / APP_NAME
            total = sum(f.stat().st_size for f in dist_dir.rglob("*") if f.is_file())
            print(f"   Размер папки: {total / (1024 * 1024):.1f} MB")
            print(f"\n   💡 Для создания установщика:")
            print(f"      1. Скачайте Inno Setup: https://jrsoftware.org/isinfo.php")
            print(f"      2. Откройте installer.iss")
            print(f"      3. Нажмите Compile → получите Setup_{APP_NAME}.exe")
    else:
        print(f"\n❌ Ошибка сборки (код {result.returncode})")
        sys.exit(1)


def main():
    onefile = "--onefile" in sys.argv
    build(onefile=onefile)


if __name__ == "__main__":
    main()
