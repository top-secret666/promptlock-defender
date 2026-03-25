"""
PromptLock Defender — GUI (tkinter).
Графический интерфейс антивируса для запуска без терминала.
"""

import os
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import (
    Tk, Frame, Label, Button, Entry, Text, Scrollbar, StringVar, IntVar,
    filedialog, messagebox, ttk, BOTH, LEFT, RIGHT, TOP, BOTTOM, X, Y,
    END, DISABLED, NORMAL, WORD, N, S, E, W,
)

# Убедимся, что пакет доступен
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from promptlock_defender.engine import DetectionEngine, Severity
from promptlock_defender.fs_monitor import FileSystemScanner
from promptlock_defender.static_scanner import StaticScanner
from promptlock_defender.heuristics import EntropyAnalyzer, ASTAnalyzer
from promptlock_defender.ml_classifier import MLClassifier
from promptlock_defender.proc_monitor import ProcessMonitor
from promptlock_defender.response import AutoResponse
from promptlock_defender.report import ReportExporter
from promptlock_defender.binary_scanner import BinaryScanner
from promptlock_defender.test_artifacts import TestArtifactGenerator


# ── Цвета и стиль ────────────────────────────────────────────────────

BG_DARK = "#1a1a2e"
BG_PANEL = "#16213e"
BG_CARD = "#0f3460"
FG_TEXT = "#e0e0e0"
FG_DIM = "#8888aa"
ACCENT = "#00d4ff"
RED = "#ff4444"
ORANGE = "#ff9800"
YELLOW = "#fdd835"
GREEN = "#4caf50"
PURPLE = "#d500f9"

SEV_COLORS = {
    "LOW": YELLOW,
    "MEDIUM": ORANGE,
    "HIGH": RED,
    "CRITICAL": PURPLE,
}


class PromptLockDefenderGUI:
    """Главное окно GUI антивируса."""

    def __init__(self):
        self.root = Tk()
        self.root.title("PromptLock Defender v2.0")
        self.root.geometry("1000x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=BG_DARK)

        # Иконка (если есть)
        try:
            icon_path = Path(__file__).parent / "icon.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except Exception:
            pass

        self.engine = None
        self.scan_running = False
        self.scan_thread = None

        self._build_ui()

    # ────────────────────── UI СТРОИТЕЛЬ ──────────────────────────

    def _build_ui(self):
        # -- Заголовок --
        header = Frame(self.root, bg=BG_DARK, pady=10)
        header.pack(fill=X)

        Label(
            header, text="🛡️  PromptLock Defender", font=("Segoe UI", 20, "bold"),
            bg=BG_DARK, fg=ACCENT,
        ).pack()
        Label(
            header, text="Антивирус для AI-powered ransomware угроз",
            font=("Segoe UI", 10), bg=BG_DARK, fg=FG_DIM,
        ).pack()

        # -- Панель управления --
        ctrl = Frame(self.root, bg=BG_PANEL, padx=15, pady=10)
        ctrl.pack(fill=X, padx=10)

        # Путь к директории
        path_frame = Frame(ctrl, bg=BG_PANEL)
        path_frame.pack(fill=X, pady=(0, 8))

        Label(
            path_frame, text="Директория:", font=("Segoe UI", 10),
            bg=BG_PANEL, fg=FG_TEXT,
        ).pack(side=LEFT)

        self.dir_var = StringVar(value="")
        self.dir_entry = Entry(
            path_frame, textvariable=self.dir_var, font=("Consolas", 10),
            bg="#1c1c3a", fg=FG_TEXT, insertbackground=FG_TEXT,
            relief="flat", bd=5,
        )
        self.dir_entry.pack(side=LEFT, fill=X, expand=True, padx=(8, 4))

        Button(
            path_frame, text="📁 Обзор", command=self._browse_dir,
            font=("Segoe UI", 9), bg=BG_CARD, fg=FG_TEXT,
            activebackground=ACCENT, relief="flat", padx=10,
        ).pack(side=LEFT, padx=(4, 0))

        # Кнопки действий
        btn_frame = Frame(ctrl, bg=BG_PANEL)
        btn_frame.pack(fill=X)

        self.scan_btn = Button(
            btn_frame, text="🔍 Полный скан", command=self._start_scan,
            font=("Segoe UI", 11, "bold"), bg=ACCENT, fg="#000",
            activebackground="#00a0cc", relief="flat", padx=20, pady=6,
        )
        self.scan_btn.pack(side=LEFT, padx=(0, 6))

        Button(
            btn_frame, text="🧪 Генерация тестовых артефактов",
            command=self._generate_artifacts,
            font=("Segoe UI", 9), bg=BG_CARD, fg=FG_TEXT,
            activebackground=ACCENT, relief="flat", padx=12, pady=6,
        ).pack(side=LEFT, padx=(0, 6))

        Button(
            btn_frame, text="📋 HTML-отчёт", command=self._export_report,
            font=("Segoe UI", 9), bg=BG_CARD, fg=FG_TEXT,
            activebackground=ACCENT, relief="flat", padx=12, pady=6,
        ).pack(side=LEFT, padx=(0, 6))

        Button(
            btn_frame, text="🗑️ Очистить", command=self._clear_results,
            font=("Segoe UI", 9), bg="#333", fg=FG_TEXT,
            activebackground="#555", relief="flat", padx=12, pady=6,
        ).pack(side=RIGHT)

        # -- Индикаторы --
        self.score_frame = Frame(self.root, bg=BG_DARK, pady=6)
        self.score_frame.pack(fill=X, padx=10)

        self.score_label = Label(
            self.score_frame, text="Уровень угрозы: —",
            font=("Segoe UI", 14, "bold"), bg=BG_DARK, fg=FG_DIM,
        )
        self.score_label.pack(side=LEFT, padx=10)

        self.alerts_label = Label(
            self.score_frame, text="Алертов: 0",
            font=("Segoe UI", 11), bg=BG_DARK, fg=FG_DIM,
        )
        self.alerts_label.pack(side=LEFT, padx=20)

        self.time_label = Label(
            self.score_frame, text="",
            font=("Segoe UI", 10), bg=BG_DARK, fg=FG_DIM,
        )
        self.time_label.pack(side=RIGHT, padx=10)

        # -- Прогресс-бар --
        self.progress_var = IntVar(value=0)
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=BG_PANEL, background=ACCENT,
            thickness=8,
        )
        self.progress = ttk.Progressbar(
            self.root, variable=self.progress_var, maximum=100,
            style="Custom.Horizontal.TProgressbar",
        )
        self.progress.pack(fill=X, padx=10, pady=(0, 4))

        self.status_var = StringVar(value="Готов к сканированию")
        Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 9), bg=BG_DARK, fg=FG_DIM, anchor="w",
        ).pack(fill=X, padx=14)

        # -- Лог алертов --
        log_frame = Frame(self.root, bg=BG_DARK, padx=10, pady=6)
        log_frame.pack(fill=BOTH, expand=True)

        Label(
            log_frame, text="Журнал обнаружений:", font=("Segoe UI", 10, "bold"),
            bg=BG_DARK, fg=FG_TEXT, anchor="w",
        ).pack(fill=X)

        text_frame = Frame(log_frame, bg=BG_DARK)
        text_frame.pack(fill=BOTH, expand=True, pady=(4, 0))

        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        self.log_text = Text(
            text_frame, font=("Consolas", 9), bg="#0d0d1a", fg=FG_TEXT,
            relief="flat", bd=8, wrap=WORD, state=DISABLED,
            yscrollcommand=scrollbar.set, selectbackground=ACCENT,
        )
        self.log_text.pack(fill=BOTH, expand=True)
        scrollbar.config(command=self.log_text.yview)

        # Тэги для цветного текста
        self.log_text.tag_configure("critical", foreground=PURPLE, font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("high", foreground=RED)
        self.log_text.tag_configure("medium", foreground=ORANGE)
        self.log_text.tag_configure("low", foreground=YELLOW)
        self.log_text.tag_configure("info", foreground=ACCENT)
        self.log_text.tag_configure("success", foreground=GREEN)
        self.log_text.tag_configure("dim", foreground=FG_DIM)
        self.log_text.tag_configure("header", foreground=ACCENT, font=("Consolas", 10, "bold"))

        # -- Footer --
        footer = Frame(self.root, bg=BG_PANEL, pady=4)
        footer.pack(fill=X, side=BOTTOM)
        Label(
            footer, text="PromptLock Defender v2.0 — Conference Edition",
            font=("Segoe UI", 8), bg=BG_PANEL, fg=FG_DIM,
        ).pack()

    # ────────────────────── ЛОГИРОВАНИЕ ───────────────────────────

    def _log(self, text: str, tag: str = "info"):
        self.log_text.config(state=NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(END, f"[{ts}] ", "dim")
        self.log_text.insert(END, text + "\n", tag)
        self.log_text.see(END)
        self.log_text.config(state=DISABLED)

    def _log_alert(self, alert):
        sev = alert.severity.value.lower()
        ts = alert.timestamp.strftime("%H:%M:%S.%f")[:-3]
        src = f"  ← {alert.source_path}" if alert.source_path else ""

        self.log_text.config(state=NORMAL)
        self.log_text.insert(END, f"[{ts}] ", "dim")
        self.log_text.insert(END, f"[{alert.severity.value:8}] ", sev)
        self.log_text.insert(END, f"{alert.description}{src}\n", sev)
        self.log_text.see(END)
        self.log_text.config(state=DISABLED)

    # ────────────────────── ДЕЙСТВИЯ ──────────────────────────────

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Выберите директорию для сканирования")
        if d:
            self.dir_var.set(d)

    def _clear_results(self):
        self.log_text.config(state=NORMAL)
        self.log_text.delete("1.0", END)
        self.log_text.config(state=DISABLED)
        self.score_label.config(text="Уровень угрозы: —", fg=FG_DIM)
        self.alerts_label.config(text="Алертов: 0", fg=FG_DIM)
        self.time_label.config(text="")
        self.progress_var.set(0)
        self.status_var.set("Готов к сканированию")
        self.engine = None

    def _get_scan_dir(self) -> str:
        d = self.dir_var.get().strip()
        if not d:
            messagebox.showwarning("Внимание", "Укажите директорию для сканирования.")
            return ""
        if not os.path.isdir(d):
            messagebox.showerror("Ошибка", f"Директория не найдена:\n{d}")
            return ""
        return d

    # ────────────────────── СКАНИРОВАНИЕ ──────────────────────────

    def _start_scan(self):
        scan_dir = self._get_scan_dir()
        if not scan_dir:
            return
        if self.scan_running:
            return

        self.scan_running = True
        self.scan_btn.config(state=DISABLED, text="⏳ Сканирование...")
        self.progress_var.set(0)

        self.scan_thread = threading.Thread(
            target=self._run_scan, args=(scan_dir,), daemon=True
        )
        self.scan_thread.start()

    def _run_scan(self, scan_dir: str):
        """Полный скан в отдельном потоке."""
        try:
            self.engine = DetectionEngine()
            self.engine.start_scan()

            # Патчим add_alert для live-вывода в GUI
            _original = self.engine.add_alert
            def _patched(alert):
                _original(alert)
                self.root.after(0, self._log_alert, alert)
                self.root.after(0, self._update_score)
            self.engine.add_alert = _patched

            start_time = time.perf_counter()

            modules = [
                ("Файловая система", 12,
                 lambda: FileSystemScanner(self.engine).scan_directory(scan_dir)),
                ("Статический анализ (сигнатуры)", 28,
                 lambda: StaticScanner(self.engine).scan_directory(scan_dir)),
                ("Анализ бинарников (ELF/PE)", 42,
                 lambda: BinaryScanner(self.engine).scan_directory(scan_dir)),
                ("AST-анализ + поведение", 55,
                 lambda: ASTAnalyzer(self.engine).scan_directory(scan_dir)),
                ("Анализ энтропии", 68,
                 lambda: EntropyAnalyzer(self.engine).scan_directory(scan_dir)),
                ("ML-классификатор", 82, None),  # special
                ("Мониторинг процессов", 95,
                 lambda: ProcessMonitor(self.engine).scan()),
            ]

            for name, progress, fn in modules:
                self.root.after(0, self.status_var.set, f"Шаг: {name}...")
                self.root.after(0, self._log, f"▶ {name}...", "header")

                step_start = time.perf_counter()

                if name == "ML-классификатор":
                    ml = MLClassifier(self.engine)
                    ml.train()
                    count = ml.scan_directory(scan_dir)
                else:
                    count = fn()

                step_time = time.perf_counter() - step_start
                self.root.after(
                    0, self._log,
                    f"  ✓ {name}: {count} алертов [{step_time:.3f}s]",
                    "success",
                )
                self.root.after(0, self.progress_var.set, progress)

            total_time = time.perf_counter() - start_time
            self.root.after(0, self.progress_var.set, 100)
            self.root.after(0, self.status_var.set, f"Скан завершён за {total_time:.2f}s")
            self.root.after(0, self.time_label.config, {"text": f"⏱ {total_time:.2f}s"})
            self.root.after(0, self._update_score)

            # Итоги
            self.root.after(0, self._log, "", "dim")
            self.root.after(
                0, self._log,
                f"{'═' * 50}", "dim",
            )
            self.root.after(
                0, self._log,
                f"ИТОГО: {len(self.engine.alerts)} алертов, "
                f"угроза {self.engine.threat_score}/100, "
                f"время {total_time:.3f}s",
                "header",
            )
            if self.engine.first_alert_time is not None:
                self.root.after(
                    0, self._log,
                    f"Первый алерт через: {self.engine.first_alert_time:.3f}s",
                    "info",
                )

            # --- ПОЯСНЕНИЕ ДЛЯ ПОЛЬЗОВАТЕЛЯ ---
            def _is_minor_alert(alert):
                # Только энтропия (и LOW), или только одна категория
                if alert.severity == Severity.LOW and (
                    "энтропия" in alert.description.lower() or
                    "обфусцирован" in alert.description.lower()
                ):
                    return True
                # Одиночная категория (lua, openssl, aes, .locked)
                desc = alert.description.lower()
                for kw in ["lua", "openssl", "aes", ".locked"]:
                    if kw in desc and alert.severity in (Severity.LOW, Severity.MEDIUM):
                        return True
                return False

            alerts = self.engine.alerts
            if alerts and all(_is_minor_alert(a) for a in alerts):
                self.root.after(0, self._log,
                    "ℹ️ Найдены только малозначимые алерты (например, высокая энтропия или одиночная сигнатура).\n"
                    "Это не признак угрозы — такие файлы встречаются в обычных программах, офисных документах, архивах и играх.",
                    "info"
                )

        except Exception as e:
            self.root.after(0, self._log, f"ОШИБКА: {e}", "critical")
        finally:
            self.scan_running = False
            self.root.after(0, self.scan_btn.config, {
                "state": NORMAL, "text": "🔍 Полный скан"
            })

    def _update_score(self):
        if not self.engine:
            return
        score = self.engine.threat_score
        total = len(self.engine.alerts)

        alerts = self.engine.alerts
        def _is_minor_alert(alert):
            if alert.severity == Severity.LOW and (
                "энтропия" in alert.description.lower() or
                "обфусцирован" in alert.description.lower()
            ):
                return True
            desc = alert.description.lower()
            for kw in ["lua", "openssl", "aes", ".locked"]:
                if kw in desc and alert.severity in (Severity.LOW, Severity.MEDIUM):
                    return True
            return False

        # Если найден вирус PromptLock — выделить особо
        found_promptlock = any(
            ("promptlock" in (a.description or '').lower() and a.severity == Severity.CRITICAL)
            for a in alerts
        )
        if found_promptlock:
            self.score_label.config(
                text="🚨 НАЙДЕН ВИРУС: PROMPTLOCK",
                fg=RED,
            )
            self.alerts_label.config(text=f"Алертов: {total}", fg=RED)
            return

        # Если только малозначимые алерты — писать 'Малый риск угрозы'
        if alerts and all(_is_minor_alert(a) for a in alerts):
            self.score_label.config(
                text="🟡 Малый риск угрозы",
                fg=YELLOW,
            )
            self.alerts_label.config(text=f"Алертов: {total}", fg=YELLOW)
            return

        # Обычный режим
        if score >= 50:
            color = RED
            icon = "🚨"
        elif score >= 20:
            color = ORANGE
            icon = "⚠️"
        else:
            color = GREEN
            icon = "✅"

        self.score_label.config(
            text=f"{icon} Уровень угрозы: {score}/100",
            fg=color,
        )
        self.alerts_label.config(text=f"Алертов: {total}", fg=FG_TEXT)

    # ────────────────────── ГЕНЕРАЦИЯ АРТЕФАКТОВ ──────────────────

    def _generate_artifacts(self):
        d = filedialog.askdirectory(title="Выберите папку для тестовых артефактов")
        if not d:
            return

        self._log("Генерация безопасных тестовых артефактов...", "info")

        def _gen():
            try:
                gen = TestArtifactGenerator(d)
                gen.generate_all(count=10, delay=0)
                self.root.after(
                    0, self._log,
                    f"✅ Создано {len(gen.created_files)} тестовых файлов в {d}",
                    "success",
                )
                self.root.after(0, self.dir_var.set, d)
                self.root.after(
                    0, lambda: messagebox.showinfo(
                        "Готово",
                        f"Создано {len(gen.created_files)} тестовых файлов.\n"
                        f"Директория: {d}\n\n"
                        "Нажмите 'Полный скан' для проверки.",
                    )
                )
            except Exception as e:
                self.root.after(0, self._log, f"ОШИБКА: {e}", "critical")

        threading.Thread(target=_gen, daemon=True).start()

    # ────────────────────── ЭКСПОРТ ОТЧЁТА ────────────────────────

    def _export_report(self):
        if not self.engine or not self.engine.alerts:
            messagebox.showinfo("Информация", "Сначала выполните сканирование.")
            return

        path = filedialog.asksaveasfilename(
            title="Сохранить отчёт",
            defaultextension=".html",
            filetypes=[("HTML-отчёт", "*.html"), ("JSON-отчёт", "*.json")],
            initialfile=f"promptlock_report_{datetime.now():%Y%m%d_%H%M%S}",
        )
        if not path:
            return

        exporter = ReportExporter(self.engine)

        if path.endswith(".json"):
            exporter.to_json(path)
        else:
            exporter.to_html(path)
            # Также создаём JSON рядом
            json_path = path.rsplit(".", 1)[0] + ".json"
            exporter.to_json(json_path)

        self._log(f"📄 Отчёт сохранён: {path}", "success")
        webbrowser.open(path)

    # ────────────────────── ЗАПУСК ────────────────────────────────

    def run(self):
        self.root.mainloop()


def main():
    app = PromptLockDefenderGUI()
    app.run()


if __name__ == "__main__":
    main()
