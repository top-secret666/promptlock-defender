<div align="center">

# 🛡️ PromptLock Defender

**Антивирус для AI-powered ransomware нового поколения**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2B-lightblue?logo=windows)](https://github.com/top-secret666/promptlock-defender)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/top-secret666/promptlock-defender?style=flat)](https://github.com/top-secret666/promptlock-defender/stargazers)

> **PromptLock** — новый класс вирусов-вымогателей, которые используют локальные AI-модели (Ollama/LLaMA) для генерации Lua-скриптов шифрования и обхода антивирусов.  
> **PromptLock Defender** обнаруживает их до того, как они успевают зашифровать ваши файлы.

</div>

---

## 🎯 Как это работает

PromptLock действует в 3 этапа:
1. **Jailbreak** → отправляет промпт к локальной AI (Ollama `localhost:11434`)
2. **Генерация кода** → AI создаёт Lua-скрипт для шифрования файлов AES-256
3. **Шифрование** → скрипт шифрует все файлы, оставляет записку `README_TO_DECRYPT.txt`

**PromptLock Defender** перехватывает на каждом этапе через **7 независимых модулей**:

| Модуль | Что обнаруживает |
|--------|-----------------|
| 🗂️ Файловая система | `.locked` файлы, записки выкупа, массовое переименование |
| 🔍 Сигнатурный анализ | Jailbreak-промпты, LLM API вызовы, крипто-паттерны в коде |
| 🔬 Бинарный анализатор | SHA256 по базе 7 реальных образцов с MalwareBazaar, строки в ELF/PE |
| 🌳 AST-анализ | Вредоносные цепочки в Python-коде (чтение→шифрование→удаление) |
| 📊 Энтропия | Зашифрованные/обфусцированные файлы (учитывает тип файла) |
| 🤖 ML-классификатор | TF-IDF + Logistic Regression по паттернам кода |
| 🖥️ Мониторинг процессов | ollama, luajit, подозрительные сетевые соединения (порт 11434) |

---

## 🚀 Быстрый старт

### Вариант 1 — Standalone EXE (без Python)

```
1. Скачайте dist/PromptLockDefender/ из релизов
2. Запустите PromptLockDefender.exe
3. Выберите директорию → нажмите «Полный скан»
```

> ⚠️ Требует **Windows 10 (64-бит)** или новее.

---

### Вариант 2 — Python (разработка / Linux)

```bash
# 1. Клонировать репозиторий
git clone https://github.com/top-secret666/promptlock-defender.git
cd promptlock-defender

# 2. Создать виртуальное окружение
python -m venv .venv

# Windows:
.venv\Scripts\activate

# Linux/Mac:
source .venv/bin/activate

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Запустить GUI
python -m promptlock_defender.gui

# Или CLI — полный скан директории
python -m promptlock_defender scan C:\Users\
```

---

### Вариант 3 — Сборка EXE самостоятельно

```bash
pip install pyinstaller

# Собрать папку (рекомендуется, быстрее запуск)
python build_exe.py

# Собрать один файл
python build_exe.py --onefile
```

Результат: `dist/PromptLockDefender/PromptLockDefender.exe`

Для создания установщика:
1. Скачайте [Inno Setup](https://jrsoftware.org/isinfo.php)
2. Откройте `installer.iss` → Compile
3. Получите `Output/Setup_PromptLockDefender.exe`

---

## 📋 CLI-команды

```bash
# Полный скан директории (все модули)
python -m promptlock_defender scan <path>

# Только файловая система
python -m promptlock_defender scan-fs <path>

# Только статический анализ кода
python -m promptlock_defender scan-static <path>

# Live-мониторинг в реальном времени
python -m promptlock_defender monitor <path>

# Веб-дашборд (открывается в браузере)
python -m promptlock_defender dashboard

# Конференц-демо (7 фаз с таймингом)
python -m promptlock_defender demo

# HTML/JSON отчёт
python -m promptlock_defender report <path>
```

---

## 🧪 Тестирование

### Безопасные тестовые артефакты

```bash
# Сгенерировать безопасные тестовые файлы (настоящих вирусов нет)
python -m promptlock_defender scan <path> --generate-test
```

В GUI: кнопка **«🧪 Генерация тестовых артефактов»**

### Реальные образцы PromptLock

> ⚠️ Только в **изолированной VM** с отключённой сетью!

1. [MalwareBazaar](https://bazaar.abuse.ch) → поиск по тегу `PromptLock`
2. Скачать ZIP (пароль: `infected`), распаковать в VM
3. Запустить антивирус → указать папку с образцами

---

## 📊 Уровни угрозы в GUI

| Индикатор | Значение |
|-----------|----------|
| 🚨 **НАЙДЕН ВИРУС: PROMPTLOCK** | Прямое совпадение хэша или строки "promptlock" |
| 🔴 Уровень угрозы: 50+/100 | Несколько категорий маркеров вместе |
| 🟡 **Малый риск угрозы** | Только одиночные сигнатуры или энтропия |
| ✅ Угроз не обнаружено | Всё чисто |

> ℹ️ Высокая энтропия у `.docx`, `.pdf`, `.pptx`, `.png`, `.mp3` — это **нормально**, антивирус помечает их как LOW и не паникует.

---

## 🗂️ Структура проекта

```
promptlock-defender/
├── promptlock_defender/
│   ├── engine.py           # Ядро: алерты, скоринг угрозы
│   ├── fs_monitor.py       # Сканер файловой системы
│   ├── static_scanner.py   # Сигнатурный анализ кода
│   ├── binary_scanner.py   # Анализ ELF/PE бинарников
│   ├── heuristics.py       # AST + энтропия + поведение
│   ├── ml_classifier.py    # ML (TF-IDF + LogReg)
│   ├── proc_monitor.py     # Мониторинг процессов/сети
│   ├── realtime_monitor.py # Live-мониторинг (watchdog)
│   ├── sandbox.py          # Docker-песочница
│   ├── response.py         # Авто-реакция (карантин, kill)
│   ├── dashboard.py        # Веб-дашборд (Flask)
│   ├── report.py           # Экспорт HTML/JSON отчётов
│   ├── test_artifacts.py   # Генератор тестовых данных
│   ├── gui.py              # GUI (tkinter, тёмная тема)
│   └── __main__.py         # CLI (12 команд)
├── demo_runner.py          # Демо-оркестратор для конференции
├── build_exe.py            # Сборка в EXE (PyInstaller)
├── installer.iss           # Inno Setup — установщик
└── requirements.txt
```

---

## 📦 Зависимости

```
watchdog>=3.0       # Мониторинг файловой системы
psutil>=5.9         # Мониторинг процессов
flask>=3.0          # Веб-дашборд
scikit-learn>=1.3   # ML-классификатор
```

---

<div align="center">

Made for conference demo · Python 3.11 · Windows 10+

</div>
