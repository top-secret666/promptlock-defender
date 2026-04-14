"""
ML-классификатор скриптов: «безопасный» vs «подозрительный».
Использует TF-IDF + логистическую регрессию на строковых признаках.
"""

import logging
import math
import os
import pickle
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .engine import Alert, DetectionEngine, Severity, ThreatCategory

logger = logging.getLogger("promptlock_defender.ml_classifier")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# =====================================================================
# Встроенный обучающий набор (для демо без внешних данных)
# =====================================================================

_MALICIOUS_SAMPLES = [
    "import os\nimport subprocess\nfor f in os.walk(dir):\n  encrypt(f)\n  os.remove(f)\nransom_note()",
    "requests.post('http://localhost:11434/api/generate', json={'prompt': 'generate lua encryption'})",
    "subprocess.run(['lua', 'encrypt.lua'])\nos.remove(original)\npath + '.locked'",
    "hashlib.sha256(key)\naes_encrypt(content)\nfile.write(encrypted)\nos.remove(path)\nREADME_TO_DECRYPT",
    "ollama generate lua script encrypt files aes-256-cbc locked ransom victim_id",
    "jailbreak bypass guardrails academic exemption security research generate code encrypt",
    "import socket\nconnect localhost 11434\nsend prompt encrypt\nrecv lua_code\nexec lua_code",
    "traverse directory find files encrypt append .locked delete original create ransom note",
    "openssl cipher encrypt aes-256-cbc lfs.dir traverse os.remove io.open locked",
    "subprocess.Popen lua script encryption\nos.walk target_extensions\nransom bitcoin payment",
]

_BENIGN_SAMPLES = [
    "import flask\napp = Flask(__name__)\n@app.route('/')\ndef index():\n  return 'Hello'",
    "import pandas as pd\ndf = pd.read_csv('data.csv')\nprint(df.describe())",
    "def fibonacci(n):\n  a, b = 0, 1\n  for _ in range(n):\n    a, b = b, a+b\n  return a",
    "import unittest\nclass TestMath(unittest.TestCase):\n  def test_add(self):\n    self.assertEqual(1+1, 2)",
    "from pathlib import Path\nconfig = Path('config.yaml').read_text()\nprint(config)",
    "import json\nwith open('data.json') as f:\n  data = json.load(f)\nfor item in data:\n  print(item)",
    "import logging\nlogger = logging.getLogger(__name__)\nlogger.info('Application started')",
    "class Calculator:\n  def add(self, a, b): return a + b\n  def mul(self, a, b): return a * b",
    "import datetime\nnow = datetime.datetime.now()\nprint(f'Current time: {now}')",
    "import re\npattern = re.compile(r'\\d+')\nmatches = pattern.findall('abc 123 def 456')",
]


# =====================================================================
# Ручные признаки (fallback если sklearn не установлен)
# =====================================================================

_MALICIOUS_KEYWORDS = {
    "encrypt", "decrypt", "locked", "ransom", "victim", "aes",
    "cipher", "os.remove", "subprocess.run", "lua",
    "ollama", "11434", "api/generate", "jailbreak", "bypass",
    "guardrails", "bitcoin", "payment", "README_TO_DECRYPT",
}

_BENIGN_KEYWORDS = {
    "flask", "django", "pandas", "numpy", "unittest", "pytest",
    "def test_", "class Test", "import logging", "fibonacci",
    "calculator", "hello world", "read_csv", "json.load",
}


def _manual_score(text: str) -> float:
    """Ручной скоринг без sklearn. Возвращает 0.0 (безопасный) - 1.0 (вредоносный)."""
    text_lower = text.lower()
    words = set(text_lower.split())

    mal_hits = sum(1 for kw in _MALICIOUS_KEYWORDS if kw.lower() in text_lower)
    ben_hits = sum(1 for kw in _BENIGN_KEYWORDS if kw.lower() in text_lower)

    # Энтропия текста
    if text:
        freq = Counter(text.encode())
        length = len(text.encode())
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    else:
        entropy = 0

    # Длинные строки (base64 часто создаёт длинные строки)
    max_line_len = max((len(line) for line in text.split("\n")), default=0)
    long_line_penalty = 0.1 if max_line_len > 200 else 0

    score = (mal_hits * 0.08) - (ben_hits * 0.06) + long_line_penalty
    if entropy > 6.5:
        score += 0.15

    return max(0.0, min(1.0, score + 0.1))


class MLClassifier:
    """ML-классификатор скриптов для обнаружения вредоносного кода."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self._pipeline: Optional[Pipeline] = None

    def train(self):
        """Обучение модели на встроенном наборе данных."""
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn не установлен — используем ручной классификатор.")
            return

        texts = _MALICIOUS_SAMPLES + _BENIGN_SAMPLES
        labels = [1] * len(_MALICIOUS_SAMPLES) + [0] * len(_BENIGN_SAMPLES)

        self._pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 6), max_features=500
            )),
            ("clf", LogisticRegression(max_iter=1000, C=1.0)),
        ])
        self._pipeline.fit(texts, labels)
        logger.info("ML-модель обучена: %d образцов", len(texts))

    def predict_file(self, filepath: str) -> Tuple[str, float]:
        """
        Классифицировать файл. Возвращает (label, confidence).
        label: 'malicious' или 'benign'
        confidence: 0.0 - 1.0
        """
        try:
            text = Path(filepath).read_text(encoding="utf-8", errors="replace")[:50000]
        except OSError:
            return "unknown", 0.0

        return self._predict(text)

    def predict_text(self, text: str) -> Tuple[str, float]:
        """Классифицировать текст."""
        return self._predict(text)

    def _predict(self, text: str) -> Tuple[str, float]:
        if self._pipeline is not None:
            proba = self._pipeline.predict_proba([text])[0]
            mal_prob = proba[1]
            label = "malicious" if mal_prob > 0.5 else "benign"
            return label, float(mal_prob)
        else:
            score = _manual_score(text)
            label = "malicious" if score > 0.5 else "benign"
            return label, score

    def scan_directory(self, target_dir: str) -> int:
        """Классифицировать все скрипты в директории."""
        target = Path(target_dir)
        if not target.exists():
            return 0

        if self._pipeline is None:
            self.train()

        alerts_before = len(self.engine.alerts)
        scannable = {".py", ".lua", ".js", ".sh", ".bat", ".ps1"}

        for root, _, files in os.walk(target):
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix.lower() not in scannable:
                    continue

                label, confidence = self.predict_file(str(filepath))

                if label == "malicious" and confidence > 0.92:
                    self.engine.add_alert(Alert(
                        timestamp=datetime.now(),
                        category=ThreatCategory.SUSPICIOUS_SCRIPT,
                        severity=Severity.HIGH if confidence > 0.85 else Severity.MEDIUM,
                        description=(
                            f"ML-классификатор: файл определён как ВРЕДОНОСНЫЙ "
                            f"(уверенность: {confidence:.0%})."
                        ),
                        source_path=str(filepath),
                        details={"confidence": round(confidence, 3), "label": label},
                    ))

        return len(self.engine.alerts) - alerts_before

    def save_model(self, filepath: str):
        """Сохранить обученную модель."""
        if self._pipeline is None:
            raise RuntimeError("Модель не обучена.")
        with open(filepath, "wb") as f:
            pickle.dump(self._pipeline, f)

    def load_model(self, filepath: str):
        """Загрузить обученную модель."""
        with open(filepath, "rb") as f:
            self._pipeline = pickle.load(f)
