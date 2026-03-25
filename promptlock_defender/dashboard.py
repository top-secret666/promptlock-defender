"""
Веб-дашборд для визуализации работы PromptLock Defender.
Flask-приложение с живым обновлением алертов.
"""

import json
import logging
import threading
from datetime import datetime
from typing import Optional

try:
    from flask import Flask, jsonify, render_template_string
except ImportError:
    Flask = None

from .engine import DetectionEngine, Severity

logger = logging.getLogger("promptlock_defender.dashboard")

# =====================================================================
# HTML-шаблон дашборда
# =====================================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PromptLock Defender — Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #0a0a1a;
            color: #e0e0e0;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1a1a3e 0%, #0d0d2b 100%);
            padding: 20px 30px;
            border-bottom: 2px solid #2a2a5a;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { color: #00d4ff; font-size: 24px; }
        .header .status { font-size: 14px; color: #888; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .score-panel {
            background: #12122e;
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin-bottom: 20px;
            border: 1px solid #2a2a5a;
        }
        .score-value {
            font-size: 72px;
            font-weight: bold;
            margin: 10px 0;
        }
        .score-label { font-size: 14px; color: #888; }
        .score-green { color: #00ff88; }
        .score-yellow { color: #ffdd00; }
        .score-red { color: #ff4444; }
        .score-critical { color: #ff0040; text-shadow: 0 0 20px rgba(255,0,64,0.5); }
        .stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #12122e;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border: 1px solid #2a2a5a;
        }
        .stat-card .number { font-size: 32px; font-weight: bold; }
        .stat-card .label { font-size: 12px; color: #888; margin-top: 5px; }
        .stat-low .number { color: #ffdd00; }
        .stat-medium .number { color: #ff8800; }
        .stat-high .number { color: #ff4444; }
        .stat-critical .number { color: #ff0040; }
        .alerts-panel {
            background: #12122e;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2a2a5a;
        }
        .alerts-panel h2 { margin-bottom: 15px; color: #00d4ff; }
        .alert-item {
            background: #0a0a1a;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #888;
            animation: fadeIn 0.3s ease;
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; } }
        .alert-item.sev-LOW { border-left-color: #ffdd00; }
        .alert-item.sev-MEDIUM { border-left-color: #ff8800; }
        .alert-item.sev-HIGH { border-left-color: #ff4444; }
        .alert-item.sev-CRITICAL { border-left-color: #ff0040; background: #1a0a10; }
        .alert-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            margin-right: 8px;
        }
        .sev-LOW .alert-severity { background: #332d00; color: #ffdd00; }
        .sev-MEDIUM .alert-severity { background: #331a00; color: #ff8800; }
        .sev-HIGH .alert-severity { background: #330a0a; color: #ff4444; }
        .sev-CRITICAL .alert-severity { background: #330010; color: #ff0040; }
        .alert-category { font-size: 12px; color: #888; }
        .alert-desc { margin-top: 8px; }
        .alert-source { font-size: 12px; color: #666; margin-top: 5px; }
        .alert-time { font-size: 11px; color: #555; float: right; }
        .timeline {
            width: 100%;
            height: 60px;
            background: #0a0a1a;
            border-radius: 8px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
            border: 1px solid #2a2a5a;
        }
        .timeline-dot {
            width: 8px; height: 8px;
            border-radius: 50%;
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
        }
        .timeline-dot.sev-LOW { background: #ffdd00; }
        .timeline-dot.sev-MEDIUM { background: #ff8800; }
        .timeline-dot.sev-HIGH { background: #ff4444; }
        .timeline-dot.sev-CRITICAL { background: #ff0040; box-shadow: 0 0 8px rgba(255,0,64,0.8); }
        .no-alerts { text-align: center; color: #444; padding: 40px; font-size: 18px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#x1f6e1; PromptLock Defender</h1>
        <div class="status" id="status">Подключение...</div>
    </div>
    <div class="container">
        <div class="score-panel">
            <div class="score-label">УРОВЕНЬ УГРОЗЫ</div>
            <div class="score-value" id="score">0</div>
            <div class="score-label">/ 100</div>
        </div>
        <div class="stats-row">
            <div class="stat-card stat-low">
                <div class="number" id="count-low">0</div>
                <div class="label">LOW</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="number" id="count-medium">0</div>
                <div class="label">MEDIUM</div>
            </div>
            <div class="stat-card stat-high">
                <div class="number" id="count-high">0</div>
                <div class="label">HIGH</div>
            </div>
            <div class="stat-card stat-critical">
                <div class="number" id="count-critical">0</div>
                <div class="label">CRITICAL</div>
            </div>
        </div>
        <div class="timeline" id="timeline"></div>
        <div class="alerts-panel">
            <h2>&#x1f514; Алерты</h2>
            <div id="alerts"><div class="no-alerts">Угроз не обнаружено</div></div>
        </div>
    </div>
    <script>
        function getScoreClass(score) {
            if (score >= 50) return 'score-critical';
            if (score >= 30) return 'score-red';
            if (score >= 10) return 'score-yellow';
            return 'score-green';
        }

        function updateDashboard() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    const scoreEl = document.getElementById('score');
                    scoreEl.textContent = data.threat_score;
                    scoreEl.className = 'score-value ' + getScoreClass(data.threat_score);

                    document.getElementById('count-low').textContent = data.by_severity.LOW || 0;
                    document.getElementById('count-medium').textContent = data.by_severity.MEDIUM || 0;
                    document.getElementById('count-high').textContent = data.by_severity.HIGH || 0;
                    document.getElementById('count-critical').textContent = data.by_severity.CRITICAL || 0;

                    document.getElementById('status').textContent =
                        'Обновлено: ' + new Date().toLocaleTimeString() +
                        ' | Алертов: ' + data.total_alerts;

                    // Таймлайн
                    const tl = document.getElementById('timeline');
                    tl.innerHTML = '';
                    if (data.alerts.length > 0) {
                        const times = data.alerts.map(a => new Date(a.timestamp).getTime());
                        const minT = Math.min(...times);
                        const maxT = Math.max(...times);
                        const range = maxT - minT || 1;
                        data.alerts.forEach(a => {
                            const dot = document.createElement('div');
                            dot.className = 'timeline-dot sev-' + a.severity;
                            const pos = ((new Date(a.timestamp).getTime() - minT) / range) * 95 + 2;
                            dot.style.left = pos + '%';
                            dot.title = a.description;
                            tl.appendChild(dot);
                        });
                    }

                    // Алерты
                    const alertsDiv = document.getElementById('alerts');
                    if (data.alerts.length === 0) {
                        alertsDiv.innerHTML = '<div class="no-alerts">&#x2705; Угроз не обнаружено</div>';
                    } else {
                        alertsDiv.innerHTML = data.alerts.slice().reverse().map(a => `
                            <div class="alert-item sev-${a.severity}">
                                <span class="alert-severity">${a.severity}</span>
                                <span class="alert-category">${a.category}</span>
                                <span class="alert-time">${new Date(a.timestamp).toLocaleTimeString()}</span>
                                <div class="alert-desc">${a.description}</div>
                                ${a.source_path ? '<div class="alert-source">&#x1f4c1; ' + a.source_path + '</div>' : ''}
                            </div>
                        `).join('');
                    }
                })
                .catch(() => {
                    document.getElementById('status').textContent = 'Ошибка подключения';
                });
        }

        updateDashboard();
        setInterval(updateDashboard, 2000);
    </script>
</body>
</html>
"""


class Dashboard:
    """Flask-дашборд для визуализации алертов в реальном времени."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self._app: Optional[Flask] = None

    def create_app(self) -> "Flask":
        if Flask is None:
            raise RuntimeError("Flask не установлен: pip install flask")

        app = Flask(__name__)
        app.config["JSON_AS_ASCII"] = False

        engine = self.engine

        @app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route("/api/status")
        def api_status():
            by_sev = {}
            for a in engine.alerts:
                by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1

            alerts_data = [
                {
                    "timestamp": a.timestamp.isoformat(),
                    "category": a.category.value,
                    "severity": a.severity.value,
                    "description": a.description,
                    "source_path": a.source_path,
                }
                for a in engine.alerts
            ]

            return jsonify({
                "threat_score": engine.threat_score,
                "total_alerts": len(engine.alerts),
                "by_severity": by_sev,
                "alerts": alerts_data,
            })

        self._app = app
        return app

    def run(self, host: str = "127.0.0.1", port: int = 5050):
        """Запуск дашборда (блокирующий)."""
        app = self.create_app()
        print(f"\n🖥️  Дашборд доступен: http://{host}:{port}")
        app.run(host=host, port=port, debug=False, use_reloader=False)

    def run_background(self, host: str = "127.0.0.1", port: int = 5050) -> threading.Thread:
        """Запуск дашборда в фоновом потоке."""
        thread = threading.Thread(
            target=self.run, kwargs={"host": host, "port": port}, daemon=True
        )
        thread.start()
        return thread
