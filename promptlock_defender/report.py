"""
Экспорт отчётов в JSON и HTML.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from .engine import DetectionEngine

logger = logging.getLogger("promptlock_defender.report")

HTML_REPORT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>PromptLock Defender — Отчёт</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; padding: 40px; }}
        .report {{ max-width: 900px; margin: 0 auto; background: #fff; border-radius: 12px;
                   box-shadow: 0 2px 20px rgba(0,0,0,0.1); padding: 30px; }}
        h1 {{ color: #1a1a5e; border-bottom: 3px solid #00d4ff; padding-bottom: 10px; }}
        .meta {{ color: #888; font-size: 13px; margin-bottom: 20px; }}
        .score-box {{ text-align: center; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .score-box.safe {{ background: #e8f5e9; color: #2e7d32; }}
        .score-box.warning {{ background: #fff3e0; color: #e65100; }}
        .score-box.danger {{ background: #ffebee; color: #c62828; }}
        .score-box .number {{ font-size: 48px; font-weight: bold; }}
        .stats {{ display: flex; gap: 15px; margin: 20px 0; }}
        .stat {{ flex: 1; text-align: center; padding: 15px; border-radius: 8px; }}
        .stat.low {{ background: #fffde7; }}
        .stat.medium {{ background: #fff3e0; }}
        .stat.high {{ background: #fce4ec; }}
        .stat.critical {{ background: #f3e5f5; }}
        .stat .num {{ font-size: 28px; font-weight: bold; }}
        .stat .lbl {{ font-size: 11px; color: #888; }}
        .alert-card {{ border-left: 4px solid #ccc; background: #fafafa; border-radius: 6px;
                       padding: 12px 15px; margin: 10px 0; }}
        .alert-card.sev-LOW {{ border-left-color: #fdd835; }}
        .alert-card.sev-MEDIUM {{ border-left-color: #ff9800; }}
        .alert-card.sev-HIGH {{ border-left-color: #e53935; }}
        .alert-card.sev-CRITICAL {{ border-left-color: #d500f9; background: #fce4ec; }}
        .alert-sev {{ display: inline-block; padding: 2px 8px; border-radius: 3px;
                      font-size: 11px; font-weight: bold; color: #fff; }}
        .sev-LOW .alert-sev {{ background: #fdd835; color: #333; }}
        .sev-MEDIUM .alert-sev {{ background: #ff9800; }}
        .sev-HIGH .alert-sev {{ background: #e53935; }}
        .sev-CRITICAL .alert-sev {{ background: #d500f9; }}
        .alert-cat {{ font-size: 12px; color: #888; margin-left: 8px; }}
        .alert-desc {{ margin-top: 6px; }}
        .alert-src {{ font-size: 12px; color: #666; margin-top: 4px; }}
        .alert-time {{ font-size: 11px; color: #aaa; float: right; }}
        .footer {{ text-align: center; color: #bbb; font-size: 12px; margin-top: 30px; }}
    </style>
</head>
<body>
<div class="report">
    <h1>&#x1f6e1; PromptLock Defender — Отчёт</h1>
    <div class="meta">Дата: {date} | Алертов: {total}</div>

    <div class="score-box {score_class}">
        <div>Уровень угрозы</div>
        <div class="number">{score} / 100</div>
    </div>

    <div class="stats">
        <div class="stat low"><div class="num">{low}</div><div class="lbl">LOW</div></div>
        <div class="stat medium"><div class="num">{medium}</div><div class="lbl">MEDIUM</div></div>
        <div class="stat high"><div class="num">{high}</div><div class="lbl">HIGH</div></div>
        <div class="stat critical"><div class="num">{critical}</div><div class="lbl">CRITICAL</div></div>
    </div>

    <h2>&#x1f514; Алерты</h2>
    {alerts_html}

    <div class="footer">PromptLock Defender v1.0 — сгенерировано автоматически</div>
</div>
</body>
</html>
"""


class ReportExporter:
    """Экспорт отчётов в JSON и HTML."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def to_json(self, filepath: Optional[str] = None) -> str:
        """Экспорт в JSON. Возвращает JSON-строку и сохраняет в файл если указан путь."""
        data = self._build_data()
        json_str = json.dumps(data, ensure_ascii=False, indent=2, default=str)

        if filepath:
            Path(filepath).write_text(json_str, encoding="utf-8")
            logger.info("JSON-отчёт сохранён: %s", filepath)

        return json_str

    def to_html(self, filepath: Optional[str] = None) -> str:
        """Экспорт в HTML. Возвращает HTML-строку и сохраняет в файл если указан путь."""
        data = self._build_data()

        score = data["threat_score"]
        score_class = "safe" if score < 20 else ("warning" if score < 50 else "danger")

        alerts_html_parts = []
        for a in sorted(data["alerts"], key=lambda x: x["timestamp"], reverse=True):
            sev = a["severity"]
            alerts_html_parts.append(
                f'<div class="alert-card sev-{sev}">'
                f'  <span class="alert-sev">{sev}</span>'
                f'  <span class="alert-cat">{a["category"]}</span>'
                f'  <span class="alert-time">{a["timestamp"]}</span>'
                f'  <div class="alert-desc">{a["description"]}</div>'
                f'  {"<div class=alert-src>&#x1f4c1; " + a["source_path"] + "</div>" if a.get("source_path") else ""}'
                f'</div>'
            )

        by_sev = data.get("by_severity", {})
        html = HTML_REPORT_TEMPLATE.format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=data["total_alerts"],
            score=score,
            score_class=score_class,
            low=by_sev.get("LOW", 0),
            medium=by_sev.get("MEDIUM", 0),
            high=by_sev.get("HIGH", 0),
            critical=by_sev.get("CRITICAL", 0),
            alerts_html="\n".join(alerts_html_parts) if alerts_html_parts
                else '<div style="text-align:center;color:#888;padding:20px;">Угроз не обнаружено</div>',
        )

        if filepath:
            Path(filepath).write_text(html, encoding="utf-8")
            logger.info("HTML-отчёт сохранён: %s", filepath)

        return html

    def _build_data(self) -> dict:
        by_sev = {}
        for a in self.engine.alerts:
            by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1

        return {
            "generated_at": datetime.now().isoformat(),
            "threat_score": self.engine.threat_score,
            "total_alerts": len(self.engine.alerts),
            "by_severity": by_sev,
            "alerts": [
                {
                    "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "category": a.category.value,
                    "severity": a.severity.value,
                    "description": a.description,
                    "source_path": a.source_path,
                    "details": a.details,
                }
                for a in self.engine.alerts
            ],
        }
