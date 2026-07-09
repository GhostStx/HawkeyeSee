"""
HawkEye — Dashboard Web
========================
Interface web temps réel pour visualiser le trafic DNS capturé.
Utilise Flask + Server-Sent Events (SSE) pour le live.

Usage :
    python -m hawkeye dashboard
"""

import json
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from flask import Flask, Response, jsonify, render_template, request
except ImportError:
    Flask = None  # type: ignore


# ── File d'attente pour les événements SSE ──

class EventBus:
    """Bus d'événements thread-safe pour le streaming SSE."""

    def __init__(self):
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event: str, data: dict) -> None:
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        with self._lock:
            dead: list[queue.Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)


# Instance globale du bus
event_bus = EventBus()


# ── Fabrication de l'application Flask ──

def create_app(db_path: str = "hawkeye.db") -> "Flask":
    """Crée et configure l'application Flask du dashboard."""

    app = Flask(__name__)

    # Chemin de la base
    app.config["DB_PATH"] = db_path
    app.config["SECRET_KEY"] = os.urandom(24).hex()

    # ── Routes ──

    @app.route("/")
    def index():
        """Page principale du dashboard."""
        return render_template("index.html")

    @app.route("/api/stats")
    def api_stats():
        """API JSON : statistiques globales."""
        try:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row
            total = conn.execute("SELECT COUNT(*) FROM requetes").fetchone()[0]
            alertes = conn.execute(
                "SELECT COUNT(*) FROM requetes WHERE alerte IS NOT NULL"
            ).fetchone()[0]
            domaines = conn.execute(
                "SELECT COUNT(DISTINCT domaine) FROM requetes"
            ).fetchone()[0]
            ips = conn.execute(
                "SELECT COUNT(DISTINCT ip_source) FROM requetes"
            ).fetchone()[0]

            # Alertes par type
            stats_alertes = conn.execute(
                "SELECT alerte_type, COUNT(*) as cnt FROM requetes "
                "WHERE alerte_type IS NOT NULL GROUP BY alerte_type ORDER BY cnt DESC"
            ).fetchall()
            conn.close()

            return jsonify({
                "total": total,
                "alertes": alertes,
                "domaines_uniques": domaines,
                "ips_uniques": ips,
                "stats_alertes": {r[0]: r[1] for r in stats_alertes}
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/requetes")
    def api_requetes():
        """API JSON : dernières requêtes."""
        limite = request.args.get("limite", 50, type=int)
        alerte_only = request.args.get("alertes", False, type=bool)
        try:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row
            if alerte_only:
                rows = conn.execute(
                    "SELECT id, timestamp, ip_source, domaine, type_query, "
                    "alerte, alerte_type FROM requetes "
                    "WHERE alerte IS NOT NULL ORDER BY id DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, timestamp, ip_source, domaine, type_query, "
                    "alerte, alerte_type FROM requetes "
                    "ORDER BY id DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            conn.close()
            return jsonify([{
                "id": r[0],
                "timestamp": r[1],
                "ip_source": r[2],
                "domaine": r[3],
                "type_query": r[4],
                "alerte": r[5],
                "alerte_type": r[6],
            } for r in rows])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/recherche")
    def api_recherche():
        """API JSON : recherche de requêtes."""
        domaine = request.args.get("domaine", "")
        ip = request.args.get("ip", "")
        alerte_type = request.args.get("alerte_type", "")
        try:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row
            conditions = []
            params = []
            if domaine:
                conditions.append("domaine LIKE ?")
                params.append(f"%{domaine}%")
            if ip:
                conditions.append("ip_source = ?")
                params.append(ip)
            if alerte_type:
                conditions.append("alerte_type = ?")
                params.append(alerte_type)
            where = " AND ".join(conditions) if conditions else "1=1"
            rows = conn.execute(
                f"SELECT id, timestamp, ip_source, domaine, type_query, "
                f"alerte, alerte_type FROM requetes "
                f"WHERE {where} ORDER BY id DESC LIMIT 100",
                params,
            ).fetchall()
            conn.close()
            return jsonify([{
                "id": r[0],
                "timestamp": r[1],
                "ip_source": r[2],
                "domaine": r[3],
                "type_query": r[4],
                "alerte": r[5],
                "alerte_type": r[6],
            } for r in rows])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/events")
    def api_events():
        """Endpoint SSE pour les événements en temps réel."""
        def stream():
            q = event_bus.subscribe()
            try:
                # Envoi initial
                yield "event: connected\ndata: {}\n\n"
                while True:
                    try:
                        data = q.get(timeout=30)
                        yield data
                    except queue.Empty:
                        yield "event: ping\ndata: {}\n\n"
            except GeneratorExit:
                event_bus.unsubscribe(q)

        return Response(
            stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.route("/api/health")
    def api_health():
        """Endpoint de santé pour Docker healthcheck."""
        try:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.execute("SELECT 1")
            conn.close()
            return jsonify({
                "status": "healthy",
                "db": app.config["DB_PATH"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            return jsonify({"status": "unhealthy", "error": str(e)}), 500

    @app.route("/api/export/csv")
    def api_export_csv():
        """Export CSV de toutes les requêtes."""
        import csv
        import io

        alerte_type = request.args.get("alerte_type", "")
        try:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row

            if alerte_type:
                rows = conn.execute(
                    "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
                    "FROM requetes WHERE alerte_type = ? ORDER BY id DESC",
                    (alerte_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
                    "FROM requetes ORDER BY id DESC"
                ).fetchall()
            conn.close()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["timestamp", "ip_source", "domaine", "type_query", "alerte", "alerte_type"])
            for row in rows:
                writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5]])

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=hawkeye-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
                },
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/export/json")
    def api_export_json():
        """Export JSON de toutes les requêtes."""
        alerte_type = request.args.get("alerte_type", "")
        try:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row

            if alerte_type:
                rows = conn.execute(
                    "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
                    "FROM requetes WHERE alerte_type = ? ORDER BY id DESC",
                    (alerte_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
                    "FROM requetes ORDER BY id DESC"
                ).fetchall()
            conn.close()

            data = [dict(r) for r in rows]
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


# ── Point d'entrée CLI ──

def run_dashboard(db_path: str = "hawkeye.db", host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Lance le dashboard web."""
    if Flask is None:
        print("[!] Flask n'est pas installé. Faites : pip install flask")
        return

    app = create_app(db_path)
    print(f"[✓] Dashboard HawkEye : http://{host}:{port}")
    print(f"    Ctrl+C pour arrêter")
    app.run(host=host, port=port, debug=debug, threaded=True)


# ── Fonction pour publier un événement depuis le sniffer ──

def publier_requete(ip_source: str, domaine: str, qtype: str,
                    alerte: Optional[str] = None,
                    alerte_type: Optional[str] = None) -> None:
    """Publie une requête sur le bus d'événements (thread-safe)."""
    event_bus.publish("requete", {
        "ip_source": ip_source,
        "domaine": domaine,
        "type_query": qtype,
        "alerte": alerte,
        "alerte_type": alerte_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
