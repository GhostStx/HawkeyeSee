"""
HawkEye — Mode Watch (Terminal Dashboard)
===========================================
Affiche un tableau de bord en temps réel dans le terminal,
mise à jour toutes les N secondes. Similaire à `top` pour le trafic DNS.

Usage :
    python -m hawkeye watch              # Live (nécessite sudo)
    python -m hawkeye watch --db hawkeye.db  # Depuis une base existante
"""

import os
import shutil
import sqlite3
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class TerminalDashboard:
    """Dashboard temps réel dans le terminal."""

    def __init__(self, db_path: str, interval: int = 2):
        self.db_path = db_path
        self.interval = interval
        self._precedent = {
            "total": 0,
            "alertes": 0,
        }

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _stats(self) -> dict:
        conn = self._conn()
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

        # Top domaines dans la dernière minute
        top_recent = conn.execute(
            "SELECT domaine, COUNT(*) as cnt FROM requetes "
            "GROUP BY domaine ORDER BY cnt DESC LIMIT 5"
        ).fetchall()

        # Dernières alertes
        dernieres_alertes = conn.execute(
            "SELECT timestamp, ip_source, domaine, alerte_type FROM requetes "
            "WHERE alerte IS NOT NULL ORDER BY id DESC LIMIT 5"
        ).fetchall()

        # Rafraîchissements
        nouveaux = total - self._precedent["total"]
        nouvelles_alertes = alertes - self._precedent["alertes"]
        self._precedent = {"total": total, "alertes": alertes}

        conn.close()
        return {
            "total": total,
            "alertes": alertes,
            "domaines": domaines,
            "ips": ips,
            "nouveaux": nouveaux,
            "nouvelles_alertes": nouvelles_alertes,
            "top_recent": top_recent,
            "dernieres_alertes": dernieres_alertes,
        }

    def _dessiner(self, stats: dict):
        """Dessine le dashboard dans le terminal."""
        cols = shutil.get_terminal_size().columns

        os.system("clear" if sys.platform == "darwin" else "clear")
        print(f"\033[1;96m{'═' * min(cols, 60)}\033[0m")
        print(f"\033[1;96m  🦅 HawkEye — Tableau de bord temps réel\033[0m")
        print(f"\033[1;96m{'═' * min(cols, 60)}\033[0m")
        print(f"  \033[90m{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\033[0m")
        print(f"  \033[90mBase : {Path(self.db_path).name}\033[0m")
        print()

        # Stats globales
        print(f"  \033[1mSTATISTIQUES\033[0m")
        print(f"  ├─ 📦 Requêtes totales  : \033[92m{stats['total']:>8}\033[0m"
              f"  (\033[93m+{stats['nouveaux']}\033[0m)")
        print(f"  ├─ 🚨 Alertes           : \033[91m{stats['alertes']:>8}\033[0m"
              f"  (\033[93m+{stats['nouvelles_alertes']}\033[0m)")
        print(f"  ├─ 🌐 Domaines uniques  : \033[96m{stats['domaines']:>8}\033[0m")
        print(f"  └─ 🖥️  IPs sources       : \033[93m{stats['ips']:>8}\033[0m")
        print()

        # Top domaines
        if stats["top_recent"]:
            print(f"  \033[1mTOP DOMAINES\033[0m")
            for i, row in enumerate(stats["top_recent"], 1):
                barre = "█" * min(row[1], cols // 4)
                print(f"  {i}. \033[96m{row[0]:<35}\033[0m \033[90m{row[1]}x\033[0m {barre}")
            print()

        # Dernières alertes
        if stats["dernieres_alertes"]:
            print(f"  \033[1mDERNIÈRES ALERTES\033[0m")
            icones = {"BLACKLIST": "🚨", "DGA": "⚠️", "DGA_RAFALE": "📡", "TUNNEL_DNS": "🔓"}
            for row in stats["dernieres_alertes"]:
                icone = icones.get(row[3] or "", "🔔")
                afficher = row[2][:50] if row[2] else "?"
                print(f"  {icone} \033[90m{row[0][11:19]}\033[0m "
                      f"\033[96m{row[1]:<16}\033[0m "
                      f"\033[93m{afficher}\033[0m")
            print()

        # Barre de progression live
        taux = stats["nouveaux"] / max(self.interval, 1)
        print(f"  \033[90mDébit : {taux:.1f} req/s | "
              f"Actualisation toutes les {self.interval}s | "
              f"Ctrl+C pour arrêter\033[0m")

    def run(self, iterations: Optional[int] = None):
        """Boucle principale du dashboard."""
        i = 0
        try:
            while iterations is None or i < iterations:
                s = self._stats()
                self._dessiner(s)
                i += 1
                if iterations is None or i < iterations:
                    time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n\n[i] Arrêt du mode watch.")
