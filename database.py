"""
HawkEye — Module Base de Données
=================================
Interface SQLite pour le stockage et l'export des requêtes DNS capturées.

Utilisation directe (hors hawkeye.py) :
    from database import init_db, inserer_requete, exporter_json
    conn = init_db("mon_historique.db")
    inserer_requete(conn, "192.168.1.10", "example.com", "A")
    exporter_json(conn, "export.json")
    conn.close()
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def init_db(db_path: str = "hawkeye.db") -> sqlite3.Connection:
    """Initialise / ouvre la base SQLite et crée la table si absente."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS requetes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            ip_source   TEXT    NOT NULL,
            domaine     TEXT    NOT NULL,
            type_query  TEXT    NOT NULL DEFAULT 'A',
            alerte      TEXT    DEFAULT NULL
        )
    """)
    conn.commit()
    return conn


def inserer_requete(
    conn: sqlite3.Connection,
    ip_source: str,
    domaine: str,
    type_query: str = "A",
    alerte: Optional[str] = None,
) -> None:
    """Insère une ligne de requête DNS dans la base."""
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO requetes (timestamp, ip_source, domaine, type_query, alerte) "
        "VALUES (?, ?, ?, ?, ?)",
        (ts, ip_source, domaine, type_query, alerte),
    )
    conn.commit()


def lister_requetes(
    conn: sqlite3.Connection, limite: int = 50
) -> list[tuple]:
    """Retourne les *limite* dernières requêtes."""
    return conn.execute(
        "SELECT id, timestamp, ip_source, domaine, type_query, alerte "
        "FROM requetes ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()


def exporter_json(
    conn: sqlite3.Connection, chemin: str = "export.json"
) -> None:
    """Exporte toutes les requêtes vers un fichier JSON."""
    curseur = conn.execute(
        "SELECT timestamp, ip_source, domaine, type_query, alerte "
        "FROM requetes ORDER BY id"
    )
    lignes = [
        {
            "timestamp": row[0],
            "ip_source": row[1],
            "domaine": row[2],
            "type_query": row[3],
            "alerte": row[4],
        }
        for row in curseur.fetchall()
    ]
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(lignes, f, indent=2, ensure_ascii=False)
    print(f"[✓] {len(lignes)} requêtes exportées → {chemin}")


def stats(conn: sqlite3.Connection) -> dict:
    """Retourne quelques statistiques sur la base."""
    total = conn.execute("SELECT COUNT(*) FROM requetes").fetchone()[0]
    avec_alerte = conn.execute(
        "SELECT COUNT(*) FROM requetes WHERE alerte IS NOT NULL"
    ).fetchone()[0]
    domaines_uniques = conn.execute(
        "SELECT COUNT(DISTINCT domaine) FROM requetes"
    ).fetchone()[0]
    ips_uniques = conn.execute(
        "SELECT COUNT(DISTINCT ip_source) FROM requetes"
    ).fetchone()[0]
    return {
        "total": total,
        "alertes": avec_alerte,
        "domaines_uniques": domaines_uniques,
        "ips_uniques": ips_uniques,
    }
