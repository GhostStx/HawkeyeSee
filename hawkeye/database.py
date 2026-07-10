"""
HawkEye — Module Base de Données
=================================
Interface SQLite pour le stockage, l'export et les statistiques
des requêtes DNS capturées.

Améliorations v2 :
  - Export CSV
  - Statistiques enrichies
  - Filtres temporels
  - Contexte manager pour la connexion
"""

import csv
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional


def init_db(db_path: str = "hawkeye.db") -> sqlite3.Connection:
    """Initialise / ouvre la base SQLite et crée la table si absente."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS requetes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            ip_source   TEXT    NOT NULL,
            domaine     TEXT    NOT NULL,
            type_query  TEXT    NOT NULL DEFAULT 'A',
            alerte      TEXT    DEFAULT NULL,
            alerte_type TEXT    DEFAULT NULL
        )
    """)
    # Ajout de la colonne alerte_type si migration depuis v1
    try:
        conn.execute("SELECT alerte_type FROM requetes LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE requetes ADD COLUMN alerte_type TEXT DEFAULT NULL")
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_requetes_timestamp
        ON requetes(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_requetes_domaine
        ON requetes(domaine)
    """)
    conn.commit()
    return conn


@contextmanager
def get_db(db_path: str = "hawkeye.db") -> Iterator[sqlite3.Connection]:
    """Context manager pour la connexion à la base."""
    conn = init_db(db_path)
    try:
        yield conn
    finally:
        conn.close()


def inserer_requete(
    conn: sqlite3.Connection,
    ip_source: str,
    domaine: str,
    type_query: str = "A",
    alerte: Optional[str] = None,
    alerte_type: Optional[str] = None,
) -> None:
    """Insère une ligne de requête DNS dans la base."""
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO requetes (timestamp, ip_source, domaine, type_query, alerte, alerte_type) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ts, ip_source, domaine, type_query, alerte, alerte_type),
    )
    conn.commit()


def inserer_requetes_batch(
    conn: sqlite3.Connection,
    requetes: list[dict],
) -> None:
    """Insère plusieurs requêtes en une transaction (plus rapide)."""
    conn.executemany(
        "INSERT INTO requetes (timestamp, ip_source, domaine, type_query, alerte, alerte_type) "
        "VALUES (:timestamp, :ip_source, :domaine, :type_query, :alerte, :alerte_type)",
        requetes,
    )
    conn.commit()


def lister_requetes(
    conn: sqlite3.Connection, limite: int = 50
) -> list[sqlite3.Row]:
    """Retourne les *limite* dernières requêtes."""
    return conn.execute(
        "SELECT id, timestamp, ip_source, domaine, type_query, alerte, alerte_type "
        "FROM requetes ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()


def chercher_requetes(
    conn: sqlite3.Connection,
    domaine: Optional[str] = None,
    ip_source: Optional[str] = None,
    alerte_type: Optional[str] = None,
    limite: int = 100,
) -> list[sqlite3.Row]:
    """Recherche des requêtes avec filtres optionnels."""
    conditions = []
    params = []
    if domaine:
        conditions.append("domaine LIKE ?")
        params.append(f"%{domaine}%")
    if ip_source:
        conditions.append("ip_source = ?")
        params.append(ip_source)
    if alerte_type:
        conditions.append("alerte_type = ?")
        params.append(alerte_type)

    where = " AND ".join(conditions) if conditions else "1=1"
    return conn.execute(
        f"SELECT id, timestamp, ip_source, domaine, type_query, alerte, alerte_type "
        f"FROM requetes WHERE {where} ORDER BY id DESC LIMIT ?",
        (*params, limite),
    ).fetchall()


def exporter_json(
    conn: sqlite3.Connection, chemin: str = "export.json"
) -> int:
    """Exporte toutes les requêtes vers un fichier JSON. Retourne le nombre."""
    curseur = conn.execute(
        "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
        "FROM requetes ORDER BY id"
    )
    lignes = [
        {
            "timestamp": row[0],
            "ip_source": row[1],
            "domaine": row[2],
            "type_query": row[3],
            "alerte": row[4],
            "alerte_type": row[5],
        }
        for row in curseur.fetchall()
    ]
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(lignes, f, indent=2, ensure_ascii=False)
    print(f"[✓] {len(lignes)} requêtes exportées → {chemin}")
    return len(lignes)


def exporter_csv(
    conn: sqlite3.Connection, chemin: str = "export.csv"
) -> int:
    """Exporte toutes les requêtes vers un fichier CSV. Retourne le nombre."""
    curseur = conn.execute(
        "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
        "FROM requetes ORDER BY id"
    )
    lignes = curseur.fetchall()
    with open(chemin, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip_source", "domaine",
                         "type_query", "alerte", "alerte_type"])
        writer.writerows(lignes)
    print(f"[✓] {len(lignes)} requêtes exportées → {chemin}")
    return len(lignes)


def stats(conn: sqlite3.Connection) -> dict:
    """Retourne des statistiques détaillées sur la base."""
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

    # Stats par type d'alerte
    stats_alertes = conn.execute(
        "SELECT alerte_type, COUNT(*) as cnt FROM requetes "
        "WHERE alerte_type IS NOT NULL GROUP BY alerte_type ORDER BY cnt DESC"
    ).fetchall()

    # Top domaines interrogés
    top_domaines = conn.execute(
        "SELECT domaine, COUNT(*) as cnt FROM requetes "
        "GROUP BY domaine ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    # Top IP sources
    top_ips = conn.execute(
        "SELECT ip_source, COUNT(*) as cnt FROM requetes "
        "GROUP BY ip_source ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    # Première et dernière requête
    premiere = conn.execute(
        "SELECT timestamp FROM requetes ORDER BY id ASC LIMIT 1"
    ).fetchone()
    derniere = conn.execute(
        "SELECT timestamp FROM requetes ORDER BY id DESC LIMIT 1"
    ).fetchone()

    return {
        "total": total,
        "alertes": avec_alerte,
        "domaines_uniques": domaines_uniques,
        "ips_uniques": ips_uniques,
        "stats_alertes": {r[0]: r[1] for r in stats_alertes},
        "top_domaines": [{"domaine": r[0], "count": r[1]} for r in top_domaines],
        "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
        "premiere_requete": premiere[0] if premiere else None,
        "derniere_requete": derniere[0] if derniere else None,
    }
