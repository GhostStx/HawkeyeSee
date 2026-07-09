"""Tests du module database."""

import json
import os
from hawkeye.database import (
    init_db, inserer_requete, lister_requetes,
    exporter_json, exporter_csv, stats, chercher_requetes,
    inserer_requetes_batch,
)


class TestDatabase:
    def test_init_db_cree_table(self, db_chemin):
        """Vérifie que init_db crée la table."""
        conn = init_db(db_chemin)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        assert any(row[0] == "requetes" for row in tables)
        conn.close()

    def test_inserer_et_lister(self, db_chemin):
        """Vérifie l'insertion et le listage."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "192.168.1.1", "example.com", "A")
        rows = lister_requetes(conn)
        assert len(rows) == 1
        assert rows[0]["ip_source"] == "192.168.1.1"
        assert rows[0]["domaine"] == "example.com"
        conn.close()

    def test_inserer_avec_alerte(self, db_chemin):
        """Vérifie l'insertion avec alerte."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "10.0.0.1", "evil.com", "A",
                        alerte="Malveillant", alerte_type="BLACKLIST")
        rows = lister_requetes(conn)
        assert rows[0]["alerte"] == "Malveillant"
        assert rows[0]["alerte_type"] == "BLACKLIST"
        conn.close()

    def test_inserer_requetes_batch(self, db_chemin):
        """Vérifie l'insertion par lot."""
        conn = init_db(db_chemin)
        requetes = [
            {"timestamp": "2024-01-01T00:00:00", "ip_source": "10.0.0.1",
             "domaine": "a.com", "type_query": "A", "alerte": None, "alerte_type": None},
            {"timestamp": "2024-01-01T00:00:01", "ip_source": "10.0.0.2",
             "domaine": "b.com", "type_query": "AAAA", "alerte": None, "alerte_type": None},
        ]
        inserer_requetes_batch(conn, requetes)
        rows = lister_requetes(conn)
        assert len(rows) == 2
        conn.close()

    def test_chercher_requetes(self, db_chemin):
        """Vérifie la recherche avec filtres."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "10.0.0.1", "example.com", "A")
        inserer_requete(conn, "10.0.0.1", "evil.com", "A",
                        alerte="Test", alerte_type="BLACKLIST")
        inserer_requete(conn, "10.0.0.2", "test.org", "A")

        # Recherche par domaine
        rows = chercher_requetes(conn, domaine="evil")
        assert len(rows) == 1

        # Recherche par IP
        rows = chercher_requetes(conn, ip_source="10.0.0.1")
        assert len(rows) == 2

        # Recherche par type d'alerte
        rows = chercher_requetes(conn, alerte_type="BLACKLIST")
        assert len(rows) == 1
        conn.close()

    def test_exporter_json(self, db_chemin, tmp_path):
        """Vérifie l'export JSON."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "10.0.0.1", "example.com", "A")
        chemin_json = tmp_path / "test_export.json"
        nb = exporter_json(conn, str(chemin_json))
        assert nb == 1

        with open(chemin_json) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["domaine"] == "example.com"
        conn.close()

    def test_exporter_csv(self, db_chemin, tmp_path):
        """Vérifie l'export CSV."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "10.0.0.1", "example.com", "A")
        chemin_csv = tmp_path / "test_export.csv"
        nb = exporter_csv(conn, str(chemin_csv))
        assert nb == 1

        with open(chemin_csv) as f:
            content = f.read()
        assert "timestamp" in content
        assert "example.com" in content
        conn.close()

    def test_stats(self, db_chemin):
        """Vérifie les statistiques."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "10.0.0.1", "example.com", "A")
        inserer_requete(conn, "10.0.0.1", "example.com", "A")
        inserer_requete(conn, "10.0.0.2", "evil.com", "A",
                        alerte="Test", alerte_type="BLACKLIST")

        s = stats(conn)
        assert s["total"] == 3
        assert s["alertes"] == 1
        assert s["domaines_uniques"] == 2
        assert s["ips_uniques"] == 2
        assert s["stats_alertes"]["BLACKLIST"] == 1
        conn.close()
