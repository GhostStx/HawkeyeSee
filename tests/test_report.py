"""Tests du générateur de rapport HTML."""

from hawkeye.database import init_db, inserer_requete
from hawkeye.report import generer_rapport


class TestReport:
    def test_generer_rapport(self, db_chemin, tmp_path):
        """Vérifie la génération du rapport HTML."""
        conn = init_db(db_chemin)
        inserer_requete(conn, "10.0.0.1", "example.com", "A")
        inserer_requete(conn, "10.0.0.2", "evil.com", "A",
                        alerte="Test", alerte_type="BLACKLIST")
        conn.close()

        chemin_rapport = tmp_path / "test_rapport.html"
        resultat = generer_rapport(db_chemin, str(chemin_rapport))

        assert resultat == str(chemin_rapport)
        assert chemin_rapport.exists()

        contenu = chemin_rapport.read_text(encoding="utf-8")
        assert "HawkEye" in contenu
        assert "Rapport" in contenu
        assert "example.com" in contenu
        assert "evil.com" in contenu
        assert "10.0.0.1" in contenu
        # Chart.js doit être inclus
        assert "chart.js" in contenu.lower() or "Chart" in contenu

    def test_rapport_vide(self, db_chemin, tmp_path):
        """Un rapport sur une base vide doit fonctionner."""
        init_db(db_chemin).close()
        chemin_rapport = tmp_path / "vide.html"
        resultat = generer_rapport(db_chemin, str(chemin_rapport))
        assert resultat == str(chemin_rapport)
        assert chemin_rapport.exists()
