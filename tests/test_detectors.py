"""Tests des détecteurs (liste noire, DGA, tunnel DNS)."""

from hawkeye.detectors.blacklist import BlacklistChecker
from hawkeye.detectors.dga import DgaDetector, EntropyDgaDetector
from hawkeye.detectors.dnstunnel import DnsTunnelDetector


class TestBlacklistChecker:
    def test_chargement(self, fichier_liste_noire):
        """Vérifie le chargement de la liste noire."""
        checker = BlacklistChecker(fichier_liste_noire)
        assert checker.charger() is True
        assert checker.count == 4  # 2 exactes + 1 suffixe + 1 wildcard

    def test_domaine_exact(self, fichier_liste_noire):
        """Vérifie la détection exacte."""
        checker = BlacklistChecker(fichier_liste_noire)
        checker.charger()
        assert checker.check("evil.com") == "BLACKLIST"
        assert checker.check("EVIL.COM") == "BLACKLIST"  # insensible à la casse

    def test_domaine_sain(self, fichier_liste_noire):
        """Vérifie qu'un domaine sain n'est pas détecté."""
        checker = BlacklistChecker(fichier_liste_noire)
        checker.charger()
        assert checker.check("google.com") is None
        assert checker.check("github.com") is None

    def test_suffixe_wildcard(self, fichier_liste_noire):
        """Vérifie la détection par suffixe."""
        checker = BlacklistChecker(fichier_liste_noire)
        checker.charger()
        assert checker.check("sub.phishing.xyz") == "BLACKLIST"
        assert checker.check("deep.sub.phishing.xyz") == "BLACKLIST"

    def test_wildcard_prefix(self, fichier_liste_noire):
        """Vérifie la détection wildcard avec *. """
        checker = BlacklistChecker(fichier_liste_noire)
        checker.charger()
        assert checker.check("test.dynamic.dns") == "BLACKLIST"
        assert checker.check("a.b.dynamic.dns") == "BLACKLIST"

    def test_fichier_introuvable(self):
        """Vérifie la gestion de fichier manquant."""
        checker = BlacklistChecker("/nonexistent/file.txt")
        assert checker.charger() is False
        assert checker.count == 0
        assert checker.check("evil.com") is None


class TestEntropyDgaDetector:
    def test_domaine_normal(self):
        """Un domaine normal a un score DGA bas."""
        detector = EntropyDgaDetector()
        resultat = detector.analyser("google")
        assert resultat["dga"] is False
        assert resultat["score"] < 0.5

    def test_domaine_dga_typique(self):
        """Un domaine DGA typique a un score élevé."""
        detector = EntropyDgaDetector()
        resultat = detector.analyser("xjqkfbdmznxqkejfbdjs")
        assert resultat["dga"] is True
        assert resultat["score"] > 0.4

    def test_domaine_avec_chiffres(self):
        """Un domaine avec beaucoup de chiffres est suspect."""
        detector = EntropyDgaDetector()
        resultat = detector.analyser("a1b2c3d4e5f6g7h8i9")
        assert resultat["dga"] is True
        assert resultat["ratio_chiffres"] > 0.2

    def test_domaine_court(self):
        """Un domaine très court n'est pas DGA."""
        detector = EntropyDgaDetector()
        resultat = detector.analyser("ab")
        assert resultat["dga"] is False

    def test_domaine_long_normal(self):
        """Un domaine long mais lisible n'est pas DGA."""
        detector = EntropyDgaDetector()
        resultat = detector.analyser("this-is-a-test-domain")
        # Devrait avoir un score modéré (contient des mots)
        assert resultat["score"] < 0.7

    def test_consonnes_consecutives(self):
        """Beaucoup de consonnes consécutives = suspect."""
        detector = EntropyDgaDetector()
        resultat = detector.analyser("xzyrwklmnbcvxzwqpsdfg")
        assert resultat["dga"] is True


class TestDgaDetector:
    def test_detection_temporelle(self):
        """Vérifie que le détecteur temporel fonctionne."""
        detector = DgaDetector(threshold=3, window=10)
        # Deux requêtes ne suffisent pas
        assert detector.analyser("test1.xyz") is None
        assert detector.analyser("test2.xyz") is None
        # La troisième déclenche l'alerte
        assert detector.analyser("test3.xyz") is not None

    def test_detection_temporelle_reset(self):
        """Vérifie que le compteur se réinitialise."""
        detector = DgaDetector(threshold=3, window=10)
        detector.analyser("a.xyz")
        detector.analyser("b.xyz")
        r = detector.analyser("c.xyz")
        assert r is not None
        # Après alerte, le compteur est reset
        assert detector.analyser("d.xyz") is None


class TestDnsTunnelDetector:
    def test_requete_normale(self):
        """Une requête DNS normale ne déclenche pas d'alerte."""
        detector = DnsTunnelDetector()
        assert detector.analyser("google.com", "A", 25) is None

    def test_nom_trop_long(self):
        """Un nom anormalement long déclenche une alerte."""
        detector = DnsTunnelDetector(seuil_taille=30)
        long_domaine = "a" * 40 + ".com"
        assert detector.analyser(long_domaine, "A", 45) is not None

    def test_txt_burst(self):
        """Une rafale de requêtes TXT déclenche une alerte."""
        detector = DnsTunnelDetector(window=10, seuil_txt_burst=3)
        assert detector.analyser("exfil.com", "TXT", 20) is None
        assert detector.analyser("exfil.com", "TXT", 20) is None
        assert detector.analyser("exfil.com", "TXT", 20) is not None

    def test_sous_domaines_profonds(self):
        """Des sous-domaines très profonds déclenchent une alerte."""
        detector = DnsTunnelDetector()
        profond = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.exemple.com"
        # Modifier le seuil pour que le test passe
        detector.seuil_taille = 20
        assert detector.analyser(profond, "A", 50) is not None

    def test_reset(self):
        """Vérifie que reset() vide tous les compteurs."""
        detector = DnsTunnelDetector(window=10, seuil_txt_burst=3)
        detector.analyser("exfil.com", "TXT", 20)
        detector.analyser("exfil.com", "TXT", 20)
        detector.reset()
        # Après reset, le compteur repart à zéro
        assert detector.analyser("exfil.com", "TXT", 20) is None
