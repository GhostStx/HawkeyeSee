"""Tests du module de déduplication d'alertes."""

import time
from hawkeye.deduplicator import AlertDeduplicator


class TestAlertDeduplicator:
    def test_premiere_alerte_non_dupliquee(self):
        """Une première alerte n'est jamais dupliquée."""
        dedup = AlertDeduplicator(cooldown_default=10)
        assert not dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")

    def test_meme_alerte_dupliquee(self):
        """La même alerte dans le cooldown est dupliquée."""
        dedup = AlertDeduplicator(cooldown_default=60)
        dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")
        assert dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")

    def test_cooldown_expire(self):
        """Avec cooldown=0, l'alerte n'est jamais dupliquée."""
        dedup = AlertDeduplicator(
            cooldown_default=0,
            cooldown_blacklist=0,
            cooldown_dga=0,
            cooldown_tunnel=0,
        )
        dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")
        assert not dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")

    def test_domaines_differents_non_dupliques(self):
        """Deux domaines différents ne sont pas dupliqués."""
        dedup = AlertDeduplicator()
        assert not dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")
        assert not dedup.est_dupliquee("autre.com", "BLACKLIST", "10.0.0.1")

    def test_types_differents_non_dupliques(self):
        """Deux types d'alerte différents ne sont pas dupliqués."""
        dedup = AlertDeduplicator()
        assert not dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")
        assert not dedup.est_dupliquee("evil.com", "DGA", "10.0.0.1")

    def test_rate_limiting_par_ip(self):
        """Trop d'alertes d'une même IP sont throttlées."""
        dedup = AlertDeduplicator(max_alertes_par_ip=3, fenetre_ip=60)
        assert not dedup.est_dupliquee("a.com", "DGA", "10.0.0.1")
        assert not dedup.est_dupliquee("b.com", "DGA", "10.0.0.1")
        assert not dedup.est_dupliquee("c.com", "DGA", "10.0.0.1")
        # La 4e alerte de la même IP est dupliquée
        assert dedup.est_dupliquee("d.com", "DGA", "10.0.0.1")

    def test_reset(self):
        """Reset() vide tous les compteurs."""
        dedup = AlertDeduplicator(cooldown_default=60)
        dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")
        dedup.reset()
        assert not dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")

    def test_cooldown_par_type_different(self):
        """Les cooldowns sont différents selon le type d'alerte."""
        dedup = AlertDeduplicator(
            cooldown_blacklist=300,  # 5 min
            cooldown_dga=30,          # 30s
        )
        # BLACKLIST : longue durée
        dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")
        assert dedup.est_dupliquee("evil.com", "BLACKLIST", "10.0.0.1")

        # Même domaine mais type DGA : cooldown différent
        assert not dedup.est_dupliquee("evil.com", "DGA", "10.0.0.1")
