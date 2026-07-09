"""
HawkEye — Déduplication d'Alertes
===================================
Évite le spam d'alertes en dédupliquant :
  - Par domaine + type d'alerte (même alerte ignorée pendant N secondes)
  - Par IP source (trop d'alertes d'une même IP = throttle)
  - Par intervalle de répétition (cooldown progressif)
"""

import time
from collections import defaultdict
from typing import Optional


class AlertDeduplicator:
    """Évite les alertes redondantes avec cooldown adaptatif.

    Features :
      - Cooldown fixe par (domaine, type)
      - Cooldown exponentiel si répétition
      - Rate limiting par IP source
      - Seuils configurables
    """

    def __init__(
        self,
        cooldown_default: int = 60,
        cooldown_blacklist: int = 300,
        cooldown_dga: int = 120,
        cooldown_tunnel: int = 60,
        max_alertes_par_ip: int = 10,
        fenetre_ip: int = 60,
    ):
        self.cooldowns = {
            "BLACKLIST": cooldown_blacklist,
            "DGA": cooldown_dga,
            "DGA_RAFALE": cooldown_dga,
            "TUNNEL_DNS": cooldown_tunnel,
        }
        self.cooldown_default = cooldown_default
        self.max_alertes_par_ip = max_alertes_par_ip
        self.fenetre_ip = fenetre_ip

        # Dernière alerte par clé (domaine:type)
        self._derniere_alerte: dict[str, float] = {}
        # Compteur de répétitions
        self._repetitions: dict[str, int] = {}
        # Timestamps des alertes par IP
        self._alertes_par_ip: dict[str, list[float]] = defaultdict(list)

    def _cle(self, domaine: str, alerte_type: str) -> str:
        return f"{domaine.lower()}:{alerte_type}"

    def est_dupliquee(self, domaine: str, alerte_type: str,
                      ip_source: str) -> bool:
        """Vérifie si une alerte est dupliquée.

        Retourne True si l'alerte doit être ignorée (déjà vue récemment).
        """
        maintenant = time.time()
        cle = self._cle(domaine, alerte_type)

        # 1. Cooldown par (domaine, type)
        cooldown = self.cooldowns.get(alerte_type, self.cooldown_default)
        repetitions = self._repetitions.get(cle, 0)

        # Cooldown exponentiel : ×2 après 3 répétitions, ×4 après 5
        if repetitions >= 5:
            cooldown *= 4
        elif repetitions >= 3:
            cooldown *= 2

        derniere = self._derniere_alerte.get(cle, 0)
        if maintenant - derniere < cooldown:
            self._repetitions[cle] = self._repetitions.get(cle, 0) + 1
            return True

        # 2. Rate limiting par IP
        self._alertes_par_ip[ip_source] = [
            t for t in self._alertes_par_ip[ip_source]
            if maintenant - t <= self.fenetre_ip
        ]

        if len(self._alertes_par_ip[ip_source]) >= self.max_alertes_par_ip:
            return True  # Trop d'alertes de cette IP

        # 3. Nouvelle alerte acceptée
        self._derniere_alerte[cle] = maintenant
        self._alertes_par_ip[ip_source].append(maintenant)
        self._repetitions[cle] = 0
        return False

    def reset(self) -> None:
        """Réinitialise tous les compteurs."""
        self._derniere_alerte.clear()
        self._repetitions.clear()
        self._alertes_par_ip.clear()
