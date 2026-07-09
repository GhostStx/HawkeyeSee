"""
HawkEye — Détection de Tunnel DNS
==================================
Détecte les tentatives d'exfiltration de données via DNS en analysant :

  1. **Taille de la requête** — Les requêtes DNS normales sont courtes
  2. **Sous-domaines longs** — Exfiltration dans le nom de domaine
  3. **Requêtes TXT fréquentes** — Utilisé pour exfiltrer en réponse
  4. **Débit anormal** — Rafales de requêtes vers un même domaine
  5. **Entropie élevée** — Données exfiltrées = haute entropie
"""

import math
import time
from collections import defaultdict
from typing import Optional


class DnsTunnelDetector:
    """Détecte les tunnels DNS (exfiltration de données)."""

    # Une requête DNS typique : ~30-50 bytes pour le nom
    # Les tunnels peuvent avoir des noms de 100+ bytes
    SEUIL_TAILLE_NOM = 60  # caractères dans le nom complet
    SEUIL_ENTROPIE_TUNNEL = 4.2
    SEUIL_TXT_BURST = 10  # requêtes TXT vers même domaine en N secondes
    SEUIL_DEBIT = 50  # requêtes totales par fenêtre

    def __init__(
        self,
        window: int = 10,
        seuil_taille: int = 60,
        seuil_txt_burst: int = 10,
        seuil_debit: int = 50,
    ):
        self.window = window
        self.seuil_taille = seuil_taille
        self.seuil_txt_burst = seuil_txt_burst
        self.seuil_debit = seuil_debit
        self.seuil_entropie_tunnel = self.SEUIL_ENTROPIE_TUNNEL
        # Compteurs temporels
        self._txt_counts: dict[str, list[float]] = defaultdict(list)
        self._total_timestamps: list[float] = []
        self._domaine_timestamps: dict[str, list[float]] = defaultdict(list)

    @staticmethod
    def entropie(texte: str) -> float:
        """Calcule l'entropie de Shannon."""
        if not texte:
            return 0.0
        freq: dict[str, int] = {}
        for c in texte.lower():
            freq[c] = freq.get(c, 0) + 1
        taille = len(texte)
        return -sum(
            (count / taille) * math.log2(count / taille)
            for count in freq.values()
        )

    def analyser(
        self, domaine: str, qtype: str, taille_nom: int
    ) -> Optional[str]:
        """Analyse une requête DNS pour détecter un tunnel.

        Args:
            domaine: Le domaine interrogé (complet)
            qtype: Type de requête DNS (A, TXT, etc.)
            taille_nom: Taille du nom de domaine en bytes

        Returns:
            Message d'alerte ou None
        """
        now = time.time()
        alertes: list[str] = []

        # ── 1. Nom anormalement long ──
        if taille_nom > self.seuil_taille:
            alertes.append(
                f"Nom long ({taille_nom} bytes) — possible exfiltration"
            )

        # ── 2. Haute entropie dans le nom ──
        nom = domaine.replace(".", "")
        e = self.entropie(nom)
        if e > self.seuil_entropie_tunnel and len(nom) > 30:
            alertes.append(
                f"Entropie élevée ({e:.2f}) — données encodées probables"
            )

        # ── 3. Rafale de requêtes TXT ──
        if qtype == "TXT":
            domaine_base = ".".join(domaine.split(".")[-2:])
            self._txt_counts[domaine_base] = [
                t for t in self._txt_counts[domaine_base]
                if now - t <= self.window
            ]
            self._txt_counts[domaine_base].append(now)

            if len(self._txt_counts[domaine_base]) >= self.seuil_txt_burst:
                alertes.append(
                    f"{len(self._txt_counts[domaine_base])} requêtes TXT "
                    f"vers {domaine_base} en {self.window}s — possible tunnel"
                )
                self._txt_counts[domaine_base].clear()

        # ── 4. Débit anormal ──
        self._total_timestamps = [
            t for t in self._total_timestamps if now - t <= self.window
        ]
        self._total_timestamps.append(now)

        if len(self._total_timestamps) >= self.seuil_debit:
            alertes.append(
                f"Débit élevé ({len(self._total_timestamps)} req/{self.window}s)"
            )

        # ── 5. Rafale vers un sous-domaine ──
        if len(domaine.split(".")) > 3:
            # Nom avec beaucoup de sous-domaines (ex: a.b.c.evil.com)
            sous_parties = domaine.split(".")[:-2]
            if len(".".join(sous_parties)) > 40:
                alertes.append(
                    f"Sous-domaines profonds ({len(sous_parties)} niveaux)"
                )

        if alertes:
            return f"[TUNNEL DNS] {' | '.join(alertes)}"
        return None

    def reset(self) -> None:
        """Réinitialise tous les compteurs."""
        self._txt_counts.clear()
        self._total_timestamps.clear()
        self._domaine_timestamps.clear()
