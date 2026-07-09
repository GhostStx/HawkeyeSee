"""
HawkEye — Détection DGA (Domain Generation Algorithms)
=======================================================
Détecte les domaines potentiellement générés algorithmiquement en combinant :

  1. **Entropie de Shannon** — Les domaines DGA ont une entropie élevée
  2. **Ratio voyelles/consonnes** — Les DGA ont peu de voyelles
  3. **Longueur du nom** — Les DGA sont souvent longs (> 15 car.)
  4. **N-grammes** — Fréquence de bigrammes inhabituels
  5. **Taux de chiffres** — Proportion de caractères numériques
  6. **Fenêtre glissante temporelle** — Rafales vers le même TLD
"""

import math
import re
import time
from collections import Counter, defaultdict
from typing import Optional


class _BaseDgaDetector:
    """Méthodes de base pour le calcul de scores linguistiques."""

    VOYELLES = set("aeiouy")
    CONSONNES = set("bcdfghjklmnpqrstvwxz")
    # Bigrammes courants en anglais (non-DGA)
    BIGRAMMES_COMMUNS = {
        "th", "he", "in", "er", "an", "re", "ed", "on", "es", "st",
        "en", "at", "to", "nt", "ha", "nd", "ou", "ea", "ng", "or",
        "ti", "as", "te", "et", "is", "ar", "al", "it", "le", "se",
    }

    @staticmethod
    def entropie_shannon(texte: str) -> float:
        """Calcule l'entropie de Shannon du texte (en bits par caractère)."""
        if not texte:
            return 0.0
        freq: dict[str, int] = Counter(texte.lower())
        taille = len(texte)
        return -sum(
            (count / taille) * math.log2(count / taille)
            for count in freq.values()
        )

    @staticmethod
    def ratio_voyelles(texte: str) -> float:
        """Proportion de voyelles dans le texte."""
        if not texte:
            return 0.0
        texte = texte.lower()
        voyelles = sum(1 for c in texte if c in _BaseDgaDetector.VOYELLES)
        return voyelles / len(texte)

    @staticmethod
    def ratio_chiffres(texte: str) -> float:
        """Proportion de chiffres dans le texte."""
        if not texte:
            return 0.0
        chiffres = sum(1 for c in texte if c.isdigit())
        return chiffres / len(texte)

    @staticmethod
    def score_bigrammes(texte: str) -> float:
        """Score de rareté des bigrammes. Plus le score est élevé, plus c'est suspect."""
        if len(texte) < 2:
            return 0.0
        texte = texte.lower()
        bigrammes = {texte[i:i+2] for i in range(len(texte)-1)}
        if not bigrammes:
            return 0.0
        rares = sum(1 for b in bigrammes if b not in _BaseDgaDetector.BIGRAMMES_COMMUNS)
        return rares / len(bigrammes)

    @staticmethod
    def longueur_max_consonnes(texte: str) -> int:
        """Longueur de la plus longue séquence de consonnes consécutives."""
        texte = texte.lower()
        max_seq = 0
        current = 0
        for c in texte:
            if c in _BaseDgaDetector.CONSONNES:
                current += 1
                max_seq = max(max_seq, current)
            else:
                current = 0
        return max_seq


class EntropyDgaDetector(_BaseDgaDetector):
    """Détecteur DGA avancé basé sur l'entropie et des caractéristiques lexicales.

    Combine plusieurs métriques en un score composite (0.0 → normal, 1.0 → DGA certain).
    """

    def __init__(
        self,
        seuil_entropie: float = 3.8,
        seuil_ratio_voyelles: float = 0.30,
        seuil_chiffres: float = 0.25,
        seuil_bigrammes: float = 0.60,
        seuil_consonnes: float = 5,
        poids_entropie: float = 2.0,
        poids_voyelles: float = 1.5,
        poids_chiffres: float = 1.0,
        poids_bigrammes: float = 1.5,
        poids_longueur: float = 1.0,
    ):
        self.seuil_entropie = seuil_entropie
        self.seuil_ratio_voyelles = seuil_ratio_voyelles
        self.seuil_chiffres = seuil_chiffres
        self.seuil_bigrammes = seuil_bigrammes
        self.seuil_consonnes = seuil_consonnes
        self.poids_entropie = poids_entropie
        self.poids_voyelles = poids_voyelles
        self.poids_chiffres = poids_chiffres
        self.poids_bigrammes = poids_bigrammes
        self.poids_longueur = poids_longueur

    def analyser(self, domaine: str) -> dict:
        """Analyse un domaine et retourne un rapport détaillé."""
        # Extraire le nom (sans le TLD)
        parties = domaine.lower().split(".")
        nom = parties[0] if len(parties) > 0 else domaine
        tld = parties[-1] if len(parties) > 1 else ""

        if not nom or len(nom) < 4:
            return {"score": 0.0, "dga": False, "raison": "Domaine trop court"}

        # Calcul des métriques
        entropie = self.entropie_shannon(nom)
        ratio_voy = self.ratio_voyelles(nom)
        ratio_chif = self.ratio_chiffres(nom)
        score_bg = self.score_bigrammes(nom)
        max_cons = self.longueur_max_consonnes(nom)
        longueur = len(nom)

        # Score composite (pondéré, normalisé entre 0 et ~1)
        s_entropie = min(entropie / 5.0, 1.0) * self.poids_entropie
        s_voyelles = max(1.0 - (ratio_voy / 0.4), 0.0) * self.poids_voyelles
        s_chiffres = min(ratio_chif / 0.5, 1.0) * self.poids_chiffres
        s_bigrammes = score_bg * self.poids_bigrammes
        s_longueur = min(longueur / 20.0, 1.0) * self.poids_longueur

        score_total = (s_entropie + s_voyelles + s_chiffres + s_bigrammes + s_longueur) / (
            self.poids_entropie + self.poids_voyelles + self.poids_chiffres
            + self.poids_bigrammes + self.poids_longueur
        )

        # Décision
        est_dga = (
            (entropie >= self.seuil_entropie and ratio_voy <= self.seuil_ratio_voyelles)
            or (score_bg >= self.seuil_bigrammes and max_cons >= self.seuil_consonnes)
            or (ratio_chif >= self.seuil_chiffres and entropie >= self.seuil_entropie)
            or score_total >= 0.6
        )

        # Raison détaillée
        raisons = []
        if entropie >= self.seuil_entropie:
            raisons.append(f"Entropie élevée ({entropie:.2f})")
        if ratio_voy <= self.seuil_ratio_voyelles:
            raisons.append(f"Peu de voyelles ({ratio_voy:.0%})")
        if ratio_chif >= self.seuil_chiffres:
            raisons.append(f"Beaucoup de chiffres ({ratio_chif:.0%})")
        if score_bg >= self.seuil_bigrammes:
            raisons.append(f"Bigrammes rares ({score_bg:.0%})")
        if max_cons >= self.seuil_consonnes:
            raisons.append(f"{max_cons} consonnes consécutives")
        if longueur >= 15:
            raisons.append(f"Nom long ({longueur} car.)")

        return {
            "score": round(score_total, 3),
            "dga": est_dga,
            "entropie": round(entropie, 2),
            "ratio_voyelles": round(ratio_voy, 3),
            "ratio_chiffres": round(ratio_chif, 3),
            "score_bigrammes": round(score_bg, 3),
            "max_consonnes": max_cons,
            "longueur": longueur,
            "raison": " | ".join(raisons) if raisons else "Apparence normale",
        }


class DgaDetector(_BaseDgaDetector):
    """Détecteur DGA avec fenêtre glissante temporelle.

    Version améliorée qui combine :
    - L'analyseur entropique (EntropyDgaDetector)
    - Le compteur temporel par TLD (rafales de domaines)
    """

    def __init__(self, threshold: int = 5, window: int = 10):
        self.threshold = threshold
        self.window = window
        self._hist: dict[str, list[tuple[float, str]]] = defaultdict(list)
        self._entropy = EntropyDgaDetector()

    def analyser(self, domaine: str) -> Optional[str]:
        """Analyse un domaine avec les deux méthodes combinées."""
        tld = domaine.rsplit(".", 1)[-1] if "." in domaine else domaine
        now = time.time()

        # 1. Nettoyage fenêtre glissante
        self._hist[tld] = [
            (t, d) for t, d in self._hist[tld] if now - t <= self.window
        ]
        self._hist[tld].append((now, domaine))

        # 2. Analyse entropique
        rapport = self._entropy.analyser(domaine)
        alerte_entropy = ""
        if rapport["dga"]:
            alerte_entropy = (
                f"[Score DGA={rapport['score']:.1%}] {rapport['raison']}"
            )

        # 3. Rafale vers le même TLD
        alerte_rafale = ""
        if len(self._hist[tld]) >= self.threshold:
            domaines = ", ".join(
                d for _, d in self._hist[tld][-self.threshold:]
            )
            self._hist[tld].clear()
            alerte_rafale = (
                f"{self.threshold}+ requêtes vers le TLD « {tld} » "
                f"en {self.window}s : {domaines}"
            )

        # 4. Combiner les alertes
        if alerte_entropy and alerte_rafale:
            return (
                f"[DGA ALERTE] {alerte_entropy} | Rafale : {alerte_rafale}"
            )
        elif alerte_entropy:
            return f"[DGA ALERTE] {alerte_entropy}"
        elif alerte_rafale:
            return f"[DGA ALERTE] Rafale : {alerte_rafale}"

        return None
