"""
HawkEye — Détecteur par Liste Noire
====================================
Vérifie si un domaine figure dans une liste noire locale.
Support : domaines exacts, sous-domaines, patterns wildcard.
"""

from pathlib import Path
from typing import Optional


class BlacklistChecker:
    """Vérifie les domaines contre une liste noire avec support wildcard."""

    def __init__(self, path: str = "malicious.txt"):
        self.path = path
        self._exact: set[str] = set()
        self._suffixes: set[str] = set()  # domaines commençant par .
        self._loaded = False

    def charger(self) -> bool:
        """Charge la liste noire depuis le fichier. Retourne True si OK."""
        self._exact.clear()
        self._suffixes.clear()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for ligne in f:
                    ligne = ligne.strip().lower()
                    if not ligne or ligne.startswith("#"):
                        continue
                    if ligne.startswith("."):
                        # .example.com => tout sous-domaine de example.com
                        self._suffixes.add(ligne)
                    else:
                        self._exact.add(ligne)
            self._loaded = True
            return True
        except FileNotFoundError:
            print(f"[!] Liste noire introuvable : {self.path}")
            return False

    @property
    def count(self) -> int:
        return len(self._exact) + len(self._suffixes)

    def check(self, domaine: str) -> Optional[str]:
        """Vérifie un domaine. Retourne le type d'alerte ou None."""
        if not self._loaded:
            if not self.charger():
                return None

        domaine = domaine.lower()

        # Vérification exacte
        if domaine in self._exact:
            return "BLACKLIST"

        # Vérification suffixe (sous-domaines)
        for suffix in self._suffixes:
            if domaine.endswith(suffix) or domaine == suffix.lstrip("."):
                return "BLACKLIST"

        # Vérification wildcard (*.exemple.com)
        for entry in self._exact:
            if "*." in entry:
                pattern = entry.replace("*.", "")
                if domaine.endswith(pattern) or domaine == pattern:
                    return "BLACKLIST"

        return None

    def est_malveillant(self, domaine: str) -> bool:
        return self.check(domaine) is not None
