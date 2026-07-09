"""
HawkEye — Notifications Console
================================
Affichage coloré et structuré des alertes et du trafic DNS dans le terminal.
"""

from datetime import datetime
from typing import Optional


class ConsoleNotifier:
    """Gère l'affichage console avec couleurs et mise en forme."""

    # Codes ANSI
    ROUGE = "\033[91m"
    JAUNE = "\033[93m"
    VERT = "\033[92m"
    CYAN = "\033[96m"
    GRIS = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    # Cache pour les stats en temps réel
    _total_paquets = 0
    _total_alertes = 0

    def paquet(
        self,
        ip_source: str,
        domaine: str,
        qtype: str,
        alerte: Optional[str] = None,
        alerte_type: Optional[str] = None,
    ) -> None:
        """Affiche une ligne de requête DNS."""
        self._total_paquets += 1
        horloge = datetime.now().strftime("%H:%M:%S")

        if alerte_type == "BLACKLIST":
            prefix = f"{self.ROUGE}█ ALERTE ROUGE{self.RESET}"
            couleur_domaine = self.ROUGE
        elif alerte_type in ("DGA", "DGA_RAFALE"):
            prefix = f"{self.JAUNE}█ DGA{self.RESET}"
            couleur_domaine = self.JAUNE
        elif alerte_type == "TUNNEL_DNS":
            prefix = f"{self.CYAN}█ TUNNEL{self.RESET}"
            couleur_domaine = self.CYAN
        else:
            prefix = f"{self.GRIS}·{self.RESET}"
            couleur_domaine = self.RESET

        domaine_affiche = f"{couleur_domaine}{domaine}{self.RESET}"
        type_affiche = f"{self.GRIS}({qtype}){self.RESET}"

        print(
            f"{self.GRIS}[{horloge}]{self.RESET} "
            f"{prefix} "
            f"{ip_source} → {domaine_affiche} {type_affiche}"
        )

        if alerte:
            self._total_alertes += 1
            if alerte_type in ("BLACKLIST",):
                print(f"  {self.ROUGE}└─ {alerte}{self.RESET}")
            elif alerte_type in ("DGA", "DGA_RAFALE"):
                print(f"  {self.JAUNE}└─ {alerte}{self.RESET}")
            elif alerte_type == "TUNNEL_DNS":
                print(f"  {self.CYAN}└─ {alerte}{self.RESET}")

    def stats_live(self) -> str:
        """Retourne une ligne de stats en temps réel."""
        return (
            f"{self.GRIS}[Stats]{self.RESET} "
            f"Paquets: {self._total_paquets} | "
            f"Alertes: {self._total_alertes}"
        )

    @staticmethod
    def info(message: str) -> None:
        """Affiche un message d'information."""
        print(f"\033[92m[✓]\033[0m {message}")

    @staticmethod
    def warning(message: str) -> None:
        """Affiche un avertissement."""
        print(f"\033[93m[!]\033[0m {message}")

    @staticmethod
    def error(message: str) -> None:
        """Affiche une erreur."""
        print(f"\033[91m[✗]\033[0m {message}")

    @staticmethod
    def titre(message: str) -> None:
        """Affiche un titre."""
        print(f"\n\033[1;96m{'═' * 60}")
        print(f"  {message}")
        print(f"{'═' * 60}\033[0m")
