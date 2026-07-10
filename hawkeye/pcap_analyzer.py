"""
HawkEye — Analyseur PCAP offline
=================================
Permet d'analyser des fichiers .pcap / .pcapng pré-capturés
sans avoir besoin de sniffer en direct. Utile pour :
  - Analyser une capture existante (Wireshark, tcpdump)
  - Tester les détecteurs sur un dataset connu
  - Forensic réseau
"""

from pathlib import Path

from .database import init_db, inserer_requete
from .detectors import BlacklistChecker, DgaDetector, DnsTunnelDetector
from .notifiers import ConsoleNotifier


class PcapAnalyzer:
    """Analyse un fichier PCAP hors-ligne."""

    def __init__(
        self,
        pcap_path: str,
        db_path: str = ":memory:",
        malicious_path: str = "malicious.txt",
        progress: bool = True,
    ):
        self.pcap_path = Path(pcap_path)
        self.db_path = db_path
        self.malicious_path = malicious_path
        self.show_progress = progress

    def analyser(self) -> dict:
        """Analyse le fichier PCAP et retourne les statistiques.

        Retourne:
            dict avec les clés : total, alertes, duree, chemin_pcap
        """
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"Fichier PCAP introuvable : {self.pcap_path}")

        # Vérifier que scapy est disponible
        try:
            from scapy.utils import rdpcap
            from scapy.all import IP, DNSQR
        except ImportError:
            raise ImportError("Scapy est requis pour l'analyse PCAP")

        # Initialisation
        console = ConsoleNotifier()
        blacklist = BlacklistChecker(self.malicious_path)
        blacklist.charger()
        dga = DgaDetector()
        dnstunnel = DnsTunnelDetector()
        conn = init_db(self.db_path)

        print(f"\n{'═' * 55}")
        print(f"  📂 Analyse PCAP : {self.pcap_path.name}")
        print(f"{'═' * 55}")

        # Chargement
        try:
            packets = rdpcap(str(self.pcap_path))
        except Exception as e:
            raise RuntimeError(f"Erreur de lecture PCAP : {e}")

        total = len(packets)
        console.info(f"{total} paquets chargés")

        # Traitement
        compteur = 0
        alertes = 0
        paquets_dns = 0

        for i, packet in enumerate(packets):
            if self.show_progress and total > 1000 and i % 1000 == 0:
                pct = (i / total) * 100
                barre = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                print(f"\r  [{barre}] {pct:.0f}% ({i}/{total})", end="", flush=True)

            if not packet.haslayer(DNSQR):
                continue

            paquets_dns += 1

            try:
                domaine = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                ip_source = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
                qtype_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 255: "ANY"}
                qtype = qtype_map.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
                taille_nom = len(domaine) + 2
            except Exception:
                continue

            alerte = None
            alerte_type = None

            # Détection
            bl_type = blacklist.check(domaine)
            if bl_type:
                alerte_type = "BLACKLIST"
                alerte = f"Domaine malveillant : {domaine}"
            else:
                dga_msg = dga.analyser(domaine)
                if dga_msg:
                    alerte_type = "DGA"
                    alerte = dga_msg

                tunnel_msg = dnstunnel.analyser(domaine, qtype, taille_nom)
                if tunnel_msg:
                    alerte_type = "TUNNEL_DNS"
                    alerte = tunnel_msg

            # Stockage
            inserer_requete(conn, ip_source, domaine, qtype, alerte, alerte_type)

            if alerte:
                alertes += 1
                console.paquet(ip_source, domaine, qtype, alerte, alerte_type)

            compteur += 1

        print()  # newline after progress bar

        # Résultats
        duree = self._estimer_duree(packets)
        console.titre("Analyse terminée")
        console.info(f"{paquets_dns} requêtes DNS sur {total} paquets")
        console.info(f"{alertes} alertes générées")

        resultat = {
            "total_paquets": total,
            "requetes_dns": paquets_dns,
            "alertes": alertes,
            "duree_estimee": duree,
            "chemin_pcap": str(self.pcap_path),
        }

        conn.close()
        return resultat

    @staticmethod
    def _estimer_duree(packets) -> str:
        """Estime la durée de la capture à partir des timestamps."""
        try:
            if len(packets) < 2:
                return "N/A"
            debut = float(packets[0].time)
            fin = float(packets[-1].time)
            secondes = int(fin - debut)
            if secondes < 60:
                return f"{secondes}s"
            elif secondes < 3600:
                return f"{secondes // 60}m {secondes % 60}s"
            else:
                return f"{secondes // 3600}h {(secondes % 3600) // 60}m"
        except Exception:
            return "N/A"


def analyser_pcap(pcap_path: str, db_path: str = "hawkeye.db",
                  malicious_path: str = "malicious.txt") -> dict:
    """Fonction d'appel rapide pour l'analyse PCAP."""
    analyzer = PcapAnalyzer(pcap_path, db_path, malicious_path)
    return analyzer.analyser()
