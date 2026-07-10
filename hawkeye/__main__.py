#!/usr/bin/env python3
"""
HawkEye v2.1 — Sniffer DNS & Détecteur d'Anomalies
=====================================================
Point d'entrée principal du package.

Usage :
    python -m hawkeye                          # Sniffer temps réel
    python -m hawkeye dashboard                # Dashboard web
    python -m hawkeye watch                    # Dashboard terminal
    python -m hawkeye report                   # Rapport HTML
    python -m hawkeye pcap capture.pcap        # Analyse PCAP offline
    python -m hawkeye --list                   # Historique
    python -m hawkeye --stats                  # Statistiques
    python -m hawkeye --recherche --domaine X  # Recherche
    python -m hawkeye --export-json            # Export JSON
    python -m hawkeye --export-csv             # Export CSV
"""

import argparse
import asyncio
import os
import sys
import signal
from pathlib import Path

# ── Chargement .env ──
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from scapy.all import IP, DNSQR, sniff

from . import __version__
from .database import (
    init_db, get_db, exporter_json, exporter_csv, stats as db_stats,
    lister_requetes, chercher_requetes,
)
from .detectors import BlacklistChecker, DgaDetector, DnsTunnelDetector
from .notifiers import ConsoleNotifier, TelegramNotifier
from .deduplicator import AlertDeduplicator

# ── Constantes ───────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = SCRIPT_DIR / "logs"
DB_PATH = SCRIPT_DIR / "hawkeye.db"
MALICIOUS_FILE = SCRIPT_DIR / "malicious.txt"
JSON_EXPORT_PATH = LOGS_DIR / "export.json"
CSV_EXPORT_PATH = LOGS_DIR / "export.csv"
RAPPORT_PATH = SCRIPT_DIR / "rapport.html"


# ── Callback du sniffer ─────────────────────────────────────────────────────

class SnifferContext:
    """Contexte partagé entre le sniffer et les callbacks."""

    def __init__(
        self,
        conn,
        blacklist: BlacklistChecker,
        dga: DgaDetector,
        dnstunnel: DnsTunnelDetector,
        dedup: AlertDeduplicator,
        console: ConsoleNotifier,
        telegram: TelegramNotifier,
        args,
    ):
        self.conn = conn
        self.blacklist = blacklist
        self.dga = dga
        self.dnstunnel = dnstunnel
        self.dedup = dedup
        self.console = console
        self.telegram = telegram
        self.args = args


def traiter_paquet(packet, ctx: SnifferContext) -> None:
    """Callback appelé pour chaque paquet DNS capturé."""
    if not packet.haslayer(DNSQR):
        return

    domaine = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
    ip_source = packet[IP].src

    # Type de requête
    qtype_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 255: "ANY"}
    qtype = qtype_map.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))

    # Filtre TYPE A
    if ctx.args.type_a_only and packet[DNSQR].qtype != 1:
        return

    alerte = None
    alerte_type = None

    # ── 1. Vérification liste noire ──
    bl_type = ctx.blacklist.check(domaine)
    if bl_type:
        alerte_type = "BLACKLIST"
        alerte = f"Domaine malveillant détecté : {domaine}"

    # ── 2. Détection DGA ──
    else:
        dga_msg = ctx.dga.analyser(domaine)
        if dga_msg:
            alerte_type = "DGA"
            alerte = dga_msg
            if "Rafale" in dga_msg:
                alerte_type = "DGA_RAFALE"

    # ── 3. Détection tunnel DNS ──
    taille_nom = len(domaine) + 2  # +2 pour les dots (estimation)
    tunnel_msg = ctx.dnstunnel.analyser(domaine, qtype, taille_nom)
    if tunnel_msg:
        alerte_type = "TUNNEL_DNS"
        alerte = (alerte + " | " + tunnel_msg) if alerte else tunnel_msg

    # ── 4. Déduplication ──
    if alerte and ctx.dedup.est_dupliquee(domaine, alerte_type, ip_source):
        # On stocke mais on n'affiche pas (silencieux)
        pass
    else:
        # ── Affichage console ──
        ctx.console.paquet(ip_source, domaine, qtype, alerte, alerte_type)

    # ── Base de données ──
    if ctx.conn is not None:
        from .database import inserer_requete
        inserer_requete(ctx.conn, ip_source, domaine, qtype, alerte, alerte_type)

    # ── Dashboard SSE ──
    try:
        from .dashboard.app import publier_requete
        publier_requete(ip_source, domaine, qtype, alerte, alerte_type)
    except Exception:
        pass

    # ── Notification Telegram (asynchrone) ──
    if ctx.telegram.enabled and alerte and not ctx.dedup.est_dupliquee(
            domaine, alerte_type, ip_source):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                ctx.telegram.envoyer_alerte(
                    titre="HawkEye Alerte",
                    domaine=domaine,
                    ip_source=ip_source,
                    type_alerte=alerte_type or "INCONNU",
                    details=alerte,
                )
            )
            loop.close()
        except Exception as e:
            print(f"[!] Telegram error: {e}")


# ── Parser CLI ───────────────────────────────────────────────────────────────

def creer_parser() -> argparse.ArgumentParser:
    """Crée le parseur d'arguments CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m hawkeye",
        description=f"HawkEye v{__version__} — Sniffer DNS & Détecteur d'Anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Sous-commandes :
  (par défaut)      Sniffer DNS en temps réel
  dashboard         Interface web (Flask)
  watch             Tableau de bord terminal
  report            Générer un rapport HTML
  pcap <fichier>    Analyser un fichier PCAP offline

Exemples :
  %(prog)s                          # Sniffer toutes les requêtes DNS
  %(prog)s dashboard                # Lancer le dashboard web
  %(prog)s watch                    # Dashboard terminal
  %(prog)s report                   # Rapport HTML
  %(prog)s pcap capture.pcap        # Analyse PCAP
  %(prog)s --stats                  # Statistiques
  %(prog)s --list                   # Voir l'historique
  %(prog)s --recherche --domaine X  # Rechercher un domaine
  %(prog)s --export-json            # Exporter en JSON
        """,
    )

    # Options globales
    parser.add_argument(
        "--db", type=str, default=str(DB_PATH),
        help=f"Chemin de la base SQLite (défaut: {DB_PATH})",
    )
    parser.add_argument(
        "--malicious", type=str, default=str(MALICIOUS_FILE),
        help=f"Fichier de liste noire (défaut: {MALICIOUS_FILE})",
    )

    # Options de sniffing
    parser.add_argument(
        "--type-a-only", action=argparse.BooleanOptionalAction, default=True,
        help="Ne capturer que les requêtes TYPE A (défaut: True)",
    )

    # Modes sans sniffing
    parser.add_argument(
        "--list", action="store_true",
        help="Afficher l'historique des requêtes",
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Afficher les statistiques de la base",
    )
    parser.add_argument(
        "--export-json", action="store_true",
        help="Exporter la base en JSON",
    )
    parser.add_argument(
        "--export-csv", action="store_true",
        help="Exporter la base en CSV",
    )
    parser.add_argument(
        "--export-json-only", action="store_true",
        help="Exporter la base en JSON (sans sniffer)",
    )

    # Recherche
    parser.add_argument(
        "--recherche", action="store_true",
        help="Mode recherche",
    )
    parser.add_argument("--domaine", type=str, default="", help="Filtrer par domaine")
    parser.add_argument("--ip", type=str, default="", help="Filtrer par IP source")
    parser.add_argument(
        "--alerte-type", type=str, default="",
        choices=["", "BLACKLIST", "DGA", "DGA_RAFALE", "TUNNEL_DNS"],
        help="Filtrer par type d'alerte",
    )

    # Sous-commandes positionnelles
    parser.add_argument(
        "commande", nargs="?", default="",
        choices=["", "dashboard", "watch", "report", "pcap"],
        help="Sous-commande (dashboard, watch, report, pcap)",
    )
    parser.add_argument(
        "fichier_pcap", nargs="?", default="",
        help="Fichier PCAP à analyser (mode pcap)",
    )

    # Dashboard options
    parser.add_argument(
        "--host", type=str,
        default="127.0.0.1",
        help="Hôte pour le dashboard (défaut: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int,
        default=int(os.getenv("HAWKEYE_DASHBOARD_PORT", "5000")),
        help="Port pour le dashboard (défaut: 5000)",
    )

    # Report options
    parser.add_argument(
        "--output", type=str, default="",
        help="Chemin de sortie pour le rapport HTML",
    )

    return parser


# ── Modes sans sniffing ──────────────────────────────────────────────────────

def mode_stats(db_path: str):
    """Affiche les statistiques."""
    with get_db(db_path) as conn:
        s = db_stats(conn)
        print("\n" + "═" * 50)
        print("  📊 Statistiques HawkEye")
        print("═" * 50)
        print(f"  📦 Requêtes totales  : {s['total']}")
        print(f"  🚨 Alertes           : {s['alertes']}")
        print(f"  🌐 Domaines uniques  : {s['domaines_uniques']}")
        print(f"  🖥️  IPs sources       : {s['ips_uniques']}")
        if s["premiere_requete"]:
            print(f"\n  🕐 Première requête  : {s['premiere_requete']}")
            print(f"  🕐 Dernière requête  : {s['derniere_requete']}")
        if s["stats_alertes"]:
            print("\n  Par type d'alerte :")
            for atype, count in s["stats_alertes"].items():
                print(f"    • {atype}: {count}")
        if s["top_domaines"]:
            print("\n  Top domaines :")
            for d in s["top_domaines"][:5]:
                print(f"    • {d['domaine']}: {d['count']}x")
        print()


def mode_liste(db_path: str):
    """Affiche l'historique."""
    with get_db(db_path) as conn:
        rows = lister_requetes(conn, 50)
        if not rows:
            print("📭 Aucune requête dans la base.")
            return
        print(
            f"{'ID':>4}  {'Timestamp':<24}  {'IP source':<18}  "
            f"{'Domaine':<40}  {'Type':<6}  Alerte"
        )
        print("-" * 130)
        for row in rows:
            alerte = (row["alerte"] or "")[:50]
            print(
                f"{row['id']:>4}  {row['timestamp']:<24}  {row['ip_source']:<18}  "
                f"{row['domaine']:<40}  {row['type_query']:<6}  {alerte}"
            )


def mode_recherche(db_path: str, domaine: str, ip: str, alerte_type: str):
    """Recherche des requêtes."""
    with get_db(db_path) as conn:
        rows = chercher_requetes(
            conn, domaine=domaine or None,
            ip_source=ip or None,
            alerte_type=alerte_type or None,
            limite=100,
        )
        if not rows:
            print("📭 Aucun résultat.")
            return
        print(f"\n🔍 {len(rows)} résultat(s) :\n")
        for row in rows:
            print(f"  [{row['timestamp']}] {row['ip_source']} → {row['domaine']} "
                  f"({row['type_query']}) "
                  f"{'🚨 ' + row['alerte_type'] if row['alerte_type'] else ''}")


# ── Mode dashboard ───────────────────────────────────────────────────────────

def mode_dashboard(db_path: str, host: str, port: int):
    """Lance le dashboard web."""
    try:
        from .dashboard.app import run_dashboard
    except ImportError as e:
        print(f"[!] Impossible de lancer le dashboard : {e}")
        print("    Installez Flask : pip install flask")
        sys.exit(1)
    run_dashboard(db_path=db_path, host=host, port=port)


# ── Mode watch ───────────────────────────────────────────────────────────────

def mode_watch(db_path: str):
    """Lance le dashboard terminal."""
    try:
        from .watch import TerminalDashboard
    except ImportError as e:
        print(f"[!] Impossible de lancer le mode watch : {e}")
        sys.exit(1)
    dash = TerminalDashboard(db_path)
    dash.run()


# ── Mode report ──────────────────────────────────────────────────────────────

def mode_report(db_path: str, output: str):
    """Génère un rapport HTML."""
    try:
        from .report import generer_rapport
    except ImportError as e:
        print(f"[!] Impossible de générer le rapport : {e}")
        sys.exit(1)
    chemin = output or str(RAPPORT_PATH)
    generer_rapport(db_path, chemin)


# ── Mode pcap ────────────────────────────────────────────────────────────────

def mode_pcap(pcap_path: str, db_path: str, malicious_path: str):
    """Analyse un fichier PCAP offline."""
    if not pcap_path:
        print("[!] Usage : python -m hawkeye pcap <fichier.pcap>")
        sys.exit(1)
    try:
        from .pcap_analyzer import analyser_pcap
    except ImportError as e:
        print(f"[!] Impossible d'analyser le PCAP : {e}")
        sys.exit(1)
    try:
        resultat = analyser_pcap(pcap_path, db_path, malicious_path)
        print(f"\n  Résumé : {resultat['requetes_dns']} requêtes DNS "
              f"sur {resultat['total_paquets']} paquets, "
              f"{resultat['alertes']} alertes")
        if resultat["duree_estimee"] != "N/A":
            print(f"  Durée capture : {resultat['duree_estimee']}")
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erreur analyse PCAP : {e}")
        sys.exit(1)


# ── Mode sniffing ────────────────────────────────────────────────────────────

def mode_sniff(args):
    """Lance le sniffer DNS."""
    os.makedirs(LOGS_DIR, exist_ok=True)

    # Initialisation
    console = ConsoleNotifier()

    # Liste noire
    blacklist = BlacklistChecker(args.malicious)
    blacklist.charger()
    if blacklist.count:
        console.info(f"Liste noire chargée : {blacklist.count} domaines")
    else:
        console.warning("Aucune liste noire chargée")

    # Détecteurs
    dga = DgaDetector()
    dnstunnel = DnsTunnelDetector()
    dedup = AlertDeduplicator()

    # Base de données
    conn = init_db(args.db)
    console.info(f"Base SQLite : {args.db}")

    # Telegram
    telegram = TelegramNotifier()
    if telegram.enabled:
        console.info("Notifications Telegram activées")
    else:
        print("[i] Telegram : désactivé (définissez HAWKEYE_TELEGRAM_TOKEN et CHAT_ID)")
    print("[i] Déduplication : active")

    # Contexte
    ctx = SnifferContext(conn, blacklist, dga, dnstunnel, dedup, console, telegram, args)

    # Gestion signal Ctrl+C
    def handler(sig, frame):
        print("\n\n[i] Arrêt demandé...")
        if args.export_json:
            exporter_json(conn, str(JSON_EXPORT_PATH))
        if args.export_csv:
            exporter_csv(conn, str(CSV_EXPORT_PATH))
        conn.close()
        if telegram.enabled:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(telegram.fermer())
                loop.close()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    console.titre("HawkEye en écoute (Ctrl+C pour arrêter)")

    try:
        sniff(
            filter="udp port 53",
            prn=lambda pkt: traiter_paquet(pkt, ctx),
            store=0,
        )
    except PermissionError:
        console.error("Permissions insuffisantes. Relancez avec sudo.")
        print("    sudo python3 -m hawkeye")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        if args.export_json:
            exporter_json(conn, str(JSON_EXPORT_PATH))
        if args.export_csv:
            exporter_csv(conn, str(CSV_EXPORT_PATH))
        conn.close()


# ── Point d'entrée ───────────────────────────────────────────────────────────

def main():
    parser = creer_parser()
    args = parser.parse_args()

    # ── Sous-commandes ──
    if args.commande == "dashboard":
        mode_dashboard(args.db, args.host, args.port)
        return

    if args.commande == "watch":
        mode_watch(args.db)
        return

    if args.commande == "report":
        output = args.output or str(RAPPORT_PATH)
        mode_report(args.db, output)
        return

    if args.commande == "pcap":
        mode_pcap(args.fichier_pcap, args.db, args.malicious)
        return

    # ── Modes sans sniffing ──
    if args.stats:
        mode_stats(args.db)
        return

    if args.list:
        mode_liste(args.db)
        return

    if args.recherche:
        mode_recherche(args.db, args.domaine, args.ip, args.alerte_type)
        return

    if args.export_json_only:
        with get_db(args.db) as conn:
            exporter_json(conn, str(JSON_EXPORT_PATH))
        return

    # ── Mode sniffing (par défaut) ──
    mode_sniff(args)


if __name__ == "__main__":
    main()
