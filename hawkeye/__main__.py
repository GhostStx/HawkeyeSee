#!/usr/bin/env python3
"""
HawkEye v2 — Sniffer DNS & Détecteur d'Anomalies
===================================================
Point d'entrée principal du package.

Usage :
    python -m hawkeye                        # Lancer le sniffer
    python -m hawkeye --help                 # Aide
    python -m hawkeye dashboard              # Lancer le dashboard web
    python -m hawkeye --list                 # Voir l'historique
    python -m hawkeye --export-json          # Exporter en JSON
    python -m hawkeye --export-csv           # Exporter en CSV
    python -m hawkeye --stats                # Voir les statistiques
"""

import argparse
import asyncio
import os
import sys
import signal
from pathlib import Path

from scapy.all import IP, UDP, DNS, DNSQR, sniff

from . import __version__
from .database import (
    init_db, get_db, exporter_json, exporter_csv, stats as db_stats,
    lister_requetes, chercher_requetes,
)
from .detectors import BlacklistChecker, DgaDetector, DnsTunnelDetector
from .notifiers import ConsoleNotifier, TelegramNotifier

# ── Constantes ───────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = SCRIPT_DIR / "logs"
DB_PATH = SCRIPT_DIR / "hawkeye.db"
MALICIOUS_FILE = SCRIPT_DIR / "malicious.txt"
JSON_EXPORT_PATH = LOGS_DIR / "export.json"
CSV_EXPORT_PATH = LOGS_DIR / "export.csv"


# ── Callback du sniffer ─────────────────────────────────────────────────────

class SnifferContext:
    """Contexte partagé entre le sniffer et les callbacks."""

    def __init__(
        self,
        conn,
        blacklist: BlacklistChecker,
        dga: DgaDetector,
        dnstunnel: DnsTunnelDetector,
        console: ConsoleNotifier,
        telegram: TelegramNotifier,
        args,
    ):
        self.conn = conn
        self.blacklist = blacklist
        self.dga = dga
        self.dnstunnel = dnstunnel
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
    if ctx.telegram.enabled and alerte:
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
        epilog=f"""
Exemples :
  %(prog)s                          # Sniffer toutes les requêtes DNS
  %(prog)s --no-type-a-only         # Inclure AAAA, MX, etc.
  %(prog)s --export-json            # Sniffer + export JSON
  %(prog)s --export-csv             # Sniffer + export CSV
  %(prog)s dashboard                # Lancer le dashboard web
  %(prog)s --list                   # Voir l'historique
  %(prog)s --stats                  # Statistiques
  %(prog)s --recherche --domaine example.com  # Rechercher un domaine
  %(prog)s --db /tmp/test.db        # Base personnalisée
        """,
    )

    # Options de sniffing
    parser.add_argument(
        "--type-a-only", action=argparse.BooleanOptionalAction, default=True,
        help="Ne capturer que les requêtes TYPE A (défaut: True)",
    )
    parser.add_argument(
        "--db", type=str, default=str(DB_PATH),
        help=f"Chemin de la base SQLite (défaut: {DB_PATH})",
    )
    parser.add_argument(
        "--malicious", type=str, default=str(MALICIOUS_FILE),
        help=f"Fichier de liste noire (défaut: {MALICIOUS_FILE})",
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

    # Dashboard
    parser.add_argument(
        "commande", nargs="?", default="",
        choices=["", "dashboard"],
        help="Commande spéciale (dashboard)",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Hôte pour le dashboard (défaut: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Port pour le dashboard (défaut: 5000)",
    )

    return parser


# ── Modes sans sniffing ──────────────────────────────────────────────────────

def mode_stats(db_path: str):
    """Affiche les statistiques."""
    with get_db(db_path) as conn:
        s = db_stats(conn)
        print(f"\n{'═' * 50}")
        print(f"  📊 Statistiques HawkEye")
        print(f"{'═' * 50}")
        print(f"  📦 Requêtes totales  : {s['total']}")
        print(f"  🚨 Alertes           : {s['alertes']}")
        print(f"  🌐 Domaines uniques  : {s['domaines_uniques']}")
        print(f"  🖥️  IPs sources       : {s['ips_uniques']}")
        if s["premiere_requete"]:
            print(f"\n  🕐 Première requête  : {s['premiere_requete']}")
            print(f"  🕐 Dernière requête  : {s['derniere_requete']}")
        if s["stats_alertes"]:
            print(f"\n  Par type d'alerte :")
            for atype, count in s["stats_alertes"].items():
                print(f"    • {atype}: {count}")
        if s["top_domaines"]:
            print(f"\n  Top domaines :")
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

    # Base de données
    conn = init_db(args.db)
    console.info(f"Base SQLite : {args.db}")

    # Telegram
    telegram = TelegramNotifier()
    if telegram.enabled:
        console.info("Notifications Telegram activées")
    else:
        print("[i] Telegram : désactivé (définissez HAWKEYE_TELEGRAM_TOKEN et CHAT_ID)")

    # Contexte
    ctx = SnifferContext(conn, blacklist, dga, dnstunnel, console, telegram, args)

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
        console.stats_live()
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

    # ── Mode dashboard ──
    if args.commande == "dashboard":
        mode_dashboard(args.db, args.host, args.port)
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
