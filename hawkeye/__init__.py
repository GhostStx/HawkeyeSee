"""
HawkEye — Sniffer DNS & Détecteur d'Anomalies
===============================================
Un outil de cybersécurité réseau pour capturer, analyser et alerter
sur le trafic DNS suspect.

Modules :
  - detectors.blacklist   : Vérification liste noire de domaines
  - detectors.dga         : Détection de Domain Generation Algorithms (entropie + ML)
  - detectors.dnstunnel   : Détection d'exfiltration par tunnel DNS
  - notifiers.console     : Affichage console coloré
  - notifiers.telegram    : Notifications Telegram
  - dashboard.app         : Interface web Flask temps réel
  - database              : Persistance SQLite + export JSON/CSV
"""

__version__ = "2.0.0"
__author__ = "HawkEye"
__description__ = "DNS Sniffer & Anomaly Detector for Cybersecurity"
