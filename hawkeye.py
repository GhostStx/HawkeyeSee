#!/usr/bin/env python3
"""
HawkEye v2 — Sniffer DNS & Détecteur d'Anomalies
==================================================
Point d'entrée de compatibilité (v1 → v2).
Redirige vers le package hawkeye/ structuré.

Usage recommandé :  python -m hawkeye --help
Usage legacy :      python hawkeye.py --help
"""

import sys
from pathlib import Path

# Ajouter le répertoire parent au path pour l'import
sys.path.insert(0, str(Path(__file__).parent))

from hawkeye.__main__ import main

if __name__ == "__main__":
    main()
