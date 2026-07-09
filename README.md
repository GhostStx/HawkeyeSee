<div align="center">

# 🦅 HawkEye v2

**Sniffer DNS & Détecteur d'Anomalies — Cybersécurité Réseau**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![CI](https://github.com/GhostStx/HawkeyeSee/actions/workflows/ci.yml/badge.svg)](https://github.com/GhostStx/HawkeyeSee/actions)
[![Code style](https://img.shields.io/badge/Code%20Style-flake8-black)](https://flake8.pycqa.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://docker.com)
[![Flask](https://img.shields.io/badge/Dashboard-Flask-black?logo=flask)](https://flask.palletsprojects.com)

**Capturez le trafic DNS en temps réel, détectez les malwares, les DGA et les tunnels DNS.**  
Projet conçu pour la cybersécurité offensive et défensive — idéal pour portfolio.

</div>

---

## ✨ Fonctionnalités

| # | Fonctionnalité | Détails |
|---|----------------|---------|
| 1 | **Sniffing DNS temps réel** | Capture tout le trafic DNS via Scapy, filtrage par type |
| 2 | **🚨 Liste noire** | Détection de domaines malveillants (phishing, malware, C2) avec support wildcard |
| 3 | **🧠 DGA avancé** | Détection algorithmique par entropie, bigrammes, ratio voyelles/chiffres |
| 4 | **🔓 Tunnel DNS** | Détection d'exfiltration (noms longs, TXT burst, débit anormal) |
| 5 | **📊 Dashboard web** | Interface temps réel avec graphiques, filtres, recherche (Flask + SSE) |
| 6 | **📱 Telegram** | Notifications d'alertes en temps réel sur votre canal |
| 7 | **💾 Persistance SQLite** | Stockage complet + exports JSON / CSV |
| 8 | **🐳 Docker** | Déploiement clé en main avec docker-compose |
| 9 | **✅ Tests** | Suite pytest avec couverture de code |
| 10 | **⚙️ CI/CD** | GitHub Actions — lint + test + build |

---

## 🚀 Démarrage rapide

### Installation

```bash
# Cloner
git clone https://github.com/GhostStx/HawkeyeSee.git
cd HawkEye

# Installer les dépendances
pip install -r requirements.txt
```

### Lancer le sniffer

```bash
# Mode sniffer (nécessite sudo pour capturer les paquets)
sudo python3 -m hawkeye

# Mode dashboard web (interface temps réel)
python3 -m hawkeye dashboard

# Voir l'historique
python3 -m hawkeye --list

# Statistiques
python3 -m hawkeye --stats

# Exporter en JSON
python3 -m hawkeye --export-json

# Exporter en CSV
python3 -m hawkeye --export-csv
```

### Options

```bash
# Inclure AAAA, MX, TXT...
sudo python3 -m hawkeye --no-type-a-only

# Base personnalisée
sudo python3 -m hawkeye --db /tmp/analyse.db

# Dashboard sur un port spécifique
python3 -m hawkeye dashboard --port 8080

# Rechercher dans l'historique
python3 -m hawkeye --recherche --domaine evil.com
python3 -m hawkeye --recherche --alerte-type DGA
```

---

## 🧪 Générer du trafic de test

Pendant que HawkEye tourne, dans un autre terminal :

```bash
# Requête normale
nslookup google.com 1.1.1.1

# Tester la liste noire
nslookup malware-tracker.example.com 1.1.1.1

# Simuler une activité DGA (domaines aléatoires)
for i in {1..10}; do nslookup "xyz$RANDOM.xyz" 1.1.1.1; done

# Simuler un tunnel DNS (noms longs)
nslookup "$(python3 -c "print('a'*60)").exfil.com" 1.1.1.1

# Rafale de TXT queries
for i in {1..15}; do nslookup -type=TXT test$i.exfil.com 1.1.1.1; done
```

---

## 🧠 Détection DGA — Comment ça marche

HawkEye combine **5 métriques** pour détecter les domaines générés algorithmiquement :

| Métrique | Détail | Poids |
|----------|--------|-------|
| **Entropie de Shannon** | Les DGA ont une distribution de caractères plus aléatoire | ×2.0 |
| **Ratio voyelles** | Les DGA ont peu de voyelles (< 30%) | ×1.5 |
| **Bigrammes rares** | Les DGA utilisent des combinaisons inhabituelles | ×1.5 |
| **Taux de chiffres** | Beaucoup de chiffres = suspect | ×1.0 |
| **Longueur du nom** | Les DGA sont souvent longs (> 15 car.) | ×1.0 |

Le score composite (0.0 → normal, 1.0 → DGA) est calculé en temps réel.

---

## 📁 Structure du projet

```
HawkEye/
├── hawkeye/                  # Package Python principal
│   ├── __init__.py           # Version et métadonnées
│   ├── __main__.py           # Point d'entrée CLI
│   ├── database.py           # SQLite + exports JSON/CSV
│   ├── detectors/
│   │   ├── blacklist.py      # Vérification liste noire
│   │   ├── dga.py            # Détection DGA (entropie + ML)
│   │   └── dnstunnel.py      # Détection tunnel DNS
│   ├── notifiers/
│   │   ├── console.py        # Affichage console coloré
│   │   └── telegram.py       # Notifications Telegram
│   └── dashboard/
│       ├── app.py            # Serveur Flask + SSE
│       └── templates/
│           └── index.html    # Interface utilisateur
├── tests/
│   ├── conftest.py           # Fixtures partagées
│   ├── test_database.py      # Tests SQLite
│   └── test_detectors.py     # Tests détecteurs
├── malicious.txt             # Liste noire de domaines
├── requirements.txt          # Dépendances
├── requirements-dev.txt      # Dépendances dev
├── Dockerfile                # Build Docker
├── docker-compose.yml        # Orchestration Docker
└── README.md                 # Cette documentation
```

---

## 🐳 Docker

```bash
# Construire l'image
docker build -t hawkeye .

# Lancer le sniffer (avec les droits réseau)
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/malicious.txt:/app/malicious.txt:ro hawkeye

# Lancer le dashboard
docker run --rm -p 5000:5000 hawkeye dashboard

# Tout en un (docker-compose)
docker-compose up -d
```

---

## 📱 Notifications Telegram

1. Créez un bot avec [@BotFather](https://t.me/BotFather) sur Telegram
2. Obtenez le token et l'ID du chat
3. Configurez les variables d'environnement :

```bash
export HAWKEYE_TELEGRAM_TOKEN="123456:ABC-DEF1234"
export HAWKEYE_TELEGRAM_CHAT_ID="-1001234567890"
sudo -E python3 -m hawkeye
```

Les alertes **BLACKLIST**, **DGA** et **TUNNEL DNS** seront envoyées automatiquement.

---

## 🧪 Tests

```bash
# Installer les dépendances de développement
pip install -r requirements-dev.txt

# Lancer tous les tests
python -m pytest tests/ -v

# Avec couverture
python -m pytest tests/ --cov=hawkeye --cov-report=term-missing
```

---

## 📊 Roadmap

- [x] **v1.0** — Sniffing DNS + liste noire + DGA basique + SQLite
- [x] **v2.0** — Package structuré, DGA entropique, tunnel DNS, dashboard, Telegram, Docker, CI
- [ ] **v2.5** — Mode serveur (API REST complète), GeoIP, WhoIS lookup
- [ ] **v3.0** — Machine Learning (Random Forest pour DGA), corrélation MITRE ATT&CK

---

## 🛡️ Pourquoi ce projet sur mon CV ?

| Compétence | Preuve |
|------------|--------|
| **Réseau** | Capture/analyse paquets DNS (Scapy, protocole DNS) |
| **Sécurité** | Détection malware, DGA, exfiltration |
| **Python** | Programmation orientée objet, asynchrone, tests |
| **Web** | Dashboard Flask temps réel (SSE, Chart.js) |
| **DevOps** | Docker, docker-compose, CI/CD GitHub Actions |
| **Data** | SQLite, statistiques, exports JSON/CSV |

---

<div align="center">

**Projet étudiant — Réseaux & Sécurité Informatique**  
Construit avec ❤️ et beaucoup de paquets DNS

</div>

## 📸 Aperçu

![HawkEye en action](docs/demo.gif)
*(GIF à générer — voir section suivante)*

### Générer un GIF de démonstration

1. Lancez HawkEye : `sudo python3 hawkeye.py`
2. Dans un autre terminal, générez du trafic :
   ```bash
   for i in {1..100}; do nslookup -type=any "test$RANDOM.xyz" 1.1.1.1; done
   ```
3. Utilisez [Terminalizer](https://github.com/faressoft/terminalizer) ou [asciinema](https://asciinema.org/) pour enregistrer et convertir en GIF.

## ⚠️ Notes

- Le script nécessite **`sudo`** ou les capacités `CAP_NET_RAW` pour le sniffing.
- La détection DGA est basique (seuil par TLD) — peut produire des faux positifs.
- La base SQLite est créée automatiquement au premier lancement.

---

Projet réalisé dans le cadre d'un apprentissage de la cybersécurité offensive/défensive.
