"""
HawkEye — Générateur de Rapports HTML
=======================================
Produit un rapport HTML autonome (sans serveur) avec :
  - Statistiques globales
  - Graphiques (Chart.js embarqué)
  - Tableau des alertes
  - Top domaines et IPs
  - Timeline des événements

Usage :
    python -m hawkeye report
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .database import init_db, stats as db_stats, lister_requetes

# Template HTML intégré pour un rapport autonome
RAPPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HawkEye — Rapport d'Analyse</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
:root{--bg:#0d1117;--bg-card:#161b22;--border:#30363d;--text:#c9d1d9;--text-dim:#8b949e;--accent:#58a6ff;--rouge:#f85149;--jaune:#d29922;--vert:#3fb950;--cyan:#39d2c0}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);padding:20px}
.header{text-align:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
.header h1{font-size:28px}.header h1 span{color:var(--accent)}
.header .date{color:var(--text-dim);font-size:14px;margin-top:4px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
.stat-card .label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim)}
.stat-card .value{font-size:32px;font-weight:700;margin-top:4px}
.stat-card .value.danger{color:var(--rouge)}.stat-card .value.warning{color:var(--jaune)}
.stat-card .value.info{color:var(--cyan)}.stat-card .value.normal{color:var(--vert)}
.section{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}
.section h2{font-size:16px;margin-bottom:12px;color:var(--accent)}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:768px){.chart-row{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 12px;font-weight:600;color:var(--text-dim);border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:6px 12px;border-bottom:1px solid var(--border);font-family:'SF Mono','Fira Code',monospace;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600;text-transform:uppercase}
.badge-blacklist{background:rgba(248,81,73,.2);color:var(--rouge)}
.badge-dga{background:rgba(210,153,34,.2);color:var(--jaune)}
.badge-tunnel{background:rgba(57,210,192,.2);color:var(--cyan)}
.badge-normal{background:rgba(63,185,80,.15);color:var(--vert)}
.footer{text-align:center;color:var(--text-dim);font-size:12px;padding:20px;border-top:1px solid var(--border);margin-top:24px}
</style>
</head>
<body>
<div class="header">
<h1>🦅 <span>HawkEye</span> — Rapport d'Analyse</h1>
<div class="date">Généré le {{ DATE }} | Base : {{ DB_NAME }}</div>
</div>

<div class="stats-grid">
<div class="stat-card"><div class="label">Requêtes totales</div><div class="value normal">{{ STATS.total }}</div></div>
<div class="stat-card"><div class="label">Alertes</div><div class="value danger">{{ STATS.alertes }}</div></div>
<div class="stat-card"><div class="label">Domaines uniques</div><div class="value info">{{ STATS.domaines_uniques }}</div></div>
<div class="stat-card"><div class="label">IPs sources</div><div class="value warning">{{ STATS.ips_uniques }}</div></div>
</div>

<div class="chart-row">
<div class="section"><h2>📊 Alertes par type</h2><canvas id="chartAlertes" height="200"></canvas></div>
<div class="section"><h2>🏆 Top 10 domaines</h2><canvas id="chartDomaines" height="200"></canvas></div>
</div>

<div class="section">
<h2>🚨 Dernières alertes</h2>
<table><thead><tr><th>Heure</th><th>IP</th><th>Domaine</th><th>Type</th><th>Détails</th></tr></thead>
<tbody id="alertesBody"></tbody></table>
</div>

<div class="section">
<h2>📋 Dernières requêtes</h2>
<table><thead><tr><th>Heure</th><th>IP</th><th>Domaine</th><th>Type</th><th>Alerte</th></tr></thead>
<tbody id="requetesBody"></tbody></table>
</div>

<div class="footer">
HawkEye v2 — Projet Cybersécurité Réseau — <a href="https://github.com/GhostStx/HawkeyeSee" style="color:var(--accent)">GitHub</a>
</div>

<script>
const ALERTES = {{ ALERTES_JSON }};
const REQUETES = {{ REQUETES_JSON }};
const STATS_ALERTES = {{ STATS_ALERTES_JSON }};
const TOP_DOMAINES = {{ TOP_DOMAINES_JSON }};

// Tableau des alertes
const alertesBody = document.getElementById('alertesBody');
if (ALERTES.length === 0) {
    alertesBody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">✅ Aucune alerte</td></tr>';
} else {
    alertesBody.innerHTML = ALERTES.slice(0, 50).map(r => {
        const badge = {'BLACKLIST':'badge-blacklist','DGA':'badge-dga','DGA_RAFALE':'badge-dga','TUNNEL_DNS':'badge-tunnel'}[r.alerte_type]||'badge-normal';
        const label = {'BLACKLIST':'🚨 Malveillant','DGA':'⚠️ DGA','DGA_RAFALE':'📡 Rafale','TUNNEL_DNS':'🔓 Tunnel'}[r.alerte_type]||r.alerte_type;
        return `<tr><td style="color:var(--text-dim)">${r.timestamp||'—'}</td><td style="color:var(--accent)">${r.ip_source}</td><td>${r.domaine}</td><td><span class="badge ${badge}">${label}</span></td><td style="color:var(--text-dim);font-size:11px">${r.alerte||''}</td></tr>`;
    }).join('');
}

// Tableau des requêtes
const requetesBody = document.getElementById('requetesBody');
requetesBody.innerHTML = REQUETES.slice(0, 100).map(r => {
    const badge = r.alerte_type ? {'BLACKLIST':'badge-blacklist','DGA':'badge-dga','DGA_RAFALE':'badge-dga','TUNNEL_DNS':'badge-tunnel'}[r.alerte_type]||'badge-normal' : 'badge-normal';
    const label = r.alerte_type||'✓ OK';
    return `<tr><td style="color:var(--text-dim)">${r.timestamp||'—'}</td><td style="color:var(--accent)">${r.ip_source}</td><td>${r.domaine}</td><td>${r.type_query}</td><td><span class="badge ${badge}">${label}</span></td></tr>`;
}).join('');

// Graphique alertes par type
new Chart(document.getElementById('chartAlertes'), {
    type: 'doughnut',
    data: {
        labels: Object.keys(STATS_ALERTES),
        datasets: [{data: Object.values(STATS_ALERTES),backgroundColor:['#f85149','#d29922','#39d2c0','#58a6ff']}]
    },
    options: {plugins:{legend:{labels:{color:'#8b949e'}}}}
});

// Graphique top domaines
new Chart(document.getElementById('chartDomaines'), {
    type: 'bar',
    data: {
        labels: TOP_DOMAINES.map(d => d.domaine),
        datasets: [{label:'Requêtes',data:TOP_DOMAINES.map(d=>d.count),backgroundColor:'rgba(88,166,255,0.5)',borderColor:'#58a6ff',borderWidth:1}]
    },
    options: {
        indexAxis:'y',responsive:true,
        plugins:{legend:{display:false}},
        scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},y:{ticks:{color:'#8b949e'},grid:{display:false}}}
    }
});
</script>
</body>
</html>
"""


def generer_rapport(db_path: str = "hawkeye.db", output: str = "rapport.html") -> str:
    """Génère un rapport HTML à partir de la base de données.

    Args:
        db_path: Chemin vers la base SQLite
        output: Chemin de sortie du fichier HTML

    Returns:
        Le chemin absolu du fichier généré
    """
    import sqlite3

    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row

    # Statistiques
    s = db_stats(conn)

    # Dernières alertes
    alertes = conn.execute(
        "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
        "FROM requetes WHERE alerte IS NOT NULL ORDER BY id DESC LIMIT 100"
    ).fetchall()

    # Dernières requêtes
    requetes = conn.execute(
        "SELECT timestamp, ip_source, domaine, type_query, alerte, alerte_type "
        "FROM requetes ORDER BY id DESC LIMIT 200"
    ).fetchall()

    conn.close()

    # Mise en forme des données
    alertes_list = [
        {
            "timestamp": r["timestamp"][:19] if r["timestamp"] else "",
            "ip_source": r["ip_source"],
            "domaine": r["domaine"],
            "type_query": r["type_query"],
            "alerte": (r["alerte"] or "")[:80],
            "alerte_type": r["alerte_type"],
        }
        for r in alertes
    ]

    requetes_list = [
        {
            "timestamp": r["timestamp"][:19] if r["timestamp"] else "",
            "ip_source": r["ip_source"],
            "domaine": r["domaine"],
            "type_query": r["type_query"],
            "alerte_type": r["alerte_type"],
        }
        for r in requetes
    ]

    # Rendu du template
    html = (
        RAPPORT_TEMPLATE
        .replace("{{ DATE }}", datetime.now().strftime("%d/%m/%Y à %H:%M"))
        .replace("{{ DB_NAME }}", Path(db_path).name)
        .replace("{{ STATS }}", f'{{"total":{s["total"]},"alertes":{s["alertes"]},"domaines_uniques":{s["domaines_uniques"]},"ips_uniques":{s["ips_uniques"]}}}')
        .replace("{{ ALERTES_JSON }}", json.dumps(alertes_list, ensure_ascii=False))
        .replace("{{ REQUETES_JSON }}", json.dumps(requetes_list, ensure_ascii=False))
        .replace("{{ STATS_ALERTES_JSON }}", json.dumps(s.get("stats_alertes", {}), ensure_ascii=False))
        .replace("{{ TOP_DOMAINES_JSON }}", json.dumps(s.get("top_domaines", []), ensure_ascii=False))
    )

    # Écriture
    output_path = Path(output)
    output_path.write_text(html, encoding="utf-8")
    print(f"[✓] Rapport généré : {output_path.resolve()}")
    print(f"    {s['total']} requêtes | {s['alertes']} alertes | {len(alertes_list)} alertes affichées")
    return str(output_path.resolve())
