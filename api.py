"""
aspis_api.py — API Python de Aspis (agent IA + parsers)
=======================================================
Tourne sur http://localhost:8000
NestJS de Wail l'appelle via HTTP, ou Fafa directement.

Endpoints :
  POST /analyze        → pipeline complet (agent IA)
  POST /parse/nmap     → parser nmap seul
  POST /parse/hydra    → parser hydra seul
  POST /parse/nikto    → parser nikto seul
  POST /ssl            → analyse SSL
  GET  /health         → test de connexion
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os, anthropic

# ── Parsers ────────────────────────────────────────────────────
from parser.nmap_parser  import parser_nmap
from parser.hydra_parser import parser_hydra
from parser.nikto_parser import parser_nikto
from crypto.ssl_analyzer import analyser_ssl, score_ssl

app = Flask(__name__)
CORS(app)  # autorise NestJS et Fafa à appeler cette API


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Aspis's AI API is running ✅"})


# ─────────────────────────────────────────────────────────────────────────────
# PARSERS — Wail/Raouf envoient le texte brut, Aspis retourne du JSON propre
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/parse/nmap', methods=['POST'])
def parse_nmap():
    """
    Input  : { "raw": "<texte brut de nmap>" }
    Output : JSON structuré des ports/services
    """
    data = request.get_json()
    raw  = data.get('raw', '')
    if not raw:
        return jsonify({"erreur": "Champ 'raw' manquant"}), 400
    return jsonify(parser_nmap(raw))


@app.route('/parse/hydra', methods=['POST'])
def parse_hydra():
    """
    Input  : { "raw": "<texte brut de hydra>" }
    Output : JSON avec credentials trouvés
    """
    data = request.get_json()
    raw  = data.get('raw', '')
    return jsonify(parser_hydra(raw))


@app.route('/parse/nikto', methods=['POST'])
def parse_nikto():
    """
    Input  : { "raw": "<texte brut de nikto>" }
    Output : JSON avec vulnérabilités web
    """
    data = request.get_json()
    raw  = data.get('raw', '')
    return jsonify(parser_nikto(raw))


@app.route('/ssl', methods=['POST'])
def ssl_analyze():
    """
    Input  : { "target": "192.168.1.1", "port": 443 }
    Output : analyse SSL/TLS complète avec score
    """
    data   = request.get_json()
    target = data.get('target', '')
    port   = data.get('port', 443)
    if not target:
        return jsonify({"erreur": "Champ 'target' manquant"}), 400
    return jsonify(analyser_ssl(target, port))


# ─────────────────────────────────────────────────────────────────────────────
# AGENT IA — pipeline complet
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Reçoit les résultats bruts de TOUS les outils,
    les parse, puis envoie à l'IA pour générer le rapport.

    Input :
    {
      "target": "192.168.1.1",
      "nmap_raw":  "<texte brut nmap>",    (optionnel)
      "hydra_raw": "<texte brut hydra>",   (optionnel)
      "nikto_raw": "<texte brut nikto>",   (optionnel)
      "ssl": true                          (optionnel)
    }

    Output : rapport IA complet en JSON
    """
    data   = request.get_json()
    target = data.get('target', 'cible inconnue')

    # ── Étape 1 : parser tous les résultats reçus ────────────────────────────
    resultats = {}

    if data.get('nmap_raw'):
        resultats['nmap'] = parser_nmap(data['nmap_raw'])

    if data.get('hydra_raw'):
        resultats['hydra'] = parser_hydra(data['hydra_raw'])

    if data.get('nikto_raw'):
        resultats['nikto'] = parser_nikto(data['nikto_raw'])

    if data.get('ssl'):
        resultats['ssl'] = analyser_ssl(target)

    if not resultats:
        return jsonify({"erreur": "Aucun résultat fourni à analyser"}), 400

    # ── Étape 2 : envoyer à l'agent IA ──────────────────────────────────────
    rapport = _appel_ia(target, resultats)
    rapport['target']          = target
    rapport['resultats_bruts'] = resultats

    return jsonify(rapport)


def _appel_ia(target: str, resultats: dict) -> dict:
    """
    Envoie les résultats parsés à Claude et retourne le rapport structuré.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        # Mode démo sans clé API → rapport simulé
        return _rapport_demo(resultats)

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""
Tu es un expert en cybersécurité. Voici les résultats d'une analyse
de sécurité sur la cible : {target}

Résultats (JSON) :
{json.dumps(resultats, indent=2, ensure_ascii=False)}

Génère un rapport de sécurité en JSON avec EXACTEMENT ce format :
{{
  "score_global": <entier 0-100>,
  "niveau_risque": "<CRITIQUE | ÉLEVÉ | MOYEN | FAIBLE>",
  "resume": "<2-3 phrases en français>",
  "vulnerabilites": [
    {{
      "titre": "<nom>",
      "criticite": "<CRITIQUE | ÉLEVÉE | MOYENNE | FAIBLE>",
      "description": "<explication simple>",
      "recommandation": "<action concrète>"
    }}
  ],
  "points_positifs": ["<liste de ce qui est bien>"],
  "score_chiffrement": <entier 0-100>,
  "analyse_chiffrement": "<évaluation du chiffrement détecté>"
}}

Réponds UNIQUEMENT avec le JSON, sans texte avant ni après.
"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        texte = response.content[0].text.strip()
        texte = texte.replace("```json", "").replace("```", "").strip()
        return json.loads(texte)
    except Exception as e:
        return {"erreur": f"Appel IA échoué : {str(e)}", **_rapport_demo(resultats)}


def _rapport_demo(resultats: dict) -> dict:
    """
    Rapport de démonstration quand l'API IA n'est pas disponible.
    Calculé à partir des parsers — utile pour tester sans clé API.
    """
    score = 100
    vulnerabilites = []

    # Analyser les résultats nmap
    if 'nmap' in resultats:
        nmap = resultats['nmap']
        score = min(score, nmap.get('score_reseau', 100))
        for svc in nmap.get('services_dangereux', []):
            vulnerabilites.append({
                "titre":           f"Service dangereux : {svc.upper()}",
                "criticite":       "ÉLEVÉE",
                "description":     f"Le service {svc} est exposé et non chiffré",
                "recommandation":  f"Désactiver {svc} ou le remplacer par une alternative sécurisée"
            })

    # Analyser les résultats hydra
    if 'hydra' in resultats and resultats['hydra'].get('mots_de_passe_faibles'):
        score -= 40
        for cred in resultats['hydra'].get('credentials_trouves', []):
            vulnerabilites.append({
                "titre":          "Mot de passe faible détecté",
                "criticite":      "CRITIQUE",
                "description":    f"Login '{cred['login']}' avec password '{cred['password']}' trouvé sur {cred['service'].upper()}",
                "recommandation": "Changer immédiatement les mots de passe et activer l'authentification par clé"
            })

    # Analyser SSL
    if 'ssl' in resultats:
        ssl_score = resultats['ssl'].get('score_ssl', 50)
        score = min(score, ssl_score + 20)

    score = max(0, score)
    niveau = "CRITIQUE" if score < 30 else "ÉLEVÉ" if score < 50 else "MOYEN" if score < 70 else "FAIBLE"

    return {
        "score_global":       score,
        "niveau_risque":      niveau,
        "resume":             f"Analyse terminée. Score de sécurité : {score}/100. {len(vulnerabilites)} vulnérabilité(s) détectée(s).",
        "vulnerabilites":     vulnerabilites,
        "points_positifs":    ["Analyse complétée avec succès"],
        "score_chiffrement":  resultats.get('ssl', {}).get('score_ssl', 50),
        "analyse_chiffrement": resultats.get('ssl', {}).get('evaluation', {}).get('note', 'Non analysé')
    }


if __name__ == '__main__':
    print("🔐 Aspis AI API démarrée sur http://localhost:8000")
    print("📡 En attente des résultats de Wail/Raouf...")
    app.run(debug=True, port=8000)
