"""
api.py — Aspis AI API (Sara)
=============================
Tourne sur http://localhost:8000

Endpoints :
    GET  /health         → test de connexion
    POST /parse/nmap     → parser nmap seul
    POST /parse/hydra    → parser hydra seul
    POST /parse/nikto    → parser nikto seul
    POST /ssl            → analyse SSL/TLS
    POST /intent         → AI Decision (detect_intent)
    POST /analyze        → pipeline complet (parse → explain)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os

# ── Parsers  ────────────────────────────────────────────────────
from parser.nmap_parser  import parser_nmap
from parser.hydra_parser import parser_hydra
from parser.nikto_parser import parser_nikto
from crypto.ssl_analyzer import analyser_ssl

# ── AIDecision  ─────────────────────────────────────────────────────────
from AIDecision.detector import detect_intent
from AIDecision.selector import select_tool

# ── AIExplainer  ────────────────────────────────────────────────────────
from AIExplainer.explainer import explain

app = Flask(__name__)
CORS(app)


# ─────────────────────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Aspis AI API is running ✅"})


# ─────────────────────────────────────────────────────────────────────────────
# AI DECISION
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/intent', methods=['POST'])
def intent():
    """
    Input  : { "message": "scan 192.168.1.1" }
    Output : { "action": "scan", "target": "192.168.1.1", "tools": ["nmap"] }

    Utilisé par Fafa pour savoir quoi lancer avant d'appeler Wail.
    """
    data    = request.get_json()
    message = data.get('message', '')
    if not message:
        return jsonify({"erreur": "Champ 'message' manquant"}), 400

    intent_result = detect_intent(message)
    tool_result   = select_tool(intent_result)

    return jsonify({
        "intent": intent_result,
        "tool":   tool_result
    })


# ─────────────────────────────────────────────────────────────────────────────
# PARSERS
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/parse/nmap', methods=['POST'])
def parse_nmap():
    data = request.get_json()
    raw  = data.get('raw', '')
    if not raw:
        return jsonify({"erreur": "Champ 'raw' manquant"}), 400
    return jsonify(parser_nmap(raw))


@app.route('/parse/hydra', methods=['POST'])
def parse_hydra():
    data = request.get_json()
    return jsonify(parser_hydra(data.get('raw', '')))


@app.route('/parse/nikto', methods=['POST'])
def parse_nikto():
    data = request.get_json()
    return jsonify(parser_nikto(data.get('raw', '')))


@app.route('/ssl', methods=['POST'])
def ssl_analyze():
    data   = request.get_json()
    target = data.get('target', '')
    port   = data.get('port', 443)
    if not target:
        return jsonify({"erreur": "Champ 'target' manquant"}), 400
    return jsonify(analyser_ssl(target, port))


# ─────────────────────────────────────────────────────────────────────────────
# AI EXPLAINER — pipeline complet
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Reçoit les résultats bruts de Wail, les parse, puis les explique via l'IA.

    Input :
    {
        "target":    "192.168.1.1",
        "nmap_raw":  "...",   (optionnel)
        "hydra_raw": "...",   (optionnel)
        "nikto_raw": "...",   (optionnel)
        "ssl":       true     (optionnel)
    }

    Output : rapport complet avec explanation + risks + scores
    """
    data   = request.get_json()
    target = data.get('target', 'cible inconnue')

    # ── Étape 1 : parser les résultats bruts ──────────────────────────────────
    parsed = {}
    if data.get('nmap_raw'):
        parsed['nmap']  = parser_nmap(data['nmap_raw'])
    if data.get('hydra_raw'):
        parsed['hydra'] = parser_hydra(data['hydra_raw'])
    if data.get('nikto_raw'):
        parsed['nikto'] = parser_nikto(data['nikto_raw'])
    if data.get('ssl'):
        parsed['ssl']   = analyser_ssl(target)

    if not parsed:
        return jsonify({"erreur": "Aucun résultat fourni"}), 400

    # ── Étape 2 : AI Explainer ────────────────────────────────────────────────
    rapport = explain(parsed)

    return jsonify({
        "target":          target,
        "parsed_results":  parsed,
        "explanation":     rapport['explanation'],
        "risks":           rapport['risks'],
    })


if __name__ == '__main__':
    print("🔐 Aspis AI API démarrée sur http://localhost:8000")
    print("📡 En attente des résultats de Wail/Raouf...")
    app.run(debug=True, port=8000)