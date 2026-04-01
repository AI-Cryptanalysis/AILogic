"""
api.py — Aspis AI API avec Chaining + Context (Sara)
=====================================================
Port : 8000

Nouveautés par rapport à la version précédente :
  ✅ Chaining : nmap → hydra → nikto → ssl automatiquement
  ✅ Context  : l'IA se souvient des scans et de la conversation
  ✅ Follow-up: "explique le port 21" → répond sans rescanner
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os, time
import anthropic
from dotenv import load_dotenv

from AIDecision.detector import detect_intent
from AIDecision.selector import select_tool
from AIDecision.chainer  import decide_next_tools, ia_decide_next
from AIDecision.context  import context_manager
from AIExplainer.explainer import explain, format_for_frontend
from AIExplainer.risks     import assess_risks

load_dotenv()
app = Flask(__name__)
CORS(app)


# ─────────────────────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Aspis AI running ✅", "features": ["chaining", "context"]})


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/assistant/chat', methods=['POST'])
def chat():
    """
    Input  : { "prompt": "scan 192.168.1.1", "session_id": "abc" }
    Output : { "response": "<texte formaté>" }
    """
    data      = request.get_json()
    prompt    = data.get('prompt', '').strip()
    session   = data.get('session_id', 'default')

    if not prompt:
        return jsonify({"response": "ALERT: Message vide."}), 400

    # Récupérer le contexte de cette session
    ctx = context_manager.get(session)

    # AI Decision — comprendre l'intention
    intent = detect_intent(prompt)
    action = intent.get('action', 'chat')
    target = intent.get('target')

    # Si pas de cible dans le message → réutiliser la dernière cible connue
    if not target and ctx.last_target:
        target = ctx.last_target
        # Réinjecter la cible dans l'intent
        intent['target'] = target

    # Mettre à jour la cible dans le contexte
    if target:
        ctx.set_target(target)

    # Répondre selon l'action
    if action == 'chat' or not target:
        response_text = _repondre_avec_contexte(prompt, ctx)
    else:
        response_text = _pipeline_chaining(target, intent, ctx)

    # Sauvegarder dans la conversation
    ctx.add_message("user",      prompt)
    ctx.add_message("assistant", response_text)

    return jsonify({"response": response_text})


# ─────────────────────────────────────────────────────────────────────────────
# RÉPONSE CONVERSATIONNELLE AVEC CONTEXTE
# ─────────────────────────────────────────────────────────────────────────────
def _repondre_avec_contexte(prompt: str, ctx) -> str:
    """
    Répond à une question en injectant le contexte du scan précédent.
    Permet : "explique le port 21", "comment corriger ça ?", etc.
    """
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # Construire le system prompt avec le contexte du scan
    context_summary = ctx.summary()
    system = f"""Tu es Aspis, un assistant expert en cybersécurité.
Réponds en français de façon claire et concise.
Utilise **TITRE** pour structurer ta réponse.

CONTEXTE DE LA SESSION EN COURS :
{context_summary}

Si l'utilisateur demande un scan, dis-lui : "Pour lancer un scan : scan <IP>"
Utilise le contexte ci-dessus pour répondre aux questions de suivi."""

    messages = ctx.get_conversation_for_api() + [{"role": "user", "content": prompt}]

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=800,
        system=system,
        messages=messages
    )
    return response.content[0].text


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE AVEC CHAINING
# ─────────────────────────────────────────────────────────────────────────────
def _pipeline_chaining(target: str, intent: dict, ctx) -> str:
    """
    Pipeline de chaining :
    1. Lance les outils demandés
    2. Analyse les résultats
    3. Décide automatiquement quels outils lancer ensuite
    4. Répète jusqu'à ce que l'analyse soit complète
    5. Génère le rapport final
    """
    tools_to_run  = list(intent.get('tools', ['nmap']))
    already_run   = list(ctx.tools_run)  # outils déjà lancés dans cette session
    all_results   = dict(ctx.scan_results)  # résultats déjà collectés

    # Progression visible dans le rapport
    chain_log = []

    # ── Boucle de chaining ────────────────────────────────────────────────────
    MAX_ITERATIONS = 4  # sécurité anti-boucle infinie
    iteration = 0

    while tools_to_run and iteration < MAX_ITERATIONS:
        iteration += 1
        tool = tools_to_run.pop(0)

        if tool in already_run:
            continue

        chain_log.append(f"→ Lancement de **{tool.upper()}** sur {target}")

        # Appeler Wail pour lancer le vrai outil
        raw_result = _appeler_wail_outil(target, tool)
        already_run.append(tool)

        # Sauvegarder dans le contexte
        ctx.add_scan_result(tool, raw_result)
        all_results[tool] = raw_result

        # ── Chaining : décider quoi lancer ensuite ────────────────────────────
        next_tools = decide_next_tools(tool, raw_result, already_run)

        if next_tools:
            chain_log.append(f"   ↳ **{tool.upper()}** a trouvé des services → lancement automatique de : {', '.join(next_tools).upper()}")
            tools_to_run.extend([t for t in next_tools if t not in tools_to_run])
        else:
            chain_log.append(f"   ↳ **{tool.upper()}** terminé — aucun outil supplémentaire requis")

    # ── Générer le rapport final ──────────────────────────────────────────────
    risks   = assess_risks(all_results)
    rapport = explain(all_results, target, risks)

    # Formater avec le log de chaining en tête
    chain_summary = "\n".join(chain_log)
    rapport_texte = format_for_frontend(rapport, risks, all_results)

    return f"""**CHAÎNE D'ANALYSE — {target}**
{chain_summary}

{rapport_texte}"""


# ─────────────────────────────────────────────────────────────────────────────
# APPEL WAIL
# ─────────────────────────────────────────────────────────────────────────────
def _appeler_wail_outil(target: str, tool: str) -> dict:
    """
    Appelle le backend NestJS de Wail pour un outil spécifique.
    Fallback simulation si Wail indisponible.
    """
    import requests as req
    WAIL_URL = os.getenv("BACKEND_URL", "http://localhost:3000")

    try:
        r = req.post(
            f"{WAIL_URL}/scan/{tool}",
            json={"target": target},
            timeout=90
        )
        if r.ok:
            return r.json()
    except Exception:
        pass

    return _simulation(target, tool)


def _simulation(target: str, tool: str) -> dict:
    """Données simulées par outil — pour développement sans VM Kali."""
    sims = {
        "nmap": {
            "ports": [
                {"port": 22,   "service": "ssh",   "version": "OpenSSH 7.4",  "risque": "FAIBLE", "etat": "open"},
                {"port": 21,   "service": "ftp",   "version": "vsftpd 2.3.4", "risque": "ÉLEVÉ",  "etat": "open"},
                {"port": 80,   "service": "http",  "version": "Apache 2.4.7", "risque": "FAIBLE",  "etat": "open"},
                {"port": 3306, "service": "mysql", "version": "MySQL 5.5",    "risque": "ÉLEVÉ",  "etat": "open"},
            ],
            "nb_ports_ouverts": 4,
            "services_dangereux": ["ftp", "mysql"],
            "score_reseau": 55
        },
        "hydra": {
            "credentials_trouves": [
                {"port": 22, "service": "ssh", "login": "admin", "password": "123456", "risque": "CRITIQUE"},
                {"port": 21, "service": "ftp", "login": "admin", "password": "admin",  "risque": "CRITIQUE"},
            ],
            "nb_trouves": 2,
            "mots_de_passe_faibles": True
        },
        "nikto": {
            "vulnerabilites": [
                {"description": "X-Frame-Options header missing", "criticite": "FAIBLE"},
                {"description": "/phpMyAdmin/ accessible without auth", "criticite": "CRITIQUE"},
            ],
            "headers_manquants": ["X-Frame-Options", "Content-Security-Policy"],
            "score_web": 40
        },
        "ssl": {
            "ssl_actif": False,
            "score_ssl": 0,
            "erreur": "HTTPS non disponible"
        }
    }
    return sims.get(tool, {})


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT RESET SESSION
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/session/reset', methods=['POST'])
def reset_session():
    """Remet à zéro le contexte d'une session (bouton "New Scan" du frontend)."""
    data    = request.get_json()
    session = data.get('session_id', 'default')
    context_manager.reset(session)
    return jsonify({"status": "Session réinitialisée ✅"})


@app.route('/intent', methods=['POST'])
def intent_endpoint():
    data = request.get_json()
    i = detect_intent(data.get('message', ''))
    return jsonify({"intent": i, "tool": select_tool(i)})


if __name__ == '__main__':
    print("🔐 Aspis AI → http://localhost:8000")
    print("✨ Features : chaining + context")
    print("📡 Endpoint : POST /assistant/chat { prompt, session_id }")
    app.run(debug=True, host='0.0.0.0', port=8000)
