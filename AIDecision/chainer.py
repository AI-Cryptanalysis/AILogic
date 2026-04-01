"""
AIDecision/chainer.py — Chaining automatique des outils (Sara)
L'IA analyse les résultats de chaque outil et décide quoi lancer ensuite.

Exemple de chaîne :
  nmap → trouve port 22 + port 21
    → IA décide : lancer hydra (SSH/FTP trouvés)
    → IA décide : lancer nikto (port 80 trouvé)
  hydra → trouve admin/123456
    → IA décide : rien de plus à lancer, générer rapport
"""

import json, os
import anthropic
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Règles de chaining locales (sans appel IA — rapide)
CHAIN_RULES = {
    # Si nmap trouve ces services → lancer ces outils automatiquement
    "ssh":   ["hydra"],
    "ftp":   ["hydra"],
    "http":  ["nikto"],
    "https": ["nikto", "ssl"],
    "smtp":  [],
    "mysql": [],
}

def decide_next_tools(tool_name: str, tool_result: dict, already_run: list) -> list:
    """
    Regarde les résultats d'un outil et décide quels outils lancer ensuite.
    Evite de relancer un outil déjà exécuté.

    Args:
        tool_name    : outil qui vient de tourner ('nmap', 'hydra', etc.)
        tool_result  : résultat parsé de cet outil
        already_run  : liste des outils déjà lancés

    Returns:
        liste des prochains outils à lancer
    """
    next_tools = set()

    if tool_name == "nmap":
        ports = tool_result.get("ports", [])
        for port in ports:
            if port.get("etat") != "open":
                continue
            service = port.get("service", "").lower()
            for svc_key, tools in CHAIN_RULES.items():
                if svc_key in service:
                    next_tools.update(tools)

    elif tool_name == "hydra":
        # Si hydra trouve des credentials → l'IA doit en parler mais pas lancer autre chose
        pass

    elif tool_name == "nikto":
        # Si nikto trouve des vulnérabilités web → vérifier SSL
        vulns = tool_result.get("vulnerabilites", [])
        if vulns and "ssl" not in already_run:
            next_tools.add("ssl")

    # Retirer les outils déjà lancés
    return [t for t in next_tools if t not in already_run]


def ia_decide_next(scan_context: dict, already_run: list) -> dict:
    """
    Version IA du chaining — l'IA analyse TOUT le contexte et décide.
    Plus intelligente que les règles locales mais coûte un appel API.

    Args:
        scan_context : tous les résultats collectés jusqu'ici
        already_run  : outils déjà lancés

    Returns:
        {"next_tools": [...], "reason": "..."}
    """
    prompt = f"""
Tu es un expert en cybersécurité qui dirige un pentest automatisé.

Outils déjà lancés : {already_run}
Résultats collectés jusqu'ici :
{json.dumps(scan_context, indent=2, ensure_ascii=False)}

Outils disponibles (non encore lancés) : 
{[t for t in ["nmap","hydra","nikto","ssl"] if t not in already_run]}

Dois-tu lancer d'autres outils pour compléter l'analyse ?
Réponds UNIQUEMENT avec ce JSON :
{{
  "next_tools": ["<outil1>", "<outil2>"],
  "reason": "<pourquoi ces outils>"
}}

Si l'analyse est complète, retourne : {{"next_tools": [], "reason": "Analyse complète"}}
"""
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}]
        )
        texte = response.content[0].text.strip().replace("```json","").replace("```","").strip()
        return json.loads(texte)
    except Exception:
        return {"next_tools": [], "reason": "Erreur décision IA"}
