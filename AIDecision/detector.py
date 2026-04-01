"""
AIDecision/detector.py
=======================
Détecte l'intention de l'utilisateur → action + cible + outils.
Utilise Claude (Anthropic).
"""

import json
import os
import anthropic
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def detect_intent(user_input: str) -> dict:
    """
    Input  : "scan 192.168.1.1"
    Output : {"action": "scan", "target": "192.168.1.1", "tools": ["nmap"]}

    Actions : scan, brute, web, ssl, full
    """
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=200,
        system="""Tu es un assistant cybersécurité.
Retourne UNIQUEMENT un JSON valide sans texte avant ni après :
{"action": "scan", "target": "IP_ou_domaine", "tools": ["nmap"]}

Actions possibles :
- "scan"  → nmap
- "brute" → hydra
- "web"   → nikto
- "ssl"   → ssl
- "full"  → nmap, hydra, nikto, ssl

Si la cible n'est pas mentionnée, mets "target": null.""",
        messages=[{"role": "user", "content": user_input}]
    )
    texte = response.content[0].text.strip().replace("```json","").replace("```","").strip()
    try:
        return json.loads(texte)
    except json.JSONDecodeError:
        return {"action": "scan", "target": None, "tools": ["nmap"]}