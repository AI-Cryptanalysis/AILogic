"""
AIExplainer/explainer.py
=========================
Explique les résultats du scan en langage naturel.
Utilise Claude (Anthropic).
"""

import os, json
import anthropic
from dotenv import load_dotenv
from .prompts import EXPLAIN_PROMPT
from .risks import assess_risks

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def explain(parsed_json: dict) -> dict:
    """
    Input  : JSON parsé des résultats (nmap, hydra, nikto, ssl)
    Output : {"explanation": "...", "risks": [...]}
    """
    # 1. Explication LLM
    prompt = EXPLAIN_PROMPT.format(scan_json=json.dumps(parsed_json, indent=2, ensure_ascii=False))

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    explanation = response.content[0].text

    # 2. Risques identifiés (logique locale — pas de LLM nécessaire)
    risks = assess_risks(parsed_json)

    return {
        "explanation": explanation,
        "risks": risks
    }