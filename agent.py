"""
ai/agent.py - L'agent IA (Sara + Fafa)
=========================================
Responsabilités :
  1. AI Logic   → décider quelle action lancer selon la demande
  2. AI Explain → transformer les résultats JSON en rapport humain
"""

import os
import json
import anthropic

# ─── Import des parsers (Sara + Raouf) ────────────────────────────────────────
from parser.nmap_parser    import parser_nmap
from parser.hydra_parser   import parser_hydra
from parser.nikto_parser   import parser_nikto

# ─── Import des outils backend (Wail) ─────────────────────────────────────────
# Ces fonctions seront codées par Wail — elles retournent du texte brut
from pentest.nmap_scanner  import run_nmap
from pentest.hydra_attack  import run_hydra
from pentest.nikto_scanner import run_nikto

# ─── Import analyse chiffrement (Sara — ton ancien projet) ────────────────────
from crypto.ssl_analyzer   import analyser_ssl


class CyberAgent:
    """
    Cerveau du système.
    Reçoit une cible + liste d'actions → retourne un rapport complet.
    """

    def __init__(self):
        # Clé API Anthropic — à mettre dans une variable d'environnement
        self.client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", "")
        )

    # ──────────────────────────────────────────────────────────────────────────
    # ÉTAPE 1 : AI LOGIC — décider quoi lancer
    # ──────────────────────────────────────────
    def decider_actions(self, user_input: str) -> list:
        """
        Analyse l'intention de l'utilisateur et retourne
        la liste des outils à lancer.

        Exemples :
          "scan 192.168.1.1"          → ['nmap']
          "test SSH passwords"        → ['nmap', 'hydra']
          "full security check"       → ['nmap', 'hydra', 'nikto', 'ssl']
          "check website"             → ['nikto', 'ssl']
        """
        prompt = f"""
Tu es un assistant cybersécurité. L'utilisateur demande :
"{user_input}"

Réponds UNIQUEMENT avec un JSON de la forme :
{{"actions": ["nmap", "hydra", "nikto", "ssl"]}}

Actions disponibles :
- "nmap"   → scanner les ports et services ouverts
- "hydra"  → tester des mots de passe faibles (brute-force SSH/FTP)
- "nikto"  → scanner les vulnérabilités web (HTTP)
- "ssl"    → analyser le chiffrement SSL/TLS

Choisis UNIQUEMENT les actions pertinentes. Ne mets pas d'explication.
"""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}]
        )
        texte = response.content[0].text.strip()
        try:
            return json.loads(texte).get("actions", ["nmap"])
        except json.JSONDecodeError:
            return ["nmap"]  # fallback

    # ──────────────────────────────────────────────────────────────────────────
    # ÉTAPE 2 : EXÉCUTER LES OUTILS (via Wail)
    # ──────────────────────────────────────────
    def executer_outils(self, target: str, actions: list) -> dict:
        """
        Lance les outils demandés et retourne les résultats parsés.
        Chaque résultat est un dict JSON propre (travail du parser).
        """
        resultats = {}

        if 'nmap' in actions:
            raw = run_nmap(target)               # Wail
            resultats['nmap'] = parser_nmap(raw) # Sara + Raouf

        if 'hydra' in actions:
            raw = run_hydra(target)
            resultats['hydra'] = parser_hydra(raw)

        if 'nikto' in actions:
            raw = run_nikto(target)
            resultats['nikto'] = parser_nikto(raw)

        if 'ssl' in actions:
            # Directement Python — pas besoin de Wail pour SSL
            resultats['ssl'] = analyser_ssl(target)

        return resultats

    # ──────────────────────────────────────────────────────────────────────────
    # ÉTAPE 3 : AI EXPLANATION — générer le rapport en langage humain
    # ──────────────────────────────────────────────────────────────────────────
    def expliquer_resultats(self, target: str, resultats: dict) -> dict:
        """
        Envoie tous les résultats JSON à l'IA et reçoit :
        - Un score de sécurité global (0-100)
        - Une liste de vulnérabilités avec niveau de criticité
        - Des recommandations concrètes
        - Un résumé en langage naturel (français)
        """
        prompt = f"""
Tu es un expert en cybersécurité. Voici les résultats d'une analyse
de sécurité sur la cible : {target}

Résultats bruts (JSON) :
{json.dumps(resultats, indent=2, ensure_ascii=False)}

Génère un rapport de sécurité structuré en JSON avec EXACTEMENT ce format :
{{
  "score_global": <entier 0-100>,
  "niveau_risque": "<CRITIQUE | ÉLEVÉ | MOYEN | FAIBLE>",
  "resume": "<2-3 phrases résumant la situation en français>",
  "vulnerabilites": [
    {{
      "titre": "<nom de la vulnérabilité>",
      "criticite": "<CRITIQUE | ÉLEVÉE | MOYENNE | FAIBLE>",
      "description": "<explication simple>",
      "recommandation": "<que faire concrètement>"
    }}
  ],
  "points_positifs": ["<ce qui est bien sécurisé>"],
  "score_chiffrement": <entier 0-100>,
  "analyse_chiffrement": "<évaluation du chiffrement SSL/TLS utilisé>"
}}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        texte = response.content[0].text.strip()
        # Nettoyer les balises markdown si présentes
        texte = texte.replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(texte)
        except json.JSONDecodeError:
            return {
                "score_global": 0,
                "niveau_risque": "INCONNU",
                "resume": texte,
                "vulnerabilites": [],
                "points_positifs": [],
                "score_chiffrement": 0,
                "analyse_chiffrement": ""
            }

    # ──────────────────────────────────────────────────────────────────────────
    # MÉTHODE PRINCIPALE : tout en un
    # ──────────────────────────────────────────────────────────────────────────
    def analyser(self, target: str, actions: list = None) -> dict:
        """
        Pipeline complet :
        target + actions → résultats outils → rapport IA

        Appelé par app.py
        """
        # Si actions non spécifiées → l'IA décide
        if not actions:
            actions = self.decider_actions(f"full security check on {target}")

        # Lancer les outils et parser les résultats
        resultats_bruts = self.executer_outils(target, actions)

        # Générer le rapport IA
        rapport = self.expliquer_resultats(target, resultats_bruts)

        # Ajouter les métadonnées
        rapport['target']          = target
        rapport['actions_lancees'] = actions
        rapport['resultats_bruts'] = resultats_bruts  # pour le frontend

        return rapport