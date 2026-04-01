
AIDecision/context.py — Gestionnaire de contexte (mémoire) (Sara)
Garde en mémoire :
  1. L'historique des messages (conversation)
  2. Les résultats des scans précédents
  3. La cible courante

Permet à l'IA de répondre à :
  "explique le port 21"  → sans avoir à rescanner
  "comment corriger ça?" → en se basant sur les vulnérabilités trouvées
  "rescanne la même cible" → réutilise la dernière IP

from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class SessionContext:
    """Contexte complet d'une session utilisateur."""

    # Conversation (messages échangés)
    messages: list = field(default_factory=list)

    # Dernière cible scannée
    last_target: Optional[str] = None

    # Résultats des scans (accumulés au fil des outils)
    scan_results: dict = field(default_factory=dict)

    # Outils déjà lancés dans cette session
    tools_run: list = field(default_factory=list)

    # Timestamp du dernier scan
    last_scan_time: Optional[float] = None

    def add_message(self, role: str, content: str):
        """Ajoute un message à l'historique. Garde max 20 messages."""
        self.messages.append({"role": role, "content": content})
        if len(self.messages) > 20:
            self.messages = self.messages[-20:]

    def add_scan_result(self, tool: str, result: dict):
        """Ajoute les résultats d'un outil au contexte."""
        self.scan_results[tool] = result
        if tool not in self.tools_run:
            self.tools_run.append(tool)
        self.last_scan_time = time.time()

    def set_target(self, target: str):
        """Met à jour la cible. Si nouvelle cible → reset des résultats."""
        if target and target != self.last_target:
            self.last_target = target
            self.scan_results = {}
            self.tools_run    = []

    def get_conversation_for_api(self) -> list:
        """Retourne l'historique formaté pour l'API Anthropic."""
        return self.messages[-10:]  # 5 derniers échanges

    def has_scan_results(self) -> bool:
        return bool(self.scan_results)

    def summary(self) -> str:
        """Résumé court du contexte — injecté dans les prompts IA."""
        if not self.has_scan_results():
            return "Aucun scan effectué dans cette session."

        lines = [f"Cible analysée : {self.last_target}"]
        lines.append(f"Outils lancés : {', '.join(self.tools_run)}")

        ports = self.scan_results.get("nmap", {}).get("ports", [])
        if ports:
            open_ports = [str(p['port']) for p in ports if p.get('etat') == 'open']
            lines.append(f"Ports ouverts : {', '.join(open_ports)}")

        creds = self.scan_results.get("hydra", {}).get("credentials_trouves", [])
        if creds:
            lines.append(f"Credentials trouvés : {len(creds)} (ex: {creds[0]['login']}/{creds[0]['password']})")

        vulns = self.scan_results.get("nikto", {}).get("vulnerabilites", [])
        if vulns:
            lines.append(f"Vulnérabilités web : {len(vulns)}")

        return "\n".join(lines)


class ContextManager:
    """
    Gère les sessions de toutes les conversations actives.
    Clé = session_id (envoyé par le frontend).
    """

    def __init__(self):
        self._sessions: dict[str, SessionContext] = {}

    def get(self, session_id: str) -> SessionContext:
        """Retourne le contexte de la session, le crée si inexistant."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext()
        return self._sessions[session_id]

    def reset(self, session_id: str):
        """Réinitialise une session (nouveau scan)."""
        self._sessions[session_id] = SessionContext()

    def cleanup(self, max_age_seconds: int = 3600):
        """Supprime les sessions inactives depuis plus d'1h."""
        now = time.time()
        to_delete = [
            sid for sid, ctx in self._sessions.items()
            if ctx.last_scan_time and (now - ctx.last_scan_time) > max_age_seconds
        ]
        for sid in to_delete:
            del self._sessions[sid]

# Instance globale — importée par api.py
context_manager = ContextManager()
