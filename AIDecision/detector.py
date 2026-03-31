import json
from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def detect_intent(user_input: str) -> dict:
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{
            "role": "system",
            "content": """Tu es un assistant cybersécurité.
            Analyse la demande et retourne UNIQUEMENT un JSON valide :
            {"action": "scan", "target": "IP_ou_domaine", "tool": "nmap"}
            Actions possibles : scan, whois, ping"""
        },
        {
            "role": "user",
            "content": user_input
        }]
    )
    result = response.choices[0].message.content
    return json.loads(result)