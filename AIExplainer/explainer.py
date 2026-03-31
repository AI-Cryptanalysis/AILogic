from openai import OpenAI
from .prompts import EXPLAIN_PROMPT
from .risks import assess_risks
import os, json

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def explain(parsed_json: dict) -> dict:
    # 1. Explication LLM
    prompt = EXPLAIN_PROMPT.format(scan_json=json.dumps(parsed_json, indent=2))
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    explanation = response.choices[0].message.content

    # 2. Risques identifiés
    risks = assess_risks(parsed_json)

    return {
        "explanation": explanation,
        "risks": risks
    }