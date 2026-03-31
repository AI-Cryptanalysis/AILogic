RISKY_PORTS = {
    21:  {"level": "HIGH",   "msg": "FTP ouvert — données en clair, désactiver si possible"},
    22:  {"level": "MEDIUM", "msg": "SSH ouvert — ok si bien configuré, désactiver root login"},
    23:  {"level": "HIGH",   "msg": "Telnet — protocole non chiffré, à bannir absolument"},
    80:  {"level": "LOW",    "msg": "HTTP — pas de chiffrement, rediriger vers HTTPS"},
    443: {"level": "OK",     "msg": "HTTPS — ok si certificat valide"},
    3389:{"level": "HIGH",   "msg": "RDP — cible fréquente des ransomwares, restreindre l'accès"},
    8080:{"level": "MEDIUM", "msg": "HTTP alternatif — souvent non sécurisé"},
}

def assess_risks(parsed_json: dict) -> list:
    risks = []
    for port_info in parsed_json.get("ports", []):
        port = port_info.get("port")
        if port in RISKY_PORTS:
            risks.append({
                "port": port,
                "service": port_info.get("service"),
                "level": RISKY_PORTS[port]["level"],
                "warning": RISKY_PORTS[port]["msg"]
            })
    return risks