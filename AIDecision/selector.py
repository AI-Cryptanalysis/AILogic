def select_tool(intent: dict) -> dict:
    tool_map = {
        "scan": "nmap",
        "whois": "whois",
        "ping": "ping"
    }
    tool = tool_map.get(intent.get("action"), "unknown")
    
    return {
        "tool": tool,
        "target": intent.get("target"),
        "action": intent.get("action")
    }