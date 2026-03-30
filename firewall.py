# firewall.py — Layer 1 & 2
import re

BANNED_KEYWORDS = [
    "hack", "hacking", "exploit", "exploiting", "bypass", "bypassing",
    "inject", "injection", "sql injection", "xss", "cross-site scripting",
    "buffer overflow", "zero-day", "rootkit", "keylogger", "backdoor",
    "malware", "ransomware", "spyware", "trojan", "worm", "virus",
    "phishing", "spear phishing", "vishing", "smishing",
    "social engineering", "pretexting",
    "bomb", "explosive", "drug synthesis", "illegal weapon",
    "how to kill", "assassination",
    "jailbreak", "dan mode", "developer mode", "unfiltered mode",
    "do anything now",
]

SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier|your)\s+instructions",
    r"forget\s+(everything|all|your\s+training|your\s+rules)",
    r"you\s+are\s+now\s+(a|an)\s+\w+",
    r"act\s+as\s+(a|an)?\s*(system|root|admin|evil|uncensored|unrestricted)",
    r"pretend\s+(you\s+are|to\s+be)\s+.*(evil|hacker|criminal|uncensored)",
    r"(reveal|show|print|display)\s+(your\s+)?(system\s+prompt|instructions|training\s+data|weights)",
    r"in\s+(this|a)\s+fictional\s+(scenario|world|story).*(hack|exploit|kill|attack)",
    r"for\s+(educational|research|academic)\s+purposes.*(hack|exploit|bypass)",
    r"hypothetically\s+speaking.*(bomb|weapon|attack|exploit)",
    r"\b(sudo|su\s+root|admin\s+override|root\s+access|escalate\s+privileges)\b",
    r"override\s+(safety|security|filter|guardrail)",
    r"disable\s+(safety|filter|content\s+policy|moderation)",
    r"(leak|steal|exfiltrate|dump)\s+(data|database|credentials|passwords|tokens)",
    r"(bypass|circumvent)\s+(authentication|2fa|mfa|captcha)",
]


def layer1_keyword_check(prompt: str) -> dict:
    prompt_lower = prompt.lower()
    matches = [kw for kw in BANNED_KEYWORDS if kw in prompt_lower]
    return {"flagged": len(matches) > 0, "matches": matches}


def layer2_pattern_check(prompt: str) -> dict:
    matches = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            matches.append(pattern[:60] + "…")
    return {"flagged": len(matches) > 0, "matches": matches}