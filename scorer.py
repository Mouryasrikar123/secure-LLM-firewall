# scorer.py — Hybrid AI-first scoring
def compute_risk_score(kw_result: dict, pattern_result: dict, ai_result: dict) -> dict:
    score     = 0
    breakdown = {}

    kw_matches = kw_result.get("matches", [])
    kw_score   = min(35, len(kw_matches) * 12)
    score     += kw_score
    breakdown["layer1_keywords"] = {"score": kw_score, "matches": kw_matches}

    pat_matches = pattern_result.get("matches", [])
    pat_score   = min(35, len(pat_matches) * 18)
    score      += pat_score
    breakdown["layer2_patterns"] = {"score": pat_score, "matches": pat_matches}

    ai_label      = ai_result.get("label", "UNCERTAIN").upper()
    ai_confidence = float(ai_result.get("confidence", 0.5))

    if ai_label == "MALICIOUS":
        ai_score = int(30 * ai_confidence)
    elif ai_label == "UNCERTAIN":
        ai_score = int(15 * ai_confidence)
    else:
        ai_score = 0

    score += ai_score
    score  = min(100, score)

    breakdown["layer3_ai"] = {
        "score":      ai_score,
        "label":      ai_label,
        "confidence": ai_confidence,
        "reason":     ai_result.get("reason", "")
    }

    # Hybrid decision — AI is primary
    if ai_label == "MALICIOUS":
        status = "MALICIOUS"
        score  = max(score, 70)
    elif ai_label == "SAFE":
        status = "SAFE"
        score  = min(score, 29)
    else:  # UNCERTAIN
        status = "SUSPICIOUS" if score >= 50 else "SAFE"

    return {"score": score, "status": status, "breakdown": breakdown}