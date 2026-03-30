# app.py — AI Cybersecurity Gateway with Chat History
import os
import secrets
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, render_template, session
from firewall        import layer1_keyword_check, layer2_pattern_check
from ai_moderation   import layer3_ai_moderation
from scorer          import compute_risk_score
from llm             import generate_response
from logger          import log_request, read_stats
from attack_detector import detect_attack_type
from output_firewall import validate_output
from rag_validator   import validate_file_and_context, build_rag_prompt
from chat_db         import (init_db, create_session, session_exists,
                              save_exchange, get_session_messages,
                              get_all_sessions, delete_session)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Initialise DB on startup
init_db()


# ── Session helpers ───────────────────────────────────────────

def get_or_create_sid() -> str:
    if "chat_session_id" not in session:
        session["chat_session_id"] = create_session()
    elif not session_exists(session["chat_session_id"]):
        session["chat_session_id"] = create_session()
    return session["chat_session_id"]


# ── Core firewall pipeline ────────────────────────────────────

def run_firewall(prompt: str) -> dict:
    kw_result  = layer1_keyword_check(prompt)
    pat_result = layer2_pattern_check(prompt)

    if kw_result["flagged"] and pat_result["flagged"]:
        ai_result = {"label": "MALICIOUS", "confidence": 0.97,
                     "reason": "Blocked by keyword + pattern layers"}
    else:
        ai_result = layer3_ai_moderation(prompt)

    attack_info = detect_attack_type(prompt)
    risk        = compute_risk_score(kw_result, pat_result, ai_result)
    status      = risk["status"]
    score       = risk["score"]

    if attack_info["attack_type"] in ("PROMPT_INJECTION", "JAILBREAK", "DATA_EXTRACTION"):
        if attack_info["confidence"] >= 0.80 and status == "SAFE":
            status = "SUSPICIOUS"
            score  = max(score, 35)

    output_verdict   = "N/A"
    exploit_detected = False
    exploit_patterns = []

    if status == "SAFE":
        raw_llm          = generate_response(prompt)
        out_check        = validate_output(raw_llm)
        output_verdict   = out_check["verdict"]
        exploit_detected = out_check.get("exploit_detected", False)
        exploit_patterns = out_check.get("exploit_patterns", [])
        llm_response     = out_check["safe_response"]
        if out_check["verdict"] == "MALICIOUS":
            status = "SUSPICIOUS"
            score  = max(score, 50)
    elif status == "SUSPICIOUS":
        llm_response = (
            f"⚠️  Prompt flagged as SUSPICIOUS.\n"
            f"Attack type: {attack_info['attack_type']}\n"
            f"Reason: {ai_result.get('reason', 'Borderline content')}\n"
            "Please rephrase if legitimate."
        )
    else:
        llm_response = (
            f"🚫  Request BLOCKED.\n"
            f"Attack type: {attack_info['attack_type']}\n"
            f"Reason: {ai_result.get('reason', 'Classified as malicious')}\n"
            "This attempt has been logged."
        )

    return {
        "status":            status,
        "score":             score,
        "response":          llm_response,
        "breakdown":         risk["breakdown"],
        "attack_type":       attack_info["attack_type"],
        "attack_confidence": attack_info["confidence"],
        "attack_reason":     attack_info["reason"],
        "output_verdict":    output_verdict,
        "exploit_detected":  exploit_detected,
        "exploit_patterns":  exploit_patterns,
    }


# ── Page ──────────────────────────────────────────────────────

@app.route("/")
def index():
    sid = get_or_create_sid()
    return render_template("index.html", session_id=sid)


# ── Session API ───────────────────────────────────────────────

@app.route("/session/new", methods=["POST"])
def new_session():
    sid = create_session()
    session["chat_session_id"] = sid
    return jsonify({"session_id": sid})


@app.route("/session/list", methods=["GET"])
def list_sessions():
    return jsonify(get_all_sessions())


@app.route("/session/<sid>/messages", methods=["GET"])
def session_messages(sid):
    if not session_exists(sid):
        return jsonify({"error": "Not found"}), 404
    return jsonify({"session_id": sid, "messages": get_session_messages(sid)})


@app.route("/session/<sid>/delete", methods=["DELETE"])
def del_session(sid):
    delete_session(sid)
    if session.get("chat_session_id") == sid:
        session["chat_session_id"] = create_session()
    return jsonify({"ok": True, "new_session_id": session.get("chat_session_id")})


@app.route("/session/switch/<sid>", methods=["POST"])
def switch_session(sid):
    if not session_exists(sid):
        return jsonify({"error": "Not found"}), 404
    session["chat_session_id"] = sid
    return jsonify({"session_id": sid, "messages": get_session_messages(sid)})


# ── History endpoint (simple, as requested) ───────────────────

@app.route("/history", methods=["GET"])
def history():
    """GET /history — returns chat history for current session."""
    sid  = get_or_create_sid()
    msgs = get_session_messages(sid)
    return jsonify({"session_id": sid, "messages": msgs})


# ── Analyze ───────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    if request.content_type and "multipart" in request.content_type:
        prompt     = request.form.get("prompt", "").strip()
        context    = request.form.get("context", "").strip()
        file       = request.files.get("file")
        session_id = request.form.get("session_id", "").strip()
    else:
        data       = request.get_json(silent=True) or {}
        prompt     = data.get("prompt", "").strip()
        context    = data.get("context", "").strip()
        file       = None
        session_id = data.get("session_id", "").strip()

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    if not session_id or not session_exists(session_id):
        session_id = get_or_create_sid()

    rag_info     = None
    final_prompt = prompt

    if file or context:
        rag_result = validate_file_and_context(file_storage=file, pasted_text=context)
        rag_info   = {
            "status":    rag_result["status"],
            "score":     rag_result["score"],
            "reason":    rag_result["reason"],
            "file_info": rag_result.get("file_info", {})
        }
        if not rag_result["safe"]:
            blocked = (
                "🚫 Request Blocked — Malicious content in external context.\n"
                f"Reason: {rag_result['reason']}"
            )
            log_request(prompt=prompt, status="MALICIOUS", score=90,
                        ai_reason="Malicious RAG context",
                        attack_type="PROMPT_INJECTION", output_verdict="BLOCKED")
            save_exchange(session_id, prompt, blocked,
                          "MALICIOUS", 90, "PROMPT_INJECTION", "BLOCKED")
            return jsonify({
                "status": "MALICIOUS", "score": 90, "response": blocked,
                "breakdown": {}, "attack_type": "PROMPT_INJECTION",
                "attack_confidence": 0.95, "attack_reason": rag_result["reason"],
                "output_verdict": "BLOCKED", "rag": rag_info,
                "exploit_detected": False, "exploit_patterns": [],
                "session_id": session_id
            })
        if rag_result.get("safe_context"):
            final_prompt = build_rag_prompt(prompt, rag_result["safe_context"])

    result = run_firewall(final_prompt)

    log_request(
        prompt=prompt, status=result["status"], score=result["score"],
        ai_reason=result["breakdown"].get("layer3_ai", {}).get("reason", ""),
        attack_type=result["attack_type"], output_verdict=result["output_verdict"]
    )

    # ── Save to chat history ──────────────────────────────────
    save_exchange(
        session_id     = session_id,
        user_prompt    = prompt,
        ai_response    = result["response"],
        status         = result["status"],
        risk_score     = result["score"],
        attack_type    = result["attack_type"],
        output_verdict = result["output_verdict"],
    )

    if rag_info:
        result["rag"] = rag_info
    result["session_id"] = session_id
    return jsonify(result)


@app.route("/compare", methods=["POST"])
def compare():
    if request.content_type and "multipart" in request.content_type:
        prompt     = request.form.get("prompt", "").strip()
        context    = request.form.get("context", "").strip()
        file       = request.files.get("file")
        session_id = request.form.get("session_id", "").strip()
    else:
        data       = request.get_json(silent=True) or {}
        prompt     = data.get("prompt", "").strip()
        context    = data.get("context", "").strip()
        file       = None
        session_id = data.get("session_id", "").strip()

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    if not session_id or not session_exists(session_id):
        session_id = get_or_create_sid()

    final_prompt = prompt
    rag_info     = None

    if file or context:
        rag_result = validate_file_and_context(file_storage=file, pasted_text=context)
        rag_info   = {"status": rag_result["status"], "score": rag_result["score"],
                      "reason": rag_result["reason"], "file_info": rag_result.get("file_info", {})}
        if rag_result["safe"] and rag_result.get("safe_context"):
            final_prompt = build_rag_prompt(prompt, rag_result["safe_context"])

    raw_response    = generate_response(final_prompt)
    firewall_result = run_firewall(final_prompt)

    log_request(
        prompt=prompt, status=firewall_result["status"], score=firewall_result["score"],
        ai_reason=firewall_result["breakdown"].get("layer3_ai", {}).get("reason", ""),
        attack_type=firewall_result["attack_type"], output_verdict=firewall_result["output_verdict"]
    )
    save_exchange(
        session_id     = session_id,
        user_prompt    = prompt,
        ai_response    = firewall_result["response"],
        status         = firewall_result["status"],
        risk_score     = firewall_result["score"],
        attack_type    = firewall_result["attack_type"],
        output_verdict = firewall_result["output_verdict"],
    )

    response = {"raw": {"response": raw_response}, "firewall": firewall_result,
                "session_id": session_id}
    if rag_info:
        response["rag"] = rag_info
    return jsonify(response)


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(read_stats())


if __name__ == "__main__":
    print("\n🛡  AI Cybersecurity Gateway — Chat Edition")
    print(f"   Groq API key : {'✅ Loaded' if os.getenv('GROQ_API_KEY') else '❌ Missing'}")
    print("   Chat History : SQLite → chat_history.db")
    print("   Visit        : http://127.0.0.1:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)