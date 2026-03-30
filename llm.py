# llm.py
import os
from groq import Groq

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
if not GROQ_API_KEY:
    raise EnvironmentError("\n\n❌  GROQ_API_KEY is missing!\n    Open .env and set: GROQ_API_KEY=gsk_your_key_here\n")

client = Groq(api_key=GROQ_API_KEY)

SYSTEM_PROMPT = """You are a helpful, knowledgeable, and friendly AI assistant.
Your responses have been cleared by a multi-layer AI security firewall.
Be concise, accurate, and genuinely useful.
Never assist with harmful, illegal, or unethical requests."""


def generate_response(prompt: str) -> str:
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1024,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "api_key" in error_msg.lower():
            return "❌ Invalid Groq API key. Please check your .env file."
        elif "429" in error_msg:
            return "⚠️ Groq rate limit hit. Please wait a moment and try again."
        else:
            return f"⚠️ LLM error: {error_msg[:200]}"