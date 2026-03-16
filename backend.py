import json
import urllib3
import logging
import hashlib
import time
from datetime import datetime, timezone

# ── Logging ────────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

http = urllib3.PoolManager()

# ══════════════════════════════════════════════════════════════════════════════
# ⚙️  CONFIGURATION — ONLY EDIT THIS SECTION
# ══════════════════════════════════════════════════════════════════════════════
GROQ_API_KEY  = "YOUR_GROQ_API_KEY_HERE"   # 👈 Paste your Groq key here
GROQ_MODEL    = "llama3-8b-8192"
MAX_TOKENS    = 1500
TEMPERATURE   = 0.2
# ══════════════════════════════════════════════════════════════════════════════

# ── CORS Headers ───────────────────────────────────────────────────────────────
CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Request-ID",
    "Content-Type": "application/json"
}

# ── Severity Map ───────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "CRITICAL": ["fire", "explosion", "crash", "collision", "bomb", "hijack",
                 "evacuation", "structural failure", "toxic", "hazmat"],
    "HIGH":     ["fuel leak", "engine failure", "smoke", "runway incursion",
                 "medical emergency", "bird strike"],
    "MEDIUM":   ["hydraulic", "brake failure", "lightning strike", "fod",
                 "ground vehicle", "spill"],
    "LOW":      ["delay", "minor damage", "flat tyre", "door fault"]
}


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Detect Severity
# ══════════════════════════════════════════════════════════════════════════════
def detect_severity(incident: str) -> str:
    lower = incident.lower()
    for level, keywords in SEVERITY_MAP.items():
        for kw in keywords:
            if kw in lower:
                return level
    return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Build Severity Badge
# ══════════════════════════════════════════════════════════════════════════════
def severity_emoji(severity: str) -> str:
    return {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW"
    }.get(severity, "⚪ UNKNOWN")


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Build Prompt
# ══════════════════════════════════════════════════════════════════════════════
def build_prompt(incident: str, severity: str, airport_code: str, aircraft_type: str) -> str:
    context_lines = [f"- Detected Severity      : {severity_emoji(severity)}"]
    if airport_code:
        context_lines.append(f"- Airport ICAO/IATA Code : {airport_code.upper()}")
    if aircraft_type:
        context_lines.append(f"- Aircraft Type          : {aircraft_type}")
    context_lines.append(
        f"- UTC Timestamp          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    context_block = "\n".join(context_lines)

    urgency_note = ""
    if severity == "CRITICAL":
        urgency_note = "\n⚠️  CRITICAL INCIDENT — Lead with IMMEDIATE life-safety actions. Be direct.\n"
    elif severity == "HIGH":
        urgency_note = "\nHIGH SEVERITY — Prioritise crew safety and containment first.\n"

    return f"""
You are a certified aircraft ground emergency response advisor (IATA / ICAO / ARFF trained).
{urgency_note}
INCIDENT CONTEXT:
{context_block}

INCIDENT DESCRIPTION:
{incident}

Provide a fully structured emergency response using EXACTLY this format:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 SEVERITY LEVEL: {severity_emoji(severity)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. ⚡ IMMEDIATE ACTIONS (First 60 seconds)
   - [Step-by-step numbered actions]

2. 📞 NOTIFICATIONS & ESCALATION
   - Who to call (ATC, Fire, Medical, Security, Airline Ops)
   - Communication priority order

3. 🔒 CONTAINMENT & EVACUATION
   - Crowd/aircraft/perimeter control
   - Evacuation trigger conditions

4. 🧰 EQUIPMENT & RESOURCES TO DEPLOY
   - ARFF vehicles, medical, foam, hazmat, etc.

5. ⚠️  SAFETY PRECAUTIONS
   - Crew PPE requirements
   - Fuel/electrical/environmental hazards

6. 📋 REGULATORY & DOCUMENTATION
   - ICAO / local authority notification requirements
   - Incident log, black box preservation if applicable

7. ✅ POST-INCIDENT PROCEDURES
   - Scene handover, debriefing, airfield inspection

Use clear imperative language. Prioritise human life above all.
If aircraft type or airport code was provided, tailor advice to that context.
"""


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Call Groq API
# ══════════════════════════════════════════════════════════════════════════════
def call_groq(prompt: str) -> str:
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert aircraft ground emergency response advisor certified in "
                    "ICAO, IATA, and ARFF standards. Provide precise, structured, actionable "
                    "emergency guidance to airport ground crew. Never speculate. Always prioritise "
                    "life safety above property."
                )
            },
            {"role": "user", "content": prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens":  MAX_TOKENS
    }

    response = http.request(
        "POST",
        "https://api.groq.com/openai/v1/chat/completions",
        body=json.dumps(payload),
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}"
        },
        timeout=urllib3.Timeout(connect=5.0, read=45.0)
    )

    if response.status != 200:
        logger.error(f"Groq API error {response.status}: {response.data.decode()}")
        raise Exception(f"Groq API returned status {response.status}: {response.data.decode()[:300]}")

    result = json.loads(response.data.decode())
    return result["choices"][0]["message"]["content"]


# ══════════════════════════════════════════════════════════════════════════════
# MAIN LAMBDA HANDLER
# ══════════════════════════════════════════════════════════════════════════════
def lambda_handler(event, context):
    start_time = time.time()
    request_id = getattr(context, "aws_request_id", f"local-{int(time.time())}")

    logger.info(f"[{request_id}] Lambda invoked")

    # ── CORS Preflight ─────────────────────────────────────────────────────
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    # ── Parse Body ─────────────────────────────────────────────────────────
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Invalid JSON in request body."})
        }

    incident      = body.get("incident", "").strip()
    airport_code  = body.get("airport_code", "").strip()    # e.g. "OMDB", "VIDP"
    aircraft_type = body.get("aircraft_type", "").strip()   # e.g. "Airbus A320"

    # ── Input Validation ───────────────────────────────────────────────────
    if not incident:
        return {
            "statusCode": 400,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Missing required field: 'incident'."})
        }

    if len(incident) > 2000:
        return {
            "statusCode": 400,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Incident description too long. Max 2000 characters."})
        }

    # ── Detect Severity ────────────────────────────────────────────────────
    severity = detect_severity(incident)
    logger.info(
        f"[{request_id}] Severity={severity} | "
        f"Airport={airport_code or 'N/A'} | Aircraft={aircraft_type or 'N/A'}"
    )

    # ── Build Prompt ───────────────────────────────────────────────────────
    prompt = build_prompt(incident, severity, airport_code, aircraft_type)

    # ── Call Groq ──────────────────────────────────────────────────────────
    try:
        advice = call_groq(prompt)
    except Exception as e:
        logger.error(f"[{request_id}] Groq call failed: {e}")
        return {
            "statusCode": 502,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"AI service error: {str(e)}"})
        }

    # ── Timing & Request Hash ──────────────────────────────────────────────
    duration_ms   = int((time.time() - start_time) * 1000)
    incident_hash = hashlib.sha256(incident.encode()).hexdigest()[:10]
    logger.info(f"[{request_id}] Done in {duration_ms}ms | hash={incident_hash}")

    # ── Final Response ─────────────────────────────────────────────────────
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "request_id":    request_id,
            "incident_hash": incident_hash,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "severity":      severity,
            "airport_code":  airport_code  or None,
            "aircraft_type": aircraft_type or None,
            "incident":      incident,
            "advice":        advice,
            "model_used":    GROQ_MODEL,
            "duration_ms":   duration_ms
        }, indent=2)
    }
```

---

## Learner Lab Setup — Just 3 Steps

**Step 1 — Lambda**
```
Runtime : Python 3.12
Handler : lambda_function.lambda_handler
Timeout : 60 seconds   ← change this in Configuration > General
Memory  : 256 MB