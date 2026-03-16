import json
import urllib3
import logging
import hashlib
import time
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)
http = urllib3.PoolManager()

GROQ_API_KEY = "YOUR_GROQ_API_KEY_HERE"
GROQ_MODEL   = "llama-3.3-70b-versatile"   # Fix 1: updated model (llama3-8b-8192 deprecated)
MAX_TOKENS   = 1500                        # Fix 4: prevents Groq truncation
TEMPERATURE  = 0.2

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Request-ID",
    "Content-Type": "application/json"
}

THRESHOLDS = {
    "engine_temp_celsius":    {"warning": 750,  "critical": 900},
    "fuel_pressure_psi":      {"warning": 30,   "critical": 15},
    "hydraulic_pressure_psi": {"warning": 1500, "critical": 800},
    "brake_temp_celsius":     {"warning": 400,  "critical": 600},
    "vibration_level":        {"warning": 3,    "critical": 7},
}

DETECTION_RULES = [
    {"id":"ENG_FIRE","name":"Engine Fire","severity":"CRITICAL","risk_weight":10,
     "conditions":lambda s:(s.get("smoke_sensor") is True and s.get("engine_temp_celsius",0)>900),
     "description":"Engine fire suspected — smoke sensor active and engine temperature critical."},
    {"id":"ENG_OVERHEAT","name":"Engine Overheat","severity":"HIGH","risk_weight":7,
     "conditions":lambda s:(s.get("engine_temp_celsius",0)>750 and not s.get("smoke_sensor")),
     "description":"Engine temperature above warning threshold — possible overheat."},
    {"id":"FUEL_LEAK","name":"Fuel Leak","severity":"CRITICAL","risk_weight":9,
     "conditions":lambda s:(s.get("fuel_leak_sensor") is True or s.get("fuel_pressure_psi",999)<15),
     "description":"Fuel leak detected — sensor active or pressure critically low."},
    {"id":"FUEL_PRESSURE_LOW","name":"Low Fuel Pressure","severity":"HIGH","risk_weight":6,
     "conditions":lambda s:(s.get("fuel_pressure_psi",999)<30 and not s.get("fuel_leak_sensor")),
     "description":"Fuel pressure below warning level — possible feed issue."},
    {"id":"RUNWAY_INCURSION","name":"Runway Incursion","severity":"CRITICAL","risk_weight":10,
     "conditions":lambda s:s.get("runway_intrusion") is True,
     "description":"Unauthorized entity detected on active runway."},
    {"id":"HYDRAULIC_FAIL","name":"Hydraulic Failure","severity":"HIGH","risk_weight":7,
     "conditions":lambda s:s.get("hydraulic_pressure_psi",9999)<800,
     "description":"Hydraulic pressure critically low — possible system failure."},
    {"id":"BRAKE_OVERHEAT","name":"Brake Overheat","severity":"HIGH","risk_weight":6,
     "conditions":lambda s:s.get("brake_temp_celsius",0)>600,
     "description":"Brake temperature critical — fire risk on ground."},
    {"id":"WILDLIFE_RISK","name":"Wildlife Strike Risk","severity":"MEDIUM","risk_weight":4,
     "conditions":lambda s:s.get("wildlife_detected") is True,
     "description":"Wildlife detected near active runway."},
    {"id":"VIBRATION_CRITICAL","name":"Structural Vibration Alert","severity":"HIGH","risk_weight":6,
     "conditions":lambda s:s.get("vibration_level",0)>=7,
     "description":"Critical vibration levels — possible structural or engine issue."},
    {"id":"SMOKE_ONLY","name":"Smoke / Fumes Detected","severity":"HIGH","risk_weight":5,
     "conditions":lambda s:(s.get("smoke_sensor") is True and s.get("engine_temp_celsius",0)<=900),
     "description":"Smoke or fumes detected — source unconfirmed."},
]

SEVERITY_RANK = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}

def compute_risk_score(matched_rules, sensor_data, aircraft_type, location):
    base = sum(r.get("risk_weight",5) for r in matched_rules)
    n = len(matched_rules)
    if n >= 3: base += 10
    elif n == 2: base += 5
    al = (aircraft_type or "").lower()
    if any(x in al for x in ["777","747","a380","a350","787"]): base += 6
    elif any(x in al for x in ["737","a320","a321","a319"]): base += 4
    else: base += 2
    ll = (location or "").lower()
    # Fix 3: extended runway identifier detection
    if any(x in ll for x in ["runway","rwy","09","18","27","36","28","14","10","16","22","04"]):
        base += 8
    elif any(x in ll for x in ["taxiway","taxi"]): base += 5
    else: base += 3
    if sensor_data.get("engine_temp_celsius",0) > 900: base += 4
    if sensor_data.get("vibration_level",0) >= 7: base += 3
    if sensor_data.get("fuel_pressure_psi",999) < 15: base += 4
    # Fix 2: normalize to prevent saturation (score was jumping to 80-100 too easily)
    score = min(int(base * 0.8), 100)
    if score >= 70: level = "EXTREME"
    elif score >= 50: level = "HIGH"
    elif score >= 30: level = "MODERATE"
    else: level = "LOW"
    # Fix 6: AI confidence score
    confidence = min(95, 50 + n * 10)
    return {"score": score, "level": level, "hazard_count": n, "ai_confidence": confidence}

def fuse_incidents(matched_rules):
    if not matched_rules: return None
    sorted_rules = sorted(matched_rules, key=lambda r: SEVERITY_RANK.get(r["severity"],0), reverse=True)
    top = sorted_rules[0]
    if len(matched_rules) == 1:
        return {"incident_id":top["id"],"incident_name":top["name"],"severity":top["severity"],
                "description":top["description"],"is_compound":False,
                "all_matched":[top["id"]],"hazard_names":[top["name"]]}
    names = [r["name"] for r in sorted_rules]
    # Fix 5: ensure compound stays CRITICAL if ANY hazard is critical
    compound_severity = "CRITICAL" if any(r["severity"]=="CRITICAL" for r in matched_rules) else top["severity"]
    return {"incident_id":"COMPOUND","incident_name":"Compound Emergency",
            "severity":compound_severity,
            "description":f"Multiple simultaneous hazards: {', '.join(names)}.",
            "is_compound":True,"all_matched":[r["id"] for r in sorted_rules],"hazard_names":names}

SEVERITY_MAP = {
    "CRITICAL":["fire","explosion","crash","collision","bomb","hijack","evacuation","structural failure","toxic","hazmat","runway intrusion"],
    "HIGH":["fuel leak","engine failure","smoke","runway incursion","medical emergency","bird strike","hydraulic"],
    "MEDIUM":["brake failure","lightning strike","fod","ground vehicle","spill","vibration","wildlife"],
}

def detect_severity_text(text):
    l = text.lower()
    for level, kws in SEVERITY_MAP.items():
        for kw in kws:
            if kw in l: return level
    return "LOW"

def detect_escalation_triggers(sensor_data: dict) -> list:
    """Fix 7: Detect pre-escalation conditions from sensor values."""
    triggers = []
    if sensor_data.get("engine_temp_celsius", 0) > 950:
        triggers.append("Engine ignition risk — temperature approaching combustion point")
    if sensor_data.get("fuel_pressure_psi", 999) < 10:
        triggers.append("Fuel system collapse risk — pressure critically near zero")
    if sensor_data.get("vibration_level", 0) >= 8:
        triggers.append("Engine structural failure risk — vibration at destructive levels")
    if sensor_data.get("hydraulic_pressure_psi", 9999) < 400:
        triggers.append("Total hydraulic failure imminent — loss of flight control surfaces")
    if sensor_data.get("brake_temp_celsius", 0) > 650:
        triggers.append("Brake fire risk — temperature exceeding material limits")
    if sensor_data.get("smoke_sensor") and sensor_data.get("fuel_leak_sensor"):
        triggers.append("Ignition + fuel combination — explosive fire risk")
    if sensor_data.get("runway_intrusion") and sensor_data.get("engine_temp_celsius", 0) > 750:
        triggers.append("Runway incursion during aircraft emergency — collision + fire compound risk")
    return triggers


def build_command_prompt(incident_desc, severity, airport_code, aircraft_type,
                         location, sensor_summary, incident_name, hazard_names,
                         is_compound, risk_score, priority, incident_history,
                         escalation_triggers=None):
    ctx = [
        f"- Detected Severity   : {severity}",
        f"- Risk Score          : {risk_score['score']}/100 ({risk_score['level']})",
        f"- AI Confidence       : {risk_score.get('ai_confidence', 70)}%",   # Fix 6
        f"- Hazard Count        : {risk_score['hazard_count']}",
    ]
    if incident_name: ctx.append(f"- Incident Type       : {incident_name}")
    if is_compound and hazard_names: ctx.append(f"- Active Hazards      : {', '.join(hazard_names)}")
    if airport_code: ctx.append(f"- Airport Code        : {airport_code.upper()}")
    if aircraft_type: ctx.append(f"- Aircraft Type       : {aircraft_type}")
    if location: ctx.append(f"- Location            : {location}")
    if sensor_summary: ctx.append(f"- Sensor Signals      : {sensor_summary}")
    ctx.append(f"- UTC Time            : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")

    urgency = "\n⚠️  CRITICAL — Lead with IMMEDIATE life-safety actions.\n" if severity=="CRITICAL" else (
              "\nHIGH SEVERITY — Prioritise crew safety and containment first.\n" if severity=="HIGH" else "")
    detail  = "\nKeep response concise — key action points only.\n" if priority=="rapid" else (
              "\nProvide maximum detail including PPE specs, equipment counts, regulatory references.\n" if priority=="detailed" else "")

    history_block = ""
    if incident_history:
        lines = "\n".join(f"  - {h}" for h in incident_history[-3:])
        history_block = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  INCIDENT HISTORY (Last 3 Events)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{lines}
Assess whether this incident may indicate systemic maintenance or operational issues.
"""

    compound_block = ""
    if is_compound and hazard_names:
        compound_block = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 MULTI-HAZARD COMPOUND EVENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Active simultaneous hazards: {', '.join(hazard_names)}
Generate a unified response strategy that addresses ALL hazards concurrently.
"""

    # Fix 7: Escalation triggers block
    escalation_block = ""
    if escalation_triggers:
        lines = "\n".join(f"  ⚠ {t}" for t in escalation_triggers)
        escalation_block = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 ESCALATION TRIGGER ALERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The following pre-escalation conditions have been detected:
{lines}
Factor these triggers into your escalation prediction section.
"""

    return f"""
You are an airport incident commander and certified ARFF/ICAO/IATA emergency response advisor.
{urgency}{detail}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 INCIDENT CONTEXT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{chr(10).join(ctx)}
{compound_block}{escalation_block}{history_block}
INCIDENT DESCRIPTION:
{incident_desc}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GENERATE FULL EMERGENCY COMMAND RESPONSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SITUATIONAL ASSESSMENT
- Aircraft status:
- Operational impact:
- Immediate life risk:
- Secondary escalation risk:

INCIDENT COMMANDER REASONING
First determine: (1) Immediate life threats (2) Operational hazards (3) Secondary escalation risks
Reason through priorities before giving procedures.

1. ⚡ IMMEDIATE ACTIONS (First 60 seconds)

2. 📞 NOTIFICATIONS & ESCALATION
   (ATC, ARFF, Medical, Security, Airline Ops — priority order)

3. 🔒 CONTAINMENT & EVACUATION

4. 🧰 TACTICAL RESOURCE DEPLOYMENT
   Specify exact numbers:
   - ARFF Units required:
   - Medical teams:
   - Hazmat units:
   - Security units:
   - Specialist equipment:

5. ⚠️  SAFETY PRECAUTIONS & PPE

6. 📋 REGULATORY & DOCUMENTATION (ICAO requirements)

7. 🔮 PREDICTED ESCALATIONS (Next 5-10 minutes)
   - Most likely next event (HIGH/MEDIUM/LOW probability)
   - Trigger conditions to watch for
   - Pre-emptive actions to prevent escalation

8. 📈 RISK ASSESSMENT
   Justify Risk Score {risk_score['score']}/100 ({risk_score['level']}).
   State what would increase or decrease this risk.

9. ✅ POST-INCIDENT PROCEDURES

Use imperative language. Prioritise life safety above all.
Tailor every section to the specific aircraft, airport, and location if provided.
"""

def call_groq(prompt):
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role":"system","content":(
                "You are an expert airport incident commander and emergency response advisor "
                "certified in ICAO Annex 14, IATA Ground Operations Manual, and ARFF standards. "
                "You reason systematically, identify compound threats, predict escalations, and "
                "allocate resources precisely. Human life is the absolute priority.")},
            {"role":"user","content":prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS
    }
    response = http.request(
        "POST","https://api.groq.com/openai/v1/chat/completions",
        body=json.dumps(payload),
        headers={"Content-Type":"application/json","Authorization":f"Bearer {GROQ_API_KEY}"},
        timeout=urllib3.Timeout(connect=5.0, read=50.0)
    )
    if response.status != 200:
        raise Exception(f"Groq API error {response.status}: {response.data.decode()[:300]}")
    return json.loads(response.data.decode())["choices"][0]["message"]["content"]

def lambda_handler(event, context):
    start_time = time.time()
    request_id = getattr(context, "aws_request_id", f"local-{int(time.time())}")
    logger.info(f"[{request_id}] Invocation started")

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode":200,"headers":CORS_HEADERS,"body":""}

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {"statusCode":400,"headers":CORS_HEADERS,"body":json.dumps({"error":"Invalid JSON."})}

    path          = event.get("path","") or event.get("rawPath","")
    mode          = body.get("mode","event" if "/event" in path else "analyze")
    airport_code  = body.get("airport_code","").strip()
    aircraft_type = body.get("aircraft_type","").strip()
    location      = body.get("location","").strip()
    priority      = body.get("priority","standard")
    incident_history = body.get("incident_history",[])

    if mode == "event":
        sensor_data = body.get("sensors",{})
        if not sensor_data:
            return {"statusCode":400,"headers":CORS_HEADERS,"body":json.dumps({"error":"Missing 'sensors' object."})}

        matched = []
        for rule in DETECTION_RULES:
            try:
                if rule["conditions"](sensor_data): matched.append(rule)
            except Exception as e:
                logger.warning(f"Rule {rule['id']} error: {e}")

        if not matched:
            return {"statusCode":200,"headers":CORS_HEADERS,"body":json.dumps({
                "request_id":request_id,"mode":"event","status":"NO_INCIDENT",
                "message":"All sensor readings within normal parameters.",
                "severity":"LOW","risk_score":{"score":0,"level":"LOW","hazard_count":0},
                "timestamp":datetime.now(timezone.utc).isoformat()},indent=2)}

        fused      = fuse_incidents(matched)
        severity   = fused["severity"]
        risk_score = compute_risk_score(matched, sensor_data, aircraft_type, location)
        escalation_triggers = detect_escalation_triggers(sensor_data)   # Fix 7
        sensor_summary = ", ".join(f"{k}={v}" for k,v in sensor_data.items() if v not in (None,False,0))
        incident_desc  = (
            f"AUTOMATED DETECTION: {fused['incident_name']}\n{fused['description']}\n"
            f"Location: {location or 'Unknown'} | Aircraft: {aircraft_type or 'Unknown'} | Airport: {airport_code or 'Unknown'}\n"
            f"Active sensor signals: {sensor_summary}"
        )
    else:
        incident_desc = body.get("incident","").strip()
        if not incident_desc:
            return {"statusCode":400,"headers":CORS_HEADERS,"body":json.dumps({"error":"Missing 'incident' field."})}
        if len(incident_desc) > 2000:
            return {"statusCode":400,"headers":CORS_HEADERS,"body":json.dumps({"error":"Max 2000 characters."})}

        sensor_data   = {}
        sensor_summary = ""
        severity       = detect_severity_text(incident_desc)
        escalation_triggers = []   # no sensor data in manual mode
        sev_weight     = {"CRITICAL":9,"HIGH":6,"MEDIUM":4,"LOW":2}
        fake_rule      = {"name":"Manual Report","severity":severity,"risk_weight":sev_weight.get(severity,5)}
        risk_score     = compute_risk_score([fake_rule],{},aircraft_type,location)
        fused = {"incident_id":"MANUAL","incident_name":"Manual Report","severity":severity,
                 "description":incident_desc,"is_compound":False,"all_matched":["MANUAL"],"hazard_names":[]}

    logger.info(f"[{request_id}] mode={mode} sev={severity} risk={risk_score['score']}/100 compound={fused['is_compound']}")

    prompt = build_command_prompt(
        incident_desc, severity, airport_code, aircraft_type, location, sensor_summary,
        fused["incident_name"], fused["hazard_names"], fused["is_compound"],
        risk_score, priority, incident_history, escalation_triggers
    )

    try:
        advice = call_groq(prompt)
    except Exception as e:
        logger.error(f"[{request_id}] Groq failed: {e}")
        return {"statusCode":502,"headers":CORS_HEADERS,"body":json.dumps({"error":f"AI service error: {str(e)}"})}

    duration_ms   = int((time.time()-start_time)*1000)
    incident_hash = hashlib.sha256(incident_desc.encode()).hexdigest()[:10]
    logger.info(f"[{request_id}] Done {duration_ms}ms hash={incident_hash}")

    return {"statusCode":200,"headers":CORS_HEADERS,"body":json.dumps({
        "request_id":request_id,"incident_hash":incident_hash,
        "timestamp":datetime.now(timezone.utc).isoformat(),
        "mode":mode,"severity":severity,
        "incident_type":fused["incident_name"],
        "is_compound":fused["is_compound"],
        "hazard_names":fused["hazard_names"],
        "all_detected":fused["all_matched"],
        "risk_score":risk_score,
        "ai_confidence": risk_score.get("ai_confidence", 70),   # Fix 6
        "escalation_triggers": escalation_triggers,              # Fix 7
        "airport_code":airport_code or None,
        "aircraft_type":aircraft_type or None,
        "location":location or None,
        "incident":incident_desc,
        "advice":advice,
        "model_used":GROQ_MODEL,
        "duration_ms":duration_ms
    },indent=2)}
