# ============================================================
# ai_rule_engine.py
# PART 1 / 4
# ============================================================

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

import anthropic
import requests

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title="EDR AI Rule Engine",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Configuration
# ============================================================

client = anthropic.Anthropic()

POLICY_SERVER = "http://127.0.0.1:8000"

HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

SYSTEM_PROMPT = """
You are an Endpoint Detection & Response AI.

Always return ONLY valid JSON.

Example:

{
    "block_ip": null,
    "block_domain": null,
    "kill_process": null,
    "firewall_rule": null,
    "alert_message": "",
    "confidence": 0
}
""".strip()

# ============================================================
# Models
# ============================================================

class ThreatEvent(BaseModel):

    event_type: str

    source_ip: str = ""

    details: dict = {}


# ============================================================
# Analyze Endpoint
# ============================================================

@app.post("/analyze")
async def analyze_threat(event: ThreatEvent):

    prompt = f"""
Threat Event

Type:
{event.event_type}

Source IP:
{event.source_ip}

Details:
{json.dumps(event.details, indent=2)}

Timestamp:
{datetime.utcnow().isoformat()}

Generate defensive actions.
"""

    try:

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        raw = response.content[0].text.strip()

        if raw.startswith("```"):

            raw = raw.replace("```json", "")
            raw = raw.replace("```", "")
            raw = raw.strip()

        rules = json.loads(raw)

        apply_rules(rules)

        return {
            "status": "success",
            "rules_applied": rules
        }

    except json.JSONDecodeError:

        return {
            "status": "error",
            "message": "Claude returned invalid JSON."
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }


# ============================================================
# apply_rules()
# (PART 2 continues from here)
# ============================================================
# ============================================================
# Rule Engine
# ============================================================

def apply_rules(rules: dict):

    # --------------------------------------------------------
    # Block IP using Windows Firewall
    # --------------------------------------------------------

    if rules.get("block_ip"):

        ip = rules["block_ip"]

        try:

            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=EDR_Block_{ip}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}"
                ],
                check=True,
                capture_output=True,
                timeout=5
            )

            print(f"[AIEngine] IP Blocked : {ip}")

        except Exception as e:

            print(f"[AIEngine] Failed to block IP : {e}")

    # --------------------------------------------------------
    # Block Domain (Policy Server)
    # --------------------------------------------------------

    if rules.get("block_domain"):

        domain = (
            rules["block_domain"]
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split("?")[0]
            .strip()
            .lower()
        )

        try:

            response = requests.post(
                f"{POLICY_SERVER}/blocked-domains",
                json={
                    "domain": domain
                },
                timeout=5
            )

            if response.status_code == 200:

                print(
                    f"[AIEngine] Domain added : {domain}"
                )

            else:

                print(
                    f"[AIEngine] Policy Server Error : {response.status_code}"
                )

        except Exception as e:

            print(
                f"[AIEngine] Domain Block Failed : {e}"
            )

    # --------------------------------------------------------
    # Kill Process
    # --------------------------------------------------------

    if rules.get("kill_process"):

        process = rules["kill_process"]

        try:

            subprocess.run(
                [
                    "taskkill",
                    "/F",
                    "/IM",
                    process
                ],
                capture_output=True,
                timeout=5
            )

            print(
                f"[AIEngine] Process Killed : {process}"
            )

        except Exception as e:

            print(
                f"[AIEngine] Process Kill Failed : {e}"
            )

    # --------------------------------------------------------
    # Alert Policy Server
    # --------------------------------------------------------

    if rules.get("alert_message"):

        try:

            requests.post(
                f"{POLICY_SERVER}/alert",
                json={
                    "event_type": "AI Rule Triggered",
                    "severity": "high",
                    "message": rules["alert_message"],
                    "confidence": rules.get("confidence", 0),
                    "timestamp": datetime.utcnow().isoformat()
                },
                timeout=5
            )

            print("[AIEngine] Alert sent.")

        except Exception as e:

            print(f"[AIEngine] Alert Failed : {e}")


# ============================================================
# Part 3 starts below
# ============================================================
# ============================================================
# PDF REPORT ENDPOINT
# ============================================================

@app.get("/generate-pdf")
def generate_pdf():

    pdf_path = Path(__file__).parent / "edr_report.pdf"

    try:

        result = subprocess.run(

            [
                sys.executable,
                "pdf_report.py"
            ],

            cwd=Path(__file__).parent,

            capture_output=True,

            text=True,

            timeout=60

        )

        if result.returncode != 0:

            print(result.stderr)

            return {
                "status": "error",
                "message": result.stderr
            }

        if not pdf_path.exists():

            return {
                "status": "error",
                "message": "PDF was not generated."
            }

        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"edr_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "EDR AI Rule Engine",
        "status": "running",
        "policy_server": POLICY_SERVER
    }


@app.get("/health")
def health():

    return {
        "status": "ok",
        "time": datetime.utcnow().isoformat()
    }


# ============================================================
# VERSION
# ============================================================

@app.get("/version")
def version():

    return {
        "name": "EDR AI Rule Engine",
        "version": "1.0",
        "author": "Firewall Agent"
    }


# ============================================================
# STARTUP MESSAGE
# ============================================================

@app.on_event("startup")
async def startup():

    print("=" * 60)
    print("EDR AI RULE ENGINE STARTED")
    print("=" * 60)
    print(f"Policy Server : {POLICY_SERVER}")
    print(f"Python        : {sys.version.split()[0]}")
    print("=" * 60)


# ============================================================
# PART 4 CONTINUES BELOW
# ============================================================
# ============================================================
# SHUTDOWN EVENT
# ============================================================

@app.on_event("shutdown")
async def shutdown():

    print("=" * 60)
    print("EDR AI RULE ENGINE STOPPED")
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "ai_rule_engine:app",
        host="127.0.0.1",
        port=8001,
        reload=False,
        log_level="info"
    )