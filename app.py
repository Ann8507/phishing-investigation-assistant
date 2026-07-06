import os
import json
import re
from flask import Flask, render_template, request, jsonify
from groq import Groq
from datetime import datetime

app = Flask(__name__)

# Configure Groq client
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

ANALYSIS_PROMPT = """You are an expert cybersecurity analyst specializing in phishing detection and email threat analysis.

Analyze the following email (headers + body) and provide a structured JSON response.

EMAIL CONTENT:
{email_content}

Respond ONLY with a valid JSON object in this exact format (no markdown, no extra text):
{{
  "risk_score": <integer 0-100>,
  "risk_level": "<Safe|Suspicious|Dangerous>",
  "summary": "<one sentence summary of what this email appears to be>",
  "key_indicators": [
    {{
      "indicator": "<indicator name>",
      "description": "<brief description of the suspicious element found>",
      "severity": "<low|medium|high>"
    }}
  ],
  "recommended_action": "<clear recommended action for the analyst>",
  "mitre_attack": {{
    "applicable": <true|false>,
    "technique_id": "<e.g. T1566.001 or null>",
    "technique_name": "<e.g. Spearphishing Attachment or null>",
    "tactic": "<e.g. Initial Access or null>"
  }},
  "technical_details": {{
    "spoofed_sender": <true|false>,
    "suspicious_urls": <true|false>,
    "urgency_language": <true|false>,
    "credential_harvesting": <true|false>,
    "malware_indicators": <true|false>,
    "social_engineering": <true|false>
  }}
}}

Risk score guidelines:
- 0-30: Safe (legitimate email)
- 31-65: Suspicious (warrants investigation)
- 66-100: Dangerous (clear phishing/malicious intent)

Be thorough but concise. Focus on concrete evidence in the email content."""

REPORT_PROMPT = """You are a cybersecurity incident response analyst. Generate a concise incident report based on the following analysis and human decision.

ORIGINAL EMAIL ANALYSIS:
{analysis}

HUMAN ANALYST DECISION: {decision}
ANALYST NOTES: {notes}
TIMESTAMP: {timestamp}

Write a professional incident report in plain text (no markdown, no JSON). Structure it as:

INCIDENT REPORT
================
Report ID: {report_id}
Date/Time: {timestamp}
Analyst Decision: {decision}

EXECUTIVE SUMMARY
Brief 2-3 sentence summary of the threat and outcome.

THREAT DETAILS
Key findings from the email analysis.

INDICATORS OF COMPROMISE (IOCs)
List specific suspicious elements found.

MITRE ATT&CK MAPPING
Applicable technique(s) if any.

ANALYST NOTES
{notes}

DISPOSITION
Final outcome and next steps taken based on the analyst decision.

Keep the report professional, concise, and actionable."""


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if not GROQ_API_KEY:
        return jsonify({"error": "GROQ_API_KEY environment variable not set. Please configure your API key."}), 500

    data = request.get_json()
    email_content = data.get("email_content", "").strip()

    if not email_content:
        return jsonify({"error": "No email content provided."}), 400

    if len(email_content) < 20:
        return jsonify({"error": "Email content is too short to analyze."}), 400

    try:
        client = Groq(api_key=GROQ_API_KEY)
        prompt = ANALYSIS_PROMPT.format(email_content=email_content)

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert cybersecurity analyst. Always respond with valid JSON only — no markdown, no explanation, no code fences."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=2048,
        )

        raw_text = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
        raw_text = re.sub(r"\s*```$", "", raw_text)
        raw_text = raw_text.strip()

        analysis = json.loads(raw_text)

        # Validate and clamp risk score
        analysis["risk_score"] = max(0, min(100, int(analysis.get("risk_score", 0))))

        return jsonify({"success": True, "analysis": analysis})

    except json.JSONDecodeError as e:
        return jsonify({"error": f"Failed to parse AI response. The model returned an unexpected format. Details: {str(e)}"}), 500
    except Exception as e:
        error_msg = str(e)
        if "api_key" in error_msg.lower() or "authentication" in error_msg.lower() or "401" in error_msg:
            return jsonify({"error": "Invalid or missing Groq API key. Please check your GROQ_API_KEY environment variable."}), 401
        return jsonify({"error": f"Analysis failed: {error_msg}"}), 500


@app.route("/generate-report", methods=["POST"])
def generate_report():
    if not GROQ_API_KEY:
        return jsonify({"error": "GROQ_API_KEY environment variable not set."}), 500

    data = request.get_json()
    analysis = data.get("analysis", {})
    decision = data.get("decision", "")
    notes = data.get("notes", "No additional notes provided.")

    if not analysis or not decision:
        return jsonify({"error": "Missing analysis data or decision."}), 400

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"PHI-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    analysis_str = json.dumps(analysis, indent=2)

    try:
        client = Groq(api_key=GROQ_API_KEY)
        prompt = REPORT_PROMPT.format(
            analysis=analysis_str,
            decision=decision,
            notes=notes,
            timestamp=timestamp,
            report_id=report_id
        )

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a professional cybersecurity incident response analyst. Write clear, concise incident reports in plain text."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=1024,
        )

        report_text = response.choices[0].message.content.strip()

        return jsonify({"success": True, "report": report_text, "report_id": report_id, "timestamp": timestamp})

    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
