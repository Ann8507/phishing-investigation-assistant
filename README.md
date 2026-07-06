# Phishing Investigation Assistant

## Overview
The Phishing Investigation Assistant is a Flask-based web application that helps analyze suspicious emails using AI. Users can paste email headers and body content to receive a phishing risk assessment.

## Features
- Dark-themed user interface
- AI-powered phishing analysis
- Risk Score (0–100)
- Risk Level (Safe / Suspicious / Dangerous)
- Key phishing indicators
- MITRE ATT&CK technique mapping
- Recommended actions
- Human-in-the-loop decision making
- Automatic incident report generation

## Technologies Used
- Python
- Flask
- HTML/CSS
- Google Gemini API (gemini-2.0-flash) *(or Claude API if that's what your code uses)*

## Installation

1. Clone the repository.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set the environment variable:

```
GEMINI_API_KEY=your_api_key
```

4. Run the application:

```bash
python app.py
```

## Project Structure

```
app.py
templates/
    index.html
requirements.txt
README.md
```

## Disclaimer
This tool is intended for educational purposes and assists analysts by providing AI-generated phishing assessments.
