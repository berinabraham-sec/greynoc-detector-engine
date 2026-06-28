# GreyNOC Detector Engine

A production-grade, OSINT-driven threat intelligence and detection engine that ingests multiple threat intelligence feeds, correlates data, predicts attack probability, and generates draft detection rules for SOC teams.

---

## Overview

The GreyNOC Detector Engine is an advanced threat intelligence platform that automates the collection, correlation, and analysis of security threat data. It ingests data from multiple open-source intelligence (OSINT) feeds, applies predictive risk scoring, and generates draft detection rules in multiple formats for security operations teams.

### Key Capabilities

- Multi-Source Ingestion: Aggregates data from CISA KEV, NVD, EPSS, and Abuse.ch feeds
- Predictive Scoring: Calculates AttackForecast probability and risk scores
- Detection Generation: Creates draft Sigma, YARA, Splunk, and KQL rules
- Correlation Engine: Links vulnerabilities with exploit intelligence and IOCs
- Reporting: Generates HTML dashboards and JSON exports

---

## Features

### Threat Intelligence Ingestion

- CISA KEV: Known Exploited Vulnerabilities (Daily)
- NIST NVD: Vulnerability Data (Daily)
- FIRST EPSS: Exploit Probability Scores (Daily)
- ThreatFox: Indicators of Compromise (Continuous)
- URLhaus: Malicious URLs (Continuous)

### Predictive AttackForecast

The engine generates predictions for each vulnerability based on:

- KEV Status: High weight - Listed in CISA Known Exploited Vulnerabilities catalog
- EPSS Score: Medium weight - Exploit Prediction Scoring System probability
- CVSS Score: Medium weight - Common Vulnerability Scoring System severity
- Active Exploitation: High weight - Known ransomware or active campaign use

### Detection Rule Generation

- Sigma: Log-based detection (DRAFT)
- YARA: File-based detection (DRAFT)
- Splunk SPL: SIEM queries (DRAFT)
- KQL: Kusto Query Language (DRAFT)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Step 1: Clone the Repository

git clone https://github.com/berinabraham-sec/greynoc-detector-engine.git
cd greynoc-detector-engine

### Step 2: Install Dependencies

pip install -r requirements.txt

### Step 3: Run the Engine

python detector_engine.py --demo
python detector_engine.py --all
python detector_engine.py --ingest
python detector_engine.py --forecast
python detector_engine.py --detect
python detector_engine.py --report

---

## Usage

### Command Line Options

- --demo: Run in demo mode with mock data
- --ingest: Ingest threat intelligence from all sources
- --forecast: Generate AttackForecast predictions
- --detect: Generate detection rules
- --report: Generate reports
- --all: Run full pipeline

### Example: Full Pipeline Run

python detector_engine.py --all

### Example: Generate Detection Rules

python detector_engine.py --detect

---

## Project Structure

greynoc-detector-engine/
- detector_engine.py          # Main application
- README.md                   # Documentation
- requirements.txt            # Python dependencies
- .gitignore                  # Git ignore file
- greynoc.db                  # SQLite database (generated)
- logs/                       # Application logs
- reports/                    # Generated reports

---

## Database Schema

### Vulns Table
- cve_id: CVE identifier (Primary Key)
- description: Vulnerability description
- cvss_score: CVSS base score
- cvss_severity: CVSS severity level
- published_date: Publication date
- last_modified: Last modified date

### KEV Table
- cve_id: CVE identifier (Primary Key)
- vendor: Vendor name
- product: Product name
- date_added: Date added to KEV catalog
- due_date: Remediation due date
- known_ransomware: Ransomware campaign indicator

### EPSS Table
- cve_id: CVE identifier (Primary Key)
- epss_score: EPSS probability score
- percentile: EPSS percentile
- date: Score date

### Forecasts Table
- forecast_id: Unique identifier
- cve_id: CVE identifier
- probability: Exploitation probability
- time_horizon: Days to expected exploitation
- risk_score: Overall risk score
- risk_level: CRITICAL/HIGH/MEDIUM/LOW
- key_drivers: JSON array of drivers

---

## Risk Scoring Methodology

Risk Score = (KEV_Weight x KEV_Status) + (EPSS_Weight x EPSS_Score) + (CVSS_Weight x CVSS_Score) + (Active_Exploitation_Weight)

### Risk Levels

- CRITICAL: 8.0 - 10.0 - Immediate action required
- HIGH: 6.0 - 7.9 - Prioritize within 7 days
- MEDIUM: 4.0 - 5.9 - Plan remediation within 30 days
- LOW: 0.0 - 3.9 - Monitor for changes

### Time Horizons

- Immediate: 7 days
- Short: 30 days
- Medium: 90 days
- Long: 180 days

---

## Detection Formats

### Sigma Rule Example

title: Suspicious Activity Related to CVE-2026-1234
id: a1b2c3d4
status: experimental
description: Detects potential exploitation attempts for CVE-2026-1234
author: GreyNOC Detector Engine
date: 2026-06-28
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'CVE-2026-1234'
            - 'cve-2026-1234'
            - 'CVE-'
    condition: selection
level: critical

### YARA Rule Example

rule CVE_2026_1234 {
    meta:
        author = "GreyNOC Detector Engine"
        date = "2026-06-28"
        description = "Detects artifacts related to CVE-2026-1234"
        severity = "critical"
    strings:
        $a1 = "CVE-2026-1234" nocase
        $a2 = "cve-2026-1234" nocase
        $a3 = "CVE-" nocase
    condition:
        any of them
}

### Splunk Query Example

index=* sourcetype=*
| search CVE-2026-1234 OR "cve-2026-1234"
| stats count by source, host, user
| where count > 0
| table source, host, user, count

---

## Troubleshooting

### Ollama Connection Failed

Check if Ollama is running:
curl http://localhost:11434/api/tags

Start Ollama:
ollama serve

### API Rate Limiting

The engine implements exponential backoff for API calls. If you encounter rate limits, wait and retry.

### Missing Data

Force re-ingestion:
python detector_engine.py --ingest

---

## Author

berinabraham-sec

GitHub: https://github.com/berinabraham-sec

---

## License

MIT License

---

## References

- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST NVD: https://nvd.nist.gov/
- FIRST EPSS: https://www.first.org/epss/
- Abuse.ch ThreatFox: https://threatfox.abuse.ch/
- Abuse.ch URLhaus: https://urlhaus.abuse.ch/

---

## Quick Reference

### Key Commands

- python detector_engine.py --demo: Run demo mode
- python detector_engine.py --ingest: Ingest intelligence
- python detector_engine.py --forecast: Generate forecasts
- python detector_engine.py --detect: Generate detections
- python detector_engine.py --all: Run full pipeline

### Risk Levels

- CRITICAL: 8.0+ - Immediate action
- HIGH: 6.0-7.9 - 7 Days
- MEDIUM: 4.0-5.9 - 30 Days
- LOW: 0.0-3.9 - Monitor

### Detection Formats

- Sigma: Log-based detection
- YARA: File-based detection
- Splunk: SIEM queries
- KQL: Kusto Query Language

---

End of Documentation