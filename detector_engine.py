#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GreyNOC Detector Engine
Enterprise Edition

Author: berinabraham-sec
Version: 2.0.0

Description:
    A production-grade, OSINT-driven threat intelligence and detection engine
    that ingests multiple threat intelligence feeds, correlates data, predicts
    attack probability, and generates draft detection rules for SOC teams.

Data Sources:
    - CISA Known Exploited Vulnerabilities (KEV) Catalog
    - NIST National Vulnerability Database (NVD)
    - FIRST EPSS (Exploit Prediction Scoring System)
    - Abuse.ch ThreatFox (IOC feed)
"""

import json
import sqlite3
import os
import sys
import time
import random
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import requests
import argparse
import logging

# ============================================================================
# SECTION 1: CONFIGURATION
# ============================================================================

class Configuration:
    """Centralized configuration for the GreyNOC Detector Engine."""

    DATABASE_FILE = "greynoc.db"
    OUTPUT_DIR = "reports"
    LOG_DIR = "logs"

    # API Endpoints - FIXED
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL = "https://api.first.org/epss/v1/cve"
    THREATFOX_API_URL = "https://threatfox.abuse.ch/api/v1/"

    # Risk Scoring Configuration
    WEIGHT_KEV = 5.0
    WEIGHT_EPSS = 1.5
    WEIGHT_CVSS = 1.0
    WEIGHT_ACTIVE_EXPLOITATION = 3.0

    # Prediction Thresholds
    THRESHOLD_CRITICAL = 8.0
    THRESHOLD_HIGH = 6.0
    THRESHOLD_MEDIUM = 4.0

    # Time Horizon Predictions (days)
    HORIZON_IMMEDIATE = 7
    HORIZON_SHORT = 30
    HORIZON_MEDIUM = 90
    HORIZON_LONG = 180

    # Detection Formats
    DETECTION_FORMATS = ["sigma", "yara", "splunk", "kql"]

    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


# ============================================================================
# SECTION 2: LOGGING
# ============================================================================

class Logger:
    """Enterprise-grade logging with structured output."""

    def __init__(self, name: str = "GreyNOC"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, Configuration.LOG_LEVEL))

        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console_format = logging.Formatter(Configuration.LOG_FORMAT)
        console.setFormatter(console_format)
        self.logger.addHandler(console)

        os.makedirs(Configuration.LOG_DIR, exist_ok=True)
        log_file = f"{Configuration.LOG_DIR}/greynoc_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(Configuration.LOG_FORMAT)
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)

        self.structured_logs = []

    def info(self, message: str, **kwargs):
        self.logger.info(message)
        self._log_structured("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs):
        self.logger.warning(message)
        self._log_structured("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs):
        self.logger.error(message)
        self._log_structured("ERROR", message, **kwargs)

    def debug(self, message: str, **kwargs):
        self.logger.debug(message)

    def _log_structured(self, level: str, message: str, **kwargs):
        entry = {"timestamp": datetime.now().isoformat(), "level": level, "message": message, **kwargs}
        self.structured_logs.append(entry)
        if len(self.structured_logs) > 10000:
            self.structured_logs = self.structured_logs[-10000:]


# ============================================================================
# SECTION 3: DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    """Manages SQLite database for threat intelligence data persistence."""

    def __init__(self, db_file: str = Configuration.DATABASE_FILE, logger: Logger = None):
        self.db_file = db_file
        self.logger = logger or Logger()
        self._initialize_database()

    def _initialize_database(self):
        """Create database schema if it doesn't exist."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL UNIQUE,
                    description TEXT,
                    cvss_score REAL,
                    cvss_severity TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    raw_data TEXT,
                    ingested_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kev (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL UNIQUE,
                    vendor TEXT,
                    product TEXT,
                    date_added TEXT,
                    due_date TEXT,
                    known_ransomware INTEGER,
                    raw_data TEXT,
                    ingested_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS epss (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL UNIQUE,
                    epss_score REAL,
                    percentile REAL,
                    date TEXT,
                    ingested_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT,
                    threat_type TEXT,
                    malware TEXT,
                    confidence REAL,
                    first_seen TEXT,
                    last_seen TEXT,
                    source TEXT,
                    ingested_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id TEXT NOT NULL UNIQUE,
                    cve_id TEXT,
                    title TEXT,
                    description TEXT,
                    format TEXT,
                    content TEXT,
                    status TEXT DEFAULT 'DRAFT',
                    severity TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS forecasts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    forecast_id TEXT NOT NULL UNIQUE,
                    cve_id TEXT NOT NULL,
                    probability REAL,
                    time_horizon INTEGER,
                    risk_score REAL,
                    risk_level TEXT,
                    key_drivers TEXT,
                    created_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            """)

            conn.commit()
            self.logger.info("Database initialized successfully")

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def execute_write(self, query: str, params: tuple = ()) -> int:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid

    def insert_or_update_vuln(self, vuln: Dict):
        query = """
            INSERT OR REPLACE INTO vulns (
                cve_id, description, cvss_score, cvss_severity,
                published_date, last_modified, raw_data, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            vuln.get('cve_id'),
            vuln.get('description', ''),
            vuln.get('cvss_score', 0.0),
            vuln.get('cvss_severity', ''),
            vuln.get('published_date', ''),
            vuln.get('last_modified', ''),
            vuln.get('raw_data', '{}'),
            datetime.now().isoformat()
        )
        self.execute_write(query, params)

    def insert_or_update_kev(self, kev: Dict):
        query = """
            INSERT OR REPLACE INTO kev (
                cve_id, vendor, product, date_added, due_date,
                known_ransomware, raw_data, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            kev.get('cve_id'),
            kev.get('vendor', ''),
            kev.get('product', ''),
            kev.get('date_added', ''),
            kev.get('due_date', ''),
            1 if kev.get('known_ransomware', False) else 0,
            kev.get('raw_data', '{}'),
            datetime.now().isoformat()
        )
        self.execute_write(query, params)

    def insert_or_update_epss(self, epss: Dict):
        query = """
            INSERT OR REPLACE INTO epss (
                cve_id, epss_score, percentile, date, ingested_at
            ) VALUES (?, ?, ?, ?, ?)
        """
        params = (
            epss.get('cve_id'),
            epss.get('epss_score', 0.0),
            epss.get('percentile', 0.0),
            epss.get('date', datetime.now().isoformat()),
            datetime.now().isoformat()
        )
        self.execute_write(query, params)

    def insert_ioc(self, ioc: Dict):
        query = """
            INSERT OR REPLACE INTO iocs (
                indicator, indicator_type, threat_type, malware,
                confidence, first_seen, last_seen, source, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            ioc.get('indicator'),
            ioc.get('indicator_type', 'unknown'),
            ioc.get('threat_type', ''),
            ioc.get('malware', ''),
            ioc.get('confidence', 0.0),
            ioc.get('first_seen', datetime.now().isoformat()),
            ioc.get('last_seen', datetime.now().isoformat()),
            ioc.get('source', 'unknown'),
            datetime.now().isoformat()
        )
        self.execute_write(query, params)

    def insert_detection(self, detection: Dict) -> str:
        detection_id = f"DET-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        query = """
            INSERT OR REPLACE INTO detections (
                detection_id, cve_id, title, description, format,
                content, status, severity, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            detection_id,
            detection.get('cve_id', ''),
            detection.get('title', ''),
            detection.get('description', ''),
            detection.get('format', 'sigma'),
            detection.get('content', ''),
            detection.get('status', 'DRAFT'),
            detection.get('severity', 'MEDIUM'),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        )
        self.execute_write(query, params)
        return detection_id

    def insert_forecast(self, forecast: Dict) -> str:
        forecast_id = f"FC-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        query = """
            INSERT OR REPLACE INTO forecasts (
                forecast_id, cve_id, probability, time_horizon,
                risk_score, risk_level, key_drivers, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            forecast_id,
            forecast.get('cve_id'),
            forecast.get('probability', 0.0),
            forecast.get('time_horizon', 0),
            forecast.get('risk_score', 0.0),
            forecast.get('risk_level', 'LOW'),
            json.dumps(forecast.get('key_drivers', [])),
            datetime.now().isoformat()
        )
        self.execute_write(query, params)
        return forecast_id

    def get_vuln_with_enrichment(self, cve_id: str) -> Optional[Dict]:
        query = """
            SELECT
                v.*,
                k.vendor, k.product, k.date_added as kev_date_added,
                k.known_ransomware,
                e.epss_score, e.percentile as epss_percentile
            FROM vulns v
            LEFT JOIN kev k ON v.cve_id = k.cve_id
            LEFT JOIN epss e ON v.cve_id = e.cve_id
            WHERE v.cve_id = ?
        """
        results = self.execute_query(query, (cve_id,))
        return results[0] if results else None

    def get_all_forecasts(self, limit: int = 100) -> List[Dict]:
        query = """
            SELECT * FROM forecasts
            ORDER BY risk_score DESC
            LIMIT ?
        """
        return self.execute_query(query, (limit,))

    def get_metadata(self, key: str) -> Optional[str]:
        results = self.execute_query("SELECT value FROM metadata WHERE key = ?", (key,))
        return results[0]['value'] if results else None

    def set_metadata(self, key: str, value: str):
        query = "INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)"
        params = (key, value, datetime.now().isoformat())
        self.execute_write(query, params)


# ============================================================================
# SECTION 4: THREAT INTELLIGENCE INGESTION
# ============================================================================

class ThreatIntelligenceIngestor:
    """Ingests data from multiple threat intelligence sources."""

    def __init__(self, db_manager: DatabaseManager, logger: Logger):
        self.db = db_manager
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "GreyNOC-Detector-Engine/2.0"})

    def ingest_cisa_kev(self) -> int:
        """Ingest CISA KEV catalog."""
        self.logger.info("Ingesting CISA KEV catalog...")
        try:
            response = self.session.get(Configuration.CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()

            count = 0
            for entry in data.get('vulnerabilities', []):
                kev = {
                    'cve_id': entry.get('cveID', ''),
                    'vendor': entry.get('vendorProject', ''),
                    'product': entry.get('product', ''),
                    'date_added': entry.get('dateAdded', ''),
                    'due_date': entry.get('dueDate', ''),
                    'known_ransomware': entry.get('knownRansomwareCampaignUse', False),
                    'raw_data': json.dumps(entry)
                }
                if kev['cve_id']:
                    self.db.insert_or_update_kev(kev)
                    count += 1

            self.db.set_metadata('cisa_kev_last_ingest', datetime.now().isoformat())
            self.logger.info(f"Ingested {count} KEV records")
            return count

        except Exception as e:
            self.logger.error(f"CISA KEV ingestion failed: {str(e)}")
            return 0

    def ingest_epss_batch(self, cve_list: List[str]) -> int:
        """Ingest EPSS scores for a batch of CVEs."""
        if not cve_list:
            return 0

        try:
            cve_string = ','.join(cve_list[:100])
            params = {'cve': cve_string}
            response = self.session.get(Configuration.EPSS_API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            count = 0
            for entry in data.get('data', []):
                epss = {
                    'cve_id': entry.get('cve', ''),
                    'epss_score': entry.get('epss', 0.0),
                    'percentile': entry.get('percentile', 0.0),
                    'date': data.get('meta', {}).get('date', datetime.now().isoformat())
                }
                if epss['cve_id']:
                    self.db.insert_or_update_epss(epss)
                    count += 1

            return count

        except Exception as e:
            self.logger.error(f"EPSS batch ingestion failed: {str(e)}")
            return 0

    def ingest_epss(self) -> int:
        """Ingest EPSS scores for all CVEs in the database."""
        self.logger.info("Ingesting EPSS scores...")

        # Get all CVEs from KEV
        kev_cves = self.db.execute_query("SELECT cve_id FROM kev")
        if not kev_cves:
            self.logger.warning("No KEV CVEs found for EPSS enrichment")
            return 0

        cve_list = [row['cve_id'] for row in kev_cves]
        total_count = 0

        # Process in batches of 100
        for i in range(0, len(cve_list), 100):
            batch = cve_list[i:i+100]
            count = self.ingest_epss_batch(batch)
            total_count += count
            time.sleep(0.5)  # Rate limiting

        self.db.set_metadata('epss_last_ingest', datetime.now().isoformat())
        self.logger.info(f"Ingested {total_count} EPSS records")
        return total_count

    def ingest_nvd_batch(self, cve_list: List[str]) -> int:
        """Ingest NVD data for a batch of CVEs."""
        if not cve_list:
            return 0

        try:
            cve_string = ','.join(cve_list[:50])
            params = {'cveId': cve_string}
            response = self.session.get(Configuration.NVD_API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            count = 0
            for vuln in data.get('vulnerabilities', []):
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')

                description = ''
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                cvss_score = 0.0
                cvss_severity = ''
                metrics = cve_data.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV3', [])
                if cvss_v3:
                    cvss = cvss_v3[0].get('cvssData', {})
                    cvss_score = cvss.get('baseScore', 0.0)
                    cvss_severity = cvss.get('baseSeverity', '')

                vuln_record = {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'cvss_severity': cvss_severity,
                    'published_date': cve_data.get('published', ''),
                    'last_modified': cve_data.get('lastModified', ''),
                    'raw_data': json.dumps(cve_data)
                }
                if vuln_record['cve_id']:
                    self.db.insert_or_update_vuln(vuln_record)
                    count += 1

            return count

        except Exception as e:
            self.logger.error(f"NVD batch ingestion failed: {str(e)}")
            return 0

    def ingest_nvd(self) -> int:
        """Ingest NVD data for all CVEs in the database."""
        self.logger.info("Ingesting NVD data...")

        # Get all CVEs from KEV
        kev_cves = self.db.execute_query("SELECT cve_id FROM kev")
        if not kev_cves:
            self.logger.warning("No KEV CVEs found for NVD enrichment")
            return 0

        cve_list = [row['cve_id'] for row in kev_cves]
        total_count = 0

        # Process in batches of 50
        for i in range(0, len(cve_list), 50):
            batch = cve_list[i:i+50]
            count = self.ingest_nvd_batch(batch)
            total_count += count
            time.sleep(0.5)

        self.db.set_metadata('nvd_last_ingest', datetime.now().isoformat())
        self.logger.info(f"Ingested {total_count} NVD records")
        return total_count

    def ingest_threatfox(self, limit: int = 100) -> int:
        """Ingest IOCs from ThreatFox."""
        self.logger.info(f"Ingesting ThreatFox data (limit: {limit})...")
        try:
            payload = {"query": "get_iocs", "limit": limit}
            response = self.session.post(Configuration.THREATFOX_API_URL, json=payload, timeout=30)
            if response.status_code != 200:
                self.logger.warning(f"ThreatFox returned status {response.status_code}")
                return 0

            data = response.json()
            if data.get('query_status') != 'ok':
                self.logger.warning(f"ThreatFox query failed: {data.get('query_status', 'unknown')}")
                return 0

            count = 0
            for ioc in data.get('data', []):
                ioc_record = {
                    'indicator': ioc.get('ioc', ''),
                    'indicator_type': ioc.get('ioc_type', ''),
                    'threat_type': ioc.get('threat_type', ''),
                    'malware': ioc.get('malware', ''),
                    'confidence': ioc.get('confidence_level', 0.0),
                    'first_seen': ioc.get('first_seen', ''),
                    'last_seen': ioc.get('last_seen', ''),
                    'source': 'ThreatFox'
                }
                if ioc_record['indicator']:
                    self.db.insert_ioc(ioc_record)
                    count += 1

            self.db.set_metadata('threatfox_last_ingest', datetime.now().isoformat())
            self.logger.info(f"Ingested {count} ThreatFox IOCs")
            return count

        except Exception as e:
            self.logger.error(f"ThreatFox ingestion failed: {str(e)}")
            return 0

    def run_full_ingest(self) -> Dict:
        """Run a complete ingestion cycle."""
        self.logger.info("Starting full threat intelligence ingestion...")

        results = {
            'cisa_kev': self.ingest_cisa_kev(),
            'epss': self.ingest_epss(),
            'nvd': self.ingest_nvd(),
            'threatfox': self.ingest_threatfox()
        }

        self.logger.info(f"Full ingestion complete: {results}")
        return results


# ============================================================================
# SECTION 5: PREDICTIVE ENGINE
# ============================================================================

class PredictiveEngine:
    """Generates AttackForecast predictions based on correlated threat intelligence."""

    def __init__(self, db_manager: DatabaseManager, logger: Logger):
        self.db = db_manager
        self.logger = logger

    def generate_forecast(self, cve_id: str) -> Dict:
        """Generate an AttackForecast for a specific CVE."""
        self.logger.info(f"Generating forecast for {cve_id}")

        vuln = self.db.get_vuln_with_enrichment(cve_id)
        if not vuln:
            self.logger.warning(f"No vulnerability data found for {cve_id}")
            return None

        risk_score = self._calculate_risk_score(vuln)
        probability = self._calculate_probability(vuln)
        time_horizon = self._calculate_time_horizon(vuln)
        risk_level = self._determine_risk_level(risk_score)
        key_drivers = self._identify_drivers(vuln)

        forecast = {
            'cve_id': cve_id,
            'probability': probability,
            'time_horizon': time_horizon,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'key_drivers': key_drivers
        }

        forecast_id = self.db.insert_forecast(forecast)
        forecast['forecast_id'] = forecast_id

        self.logger.info(f"Forecast generated for {cve_id}: {risk_level} ({risk_score:.2f})")
        return forecast

    def generate_all_forecasts(self, limit: int = 100) -> List[Dict]:
        """Generate forecasts for all CVEs with enrichment data."""
        self.logger.info("Generating forecasts for all CVEs...")

        query = """
            SELECT DISTINCT v.cve_id
            FROM vulns v
            LEFT JOIN kev k ON v.cve_id = k.cve_id
            WHERE v.cvss_score IS NOT NULL
            ORDER BY v.cvss_score DESC
            LIMIT ?
        """
        results = self.db.execute_query(query, (limit,))

        forecasts = []
        for row in results:
            forecast = self.generate_forecast(row['cve_id'])
            if forecast:
                forecasts.append(forecast)

        self.logger.info(f"Generated {len(forecasts)} forecasts")
        return forecasts

    def _calculate_risk_score(self, vuln: Dict) -> float:
        risk = 0.0

        if vuln.get('kev_date_added'):
            risk += Configuration.WEIGHT_KEV

        epss_score = vuln.get('epss_score', 0.0)
        risk += epss_score * 10 * Configuration.WEIGHT_EPSS

        cvss_score = vuln.get('cvss_score', 0.0)
        risk += cvss_score * Configuration.WEIGHT_CVSS

        if vuln.get('known_ransomware'):
            risk += Configuration.WEIGHT_ACTIVE_EXPLOITATION

        return min(10.0, round(risk, 2))

    def _calculate_probability(self, vuln: Dict) -> float:
        epss_score = vuln.get('epss_score', 0.0)

        if vuln.get('kev_date_added'):
            epss_score = min(1.0, epss_score + 0.3)

        cvss_score = vuln.get('cvss_score', 0.0)
        if cvss_score >= 9.0:
            epss_score = min(1.0, epss_score + 0.15)

        return round(epss_score, 2)

    def _calculate_time_horizon(self, vuln: Dict) -> int:
        horizon = Configuration.HORIZON_MEDIUM

        if vuln.get('kev_date_added'):
            horizon = Configuration.HORIZON_IMMEDIATE
        elif vuln.get('epss_score', 0.0) > 0.5:
            horizon = Configuration.HORIZON_SHORT
        elif vuln.get('cvss_score', 0.0) > 7.0:
            horizon = Configuration.HORIZON_MEDIUM

        return horizon

    def _determine_risk_level(self, score: float) -> str:
        if score >= Configuration.THRESHOLD_CRITICAL:
            return "CRITICAL"
        elif score >= Configuration.THRESHOLD_HIGH:
            return "HIGH"
        elif score >= Configuration.THRESHOLD_MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"

    def _identify_drivers(self, vuln: Dict) -> List[str]:
        drivers = []

        if vuln.get('kev_date_added'):
            drivers.append(f"Listed in CISA KEV catalog (added {vuln.get('kev_date_added')})")

        if vuln.get('known_ransomware'):
            drivers.append("Known ransomware campaign use")

        epss = vuln.get('epss_score', 0.0)
        if epss > 0.5:
            drivers.append(f"High EPSS score ({epss:.2%})")

        cvss = vuln.get('cvss_score', 0.0)
        if cvss >= 9.0:
            drivers.append(f"Critical CVSS severity ({cvss:.1f})")
        elif cvss >= 7.0:
            drivers.append(f"High CVSS severity ({cvss:.1f})")

        if vuln.get('product'):
            drivers.append(f"Affects {vuln.get('product')} by {vuln.get('vendor', 'unknown')}")

        return drivers


# ============================================================================
# SECTION 6: DETECTION GENERATOR
# ============================================================================

class DetectionGenerator:
    """Generates draft detection rules in multiple formats."""

    def __init__(self, db_manager: DatabaseManager, logger: Logger):
        self.db = db_manager
        self.logger = logger

    def generate_detections(self, forecast: Dict) -> Dict:
        """Generate detection rules for a forecast."""
        self.logger.info(f"Generating detections for {forecast['cve_id']}")

        detections = {}

        for format_type in Configuration.DETECTION_FORMATS:
            try:
                detection = self._generate_detection(forecast, format_type)
                if detection:
                    detections[format_type] = detection
                    detection_id = self.db.insert_detection(detection)
                    detections[format_type]['detection_id'] = detection_id
            except Exception as e:
                self.logger.error(f"Failed to generate {format_type} detection: {str(e)}")

        return detections

    def _generate_detection(self, forecast: Dict, format_type: str) -> Dict:
        generators = {
            'sigma': self._generate_sigma,
            'yara': self._generate_yara,
            'splunk': self._generate_splunk,
            'kql': self._generate_kql
        }

        generator = generators.get(format_type)
        if not generator:
            return None

        return generator(forecast)

    def _generate_sigma(self, forecast: Dict) -> Dict:
        cve_id = forecast['cve_id']
        risk_level = forecast['risk_level']

        content = f"""title: Suspicious Activity Related to {cve_id}
id: {hashlib.md5(cve_id.encode()).hexdigest()[:8]}
status: experimental
description: Detects potential exploitation attempts for {cve_id}
author: GreyNOC Detector Engine
date: {datetime.now().strftime('%Y-%m-%d')}
references:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '{cve_id}'
            - '{cve_id.lower()}'
            - 'CVE-'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: {risk_level.lower()}
"""
        return {
            'title': f'{cve_id} - Suspicious Activity',
            'cve_id': cve_id,
            'format': 'sigma',
            'severity': risk_level,
            'content': content,
            'status': 'DRAFT'
        }

    def _generate_yara(self, forecast: Dict) -> Dict:
        cve_id = forecast['cve_id']
        risk_level = forecast['risk_level']

        content = f"""rule {cve_id.replace('-', '_')} {{
    meta:
        author = "GreyNOC Detector Engine"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        description = "Detects artifacts related to {cve_id}"
        reference = "https://nvd.nist.gov/vuln/detail/{cve_id}"
        severity = "{risk_level.lower()}"
    strings:
        $a1 = "{cve_id}" nocase
        $a2 = "{cve_id.lower()}" nocase
        $a3 = "CVE-" nocase
    condition:
        any of them
}}
"""
        return {
            'title': f'{cve_id} - Malware Detection',
            'cve_id': cve_id,
            'format': 'yara',
            'severity': risk_level,
            'content': content,
            'status': 'DRAFT'
        }

    def _generate_splunk(self, forecast: Dict) -> Dict:
        cve_id = forecast['cve_id']
        risk_level = forecast['risk_level']

        content = f"""index=* sourcetype=*
| search CVE- OR "{cve_id}" OR "{cve_id.lower()}"
| stats count by source, host, user
| where count > 0
| table source, host, user, count
| eval risk_level = "{risk_level}"
| eval cve = "{cve_id}"
"""
        return {
            'title': f'{cve_id} - Splunk Search',
            'cve_id': cve_id,
            'format': 'splunk',
            'severity': risk_level,
            'content': content,
            'status': 'DRAFT'
        }

    def _generate_kql(self, forecast: Dict) -> Dict:
        cve_id = forecast['cve_id']
        risk_level = forecast['risk_level']

        content = f"""// {cve_id} Detection
let cve = "{cve_id}";
let cveLower = "{cve_id.lower()}";
DeviceEvents
| where (ProcessCommandLine contains cve) 
    or (ProcessCommandLine contains cveLower)
    or (ProcessCommandLine contains "CVE-")
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
| extend RiskLevel = "{risk_level}"
| extend CVE = cve
"""
        return {
            'title': f'{cve_id} - KQL Detection',
            'cve_id': cve_id,
            'format': 'kql',
            'severity': risk_level,
            'content': content,
            'status': 'DRAFT'
        }

    def generate_detection_package(self, forecasts: List[Dict]) -> Dict:
        """Generate detections for multiple forecasts."""
        self.logger.info(f"Generating detection package for {len(forecasts)} forecasts")

        package = {
            'generated': datetime.now().isoformat(),
            'total_forecasts': len(forecasts),
            'detections': {}
        }

        for forecast in forecasts:
            cve_id = forecast['cve_id']
            detections = self.generate_detections(forecast)
            package['detections'][cve_id] = detections

        return package


# ============================================================================
# SECTION 7: REPORTING ENGINE
# ============================================================================

class ReportingEngine:
    """Generates comprehensive reports in multiple formats."""

    def __init__(self, db_manager: DatabaseManager, logger: Logger):
        self.db = db_manager
        self.logger = logger
        self.timestamp = datetime.now()

    def generate_console_report(self, forecasts: List[Dict]) -> str:
        """Generate a formatted console report."""
        report = []
        report.append("")
        report.append("=" * 80)
        report.append("GREYNOC DETECTOR ENGINE - ATTACKFORECAST REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("-" * 80)

        if not forecasts:
            report.append("No forecasts available.")
            return "\n".join(report)

        risk_levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in forecasts:
            risk_levels[f.get('risk_level', 'LOW')] += 1

        report.append("")
        report.append("SUMMARY:")
        report.append(f"  Total Forecasts: {len(forecasts)}")
        report.append(f"  Critical: {risk_levels['CRITICAL']}")
        report.append(f"  High: {risk_levels['HIGH']}")
        report.append(f"  Medium: {risk_levels['MEDIUM']}")
        report.append(f"  Low: {risk_levels['LOW']}")

        report.append("")
        report.append("TOP THREATS:")
        for i, f in enumerate(forecasts[:10], 1):
            report.append(f"  {i}. {f['cve_id']} - Risk: {f['risk_score']:.2f} ({f['risk_level']})")
            report.append(f"     Probability: {f['probability']:.2%} | Horizon: {f['time_horizon']} days")
            if f.get('key_drivers'):
                report.append(f"     Drivers: {', '.join(f['key_drivers'][:2])}")

        report.append("")
        report.append("=" * 80)
        return "\n".join(report)

    def generate_html_report(self, forecasts: List[Dict]) -> str:
        """Generate an HTML dashboard report."""
        timestamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')

        risk_levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in forecasts:
            risk_levels[f.get('risk_level', 'LOW')] += 1

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>GreyNOC - AttackForecast Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #12122a; padding: 30px; border-radius: 8px; border: 1px solid #2a2a4a; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 15px; }}
        h2 {{ color: #00d4ff; margin-top: 25px; }}
        .header {{ display: flex; gap: 30px; margin: 20px 0; padding: 15px; background: #1a1a3a; border-radius: 4px; flex-wrap: wrap; }}
        .header strong {{ color: #00d4ff; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #1a1a3a; padding: 20px; border-radius: 6px; text-align: center; border: 1px solid #2a2a4a; }}
        .stat-card .number {{ font-size: 32px; font-weight: bold; }}
        .stat-card .number-critical {{ color: #ff0040; }}
        .stat-card .number-high {{ color: #ff6600; }}
        .stat-card .number-medium {{ color: #ffcc00; }}
        .stat-card .number-low {{ color: #00cc66; }}
        .stat-card .label {{ font-size: 12px; color: #8888aa; }}
        .forecast {{ padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #444; background: #1a1a3a; }}
        .forecast-critical {{ border-left-color: #ff0040; background: #2a0a1a; }}
        .forecast-high {{ border-left-color: #ff6600; background: #2a1a0a; }}
        .forecast-medium {{ border-left-color: #ffcc00; background: #2a2a0a; }}
        .forecast-low {{ border-left-color: #00cc66; background: #0a2a1a; }}
        .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #2a2a4a; font-size: 12px; color: #666688; text-align: center; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 11px; }}
        .badge-critical {{ background: #ff0040; }}
        .badge-high {{ background: #ff6600; }}
        .badge-medium {{ background: #ffcc00; color: #0a0a1a; }}
        .badge-low {{ background: #00cc66; color: #0a0a1a; }}
        .progress-bar {{ height: 6px; background: #2a2a4a; border-radius: 3px; margin: 5px 0; overflow: hidden; }}
        .progress-fill {{ height: 100%; border-radius: 3px; }}
        .progress-critical {{ background: #ff0040; }}
        .progress-high {{ background: #ff6600; }}
        .progress-medium {{ background: #ffcc00; }}
        .progress-low {{ background: #00cc66; }}
    </style>
</head>
<body>
<div class="container">
    <h1>GreyNOC Detector Engine</h1>
    <p style="color: #8888aa;">Predictive Threat Intelligence Dashboard</p>
    <div class="header">
        <div><strong>Generated:</strong> {timestamp}</div>
        <div><strong>Forecasts:</strong> {len(forecasts)}</div>
    </div>
    <div class="stats-grid">
        <div class="stat-card"><div class="number number-critical">{risk_levels['CRITICAL']}</div><div class="label">Critical</div></div>
        <div class="stat-card"><div class="number number-high">{risk_levels['HIGH']}</div><div class="label">High</div></div>
        <div class="stat-card"><div class="number number-medium">{risk_levels['MEDIUM']}</div><div class="label">Medium</div></div>
        <div class="stat-card"><div class="number number-low">{risk_levels['LOW']}</div><div class="label">Low</div></div>
    </div>
    <h2>AttackForecast Results</h2>
"""

        for f in forecasts[:20]:
            risk_level = f.get('risk_level', 'LOW').lower()
            score = f.get('risk_score', 0.0)
            probability = f.get('probability', 0.0)

            html += f"""
    <div class="forecast forecast-{risk_level}">
        <div><strong>{f['cve_id']}</strong> <span class="badge badge-{risk_level}">{f.get('risk_level', 'LOW')}</span></div>
        <div>Risk Score: {score:.2f} | Probability: {probability:.2%} | Horizon: {f.get('time_horizon', 0)} days</div>
        <div class="progress-bar"><div class="progress-fill progress-{risk_level}" style="width:{probability*100}%;"></div></div>
        <div style="font-size:12px; color:#8888aa;">Drivers: {', '.join(f.get('key_drivers', [])[:3])}</div>
    </div>
"""

        html += f"""
    <div class="footer">Generated by GreyNOC Detector Engine v2.0.0</div>
</div>
</body>
</html>"""
        return html

    def generate_json_report(self, forecasts: List[Dict], detections: Dict = None) -> str:
        """Generate a JSON report."""
        report = {
            'generated': self.timestamp.isoformat(),
            'total_forecasts': len(forecasts),
            'forecasts': forecasts
        }
        if detections:
            report['detections'] = detections
        return json.dumps(report, indent=2)


# ============================================================================
# SECTION 8: MAIN APPLICATION
# ============================================================================

class GreyNOCDetectorEngine:
    """Main orchestrator for the GreyNOC Detector Engine."""

    def __init__(self):
        self.logger = Logger()
        self.db = DatabaseManager(logger=self.logger)
        self.ingestor = ThreatIntelligenceIngestor(self.db, self.logger)
        self.predictive = PredictiveEngine(self.db, self.logger)
        self.detection = DetectionGenerator(self.db, self.logger)
        self.reporting = ReportingEngine(self.db, self.logger)

    def run_full_pipeline(self) -> Dict:
        """Run the complete GreyNOC pipeline."""
        self.logger.info("Starting full GreyNOC pipeline...")

        ingest_results = self.ingestor.run_full_ingest()
        forecasts = self.predictive.generate_all_forecasts(limit=50)
        detection_package = self.detection.generate_detection_package(forecasts[:10])

        os.makedirs(Configuration.OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        console_report = self.reporting.generate_console_report(forecasts)
        print(console_report)

        html_content = self.reporting.generate_html_report(forecasts)
        html_file = f"{Configuration.OUTPUT_DIR}/greynoc_report_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
        self.logger.info(f"HTML report saved: {html_file}")

        json_content = self.reporting.generate_json_report(forecasts, detection_package)
        json_file = f"{Configuration.OUTPUT_DIR}/greynoc_export_{timestamp}.json"
        with open(json_file, 'w') as f:
            f.write(json_content)
        self.logger.info(f"JSON report saved: {json_file}")

        return {
            'ingest': ingest_results,
            'forecasts': forecasts,
            'detections': detection_package,
            'reports': {'html': html_file, 'json': json_file}
        }

    def run_demo(self):
        """Run a demonstration with mock data."""
        self.logger.info("Running GreyNOC demo with mock data...")

        mock_forecasts = []
        for i in range(10):
            cve_id = f"CVE-2026-{random.randint(1000, 9999)}"
            risk_score = random.uniform(2.0, 9.5)
            forecast = {
                'cve_id': cve_id,
                'probability': random.uniform(0.1, 0.9),
                'time_horizon': random.choice([7, 30, 90, 180]),
                'risk_score': risk_score,
                'risk_level': self.predictive._determine_risk_level(risk_score),
                'key_drivers': [
                    random.choice(['High CVSS score', 'Known exploit available', 'CISA KEV listed', 'Active ransomware campaign']),
                    random.choice(['Affects critical infrastructure', 'Public exploit code available', 'Widely deployed software'])
                ]
            }
            mock_forecasts.append(forecast)

        detection_package = self.detection.generate_detection_package(mock_forecasts[:5])

        os.makedirs(Configuration.OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        console_report = self.reporting.generate_console_report(mock_forecasts)
        print(console_report)

        html_content = self.reporting.generate_html_report(mock_forecasts)
        html_file = f"{Configuration.OUTPUT_DIR}/greynoc_demo_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"\nHTML report saved: {html_file}")

        return mock_forecasts


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='GreyNOC Detector Engine')
    parser.add_argument('--demo', action='store_true', help='Run in demo mode with mock data')
    parser.add_argument('--ingest', action='store_true', help='Run full intelligence ingestion')
    parser.add_argument('--forecast', action='store_true', help='Generate AttackForecast predictions')
    parser.add_argument('--detect', action='store_true', help='Generate detection rules')
    parser.add_argument('--report', action='store_true', help='Generate reports')
    parser.add_argument('--all', action='store_true', help='Run full pipeline')

    args = parser.parse_args()

    engine = GreyNOCDetectorEngine()

    if args.demo:
        engine.run_demo()
    elif args.all:
        engine.run_full_pipeline()
    elif args.ingest:
        engine.ingestor.run_full_ingest()
    elif args.forecast:
        forecasts = engine.predictive.generate_all_forecasts()
        print(engine.reporting.generate_console_report(forecasts))
    elif args.detect:
        forecasts = engine.predictive.generate_all_forecasts(limit=10)
        detection_package = engine.detection.generate_detection_package(forecasts)
        print(json.dumps(detection_package, indent=2))
    elif args.report:
        forecasts = engine.predictive.generate_all_forecasts()
        os.makedirs(Configuration.OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_content = engine.reporting.generate_html_report(forecasts)
        html_file = f"{Configuration.OUTPUT_DIR}/greynoc_report_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"HTML report saved: {html_file}")
    else:
        print("""
GreyNOC Detector Engine - Enterprise Edition

Usage:
  python detector_engine.py --demo          Run in demo mode
  python detector_engine.py --ingest        Ingest threat intelligence
  python detector_engine.py --forecast      Generate AttackForecast predictions
  python detector_engine.py --detect        Generate detection rules
  python detector_engine.py --report        Generate reports
  python detector_engine.py --all           Run full pipeline
        """)


if __name__ == "__main__":
    main()