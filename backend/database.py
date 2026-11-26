"""
AI Sentinel - Database Manager (SQLite)
Handles persistent storage of real-time website scans, query retrieval,
and aggregate statistics calculation for the Security Dashboard.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

BACKEND_DIR = Path(__file__).resolve().parent
DB_PATH = BACKEND_DIR / "sentinel.db"


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    safety_status TEXT NOT NULL,
                    explanation TEXT,
                    detected_indicators TEXT,
                    user_risks TEXT,
                    retrieved_security_info TEXT,
                    features TEXT,
                    safe_browsing TEXT,
                    timestamp TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    is_success INTEGER DEFAULT 1
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_date ON scans(scan_date);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON scans(category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp);")
    finally:
        conn.close()


def record_scan(scan_result: Dict[str, Any], is_success: bool = True) -> int:
    """
    Persists a completed scan result into the database.
    Does not count failed scans as safe.
    """
    if not isinstance(scan_result, dict):
        return -1

    url = scan_result.get("url", "").strip()
    if not url:
        return -1

    now = datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
    scan_date_str = now.strftime("%Y-%m-%d")

    risk_score = scan_result.get("risk_score", 0)
    category = scan_result.get("category", "Unknown")
    safety_status = scan_result.get("safety_status", "Unknown")
    explanation = scan_result.get("ai_generated_explanation") or scan_result.get("explanation") or ""

    detected_indicators = json.dumps(scan_result.get("detected_indicators") or [])
    user_risks = json.dumps(scan_result.get("user_risks") or [])
    retrieved_info = json.dumps(scan_result.get("retrieved_security_info") or [])
    features_json = json.dumps(scan_result.get("features") or {})
    safe_browsing_json = json.dumps(scan_result.get("safe_browsing") or {})

    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    url, risk_score, category, safety_status, explanation,
                    detected_indicators, user_risks, retrieved_security_info,
                    features, safe_browsing, timestamp, scan_date, is_success
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    int(risk_score) if isinstance(risk_score, (int, float)) else 0,
                    category,
                    safety_status,
                    explanation,
                    detected_indicators,
                    user_risks,
                    retrieved_info,
                    features_json,
                    safe_browsing_json,
                    timestamp_str,
                    scan_date_str,
                    1 if is_success else 0,
                ),
            )
            return cursor.lastrowid
    finally:
        conn.close()


def get_scan_history(limit: int = 50, offset: int = 0, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent scan records formatted for the dashboard history table."""
    conn = get_db_connection()
    try:
        query = "SELECT * FROM scans WHERE is_success = 1"
        params: List[Any] = []

        if search and search.strip():
            query += " AND (url LIKE ? OR category LIKE ? OR explanation LIKE ?)"
            term = f"%{search.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()

        history = []
        for r in rows:
            try:
                indicators = json.loads(r["detected_indicators"]) if r["detected_indicators"] else []
            except Exception:
                indicators = []

            try:
                risks = json.loads(r["user_risks"]) if r["user_risks"] else []
            except Exception:
                risks = []

            history.append({
                "id": r["id"],
                "url": r["url"],
                "risk_score": r["risk_score"],
                "category": r["category"],
                "safety_status": r["safety_status"],
                "explanation": r["explanation"],
                "detected_indicators": indicators,
                "user_risks": risks,
                "timestamp": r["timestamp"],
                "scan_date": r["scan_date"],
            })
        return history
    finally:
        conn.close()


def get_dashboard_statistics() -> Dict[str, Any]:
    """
    Computes real aggregate metrics and threat detection analytics
    strictly based on stored scan history.
    """
    conn = get_db_connection()
    try:
        # Total counts
        total_row = conn.execute("SELECT COUNT(*) AS total FROM scans WHERE is_success = 1").fetchone()
        total_scans = total_row["total"] if total_row else 0

        # Safe count (0-30 or 'Low Risk'/'Safe')
        safe_row = conn.execute(
            """
            SELECT COUNT(*) AS safe_count FROM scans
            WHERE is_success = 1 AND (category = 'Low Risk' OR safety_status = 'Safe' OR risk_score <= 30)
            """
        ).fetchone()
        safe_count = safe_row["safe_count"] if safe_row else 0

        # Suspicious count (31-60 or 'Medium Risk'/'Suspicious')
        susp_row = conn.execute(
            """
            SELECT COUNT(*) AS susp_count FROM scans
            WHERE is_success = 1 AND (category = 'Medium Risk' OR safety_status = 'Suspicious' OR (risk_score >= 31 AND risk_score <= 60))
            """
        ).fetchone()
        suspicious_count = susp_row["susp_count"] if susp_row else 0

        # Malicious count (61-100 or 'High Risk'/'Malicious')
        mal_row = conn.execute(
            """
            SELECT COUNT(*) AS mal_count FROM scans
            WHERE is_success = 1 AND (category = 'High Risk' OR safety_status = 'Malicious' OR risk_score >= 61)
            """
        ).fetchone()
        malicious_count = mal_row["mal_count"] if mal_row else 0

        # Overall threat percentage (Threats / Total)
        threat_count = suspicious_count + malicious_count
        threat_percentage = round((threat_count / total_scans * 100), 1) if total_scans > 0 else 0.0

        # Average risk score
        avg_row = conn.execute("SELECT AVG(risk_score) AS avg_score FROM scans WHERE is_success = 1").fetchone()
        avg_risk_score = round(avg_row["avg_score"], 1) if avg_row and avg_row["avg_score"] is not None else 0.0

        # Daily website scans breakdown (last 14 days with activity)
        daily_rows = conn.execute(
            """
            SELECT
                scan_date,
                COUNT(*) AS total,
                SUM(CASE WHEN (category = 'Low Risk' OR risk_score <= 30) THEN 1 ELSE 0 END) AS safe,
                SUM(CASE WHEN (category = 'Medium Risk' OR (risk_score >= 31 AND risk_score <= 60)) THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN (category = 'High Risk' OR risk_score >= 61) THEN 1 ELSE 0 END) AS malicious
            FROM scans
            WHERE is_success = 1
            GROUP BY scan_date
            ORDER BY scan_date ASC
            LIMIT 14
            """
        ).fetchall()

        daily_scans = []
        for r in daily_rows:
            daily_scans.append({
                "date": r["scan_date"],
                "total": r["total"],
                "safe": r["safe"],
                "suspicious": r["suspicious"],
                "malicious": r["malicious"],
            })

        # Risk score brackets for distribution histogram
        bracket_row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN risk_score <= 20 THEN 1 ELSE 0 END) AS b0_20,
                SUM(CASE WHEN risk_score > 20 AND risk_score <= 40 THEN 1 ELSE 0 END) AS b21_40,
                SUM(CASE WHEN risk_score > 40 AND risk_score <= 60 THEN 1 ELSE 0 END) AS b41_60,
                SUM(CASE WHEN risk_score > 60 AND risk_score <= 80 THEN 1 ELSE 0 END) AS b61_80,
                SUM(CASE WHEN risk_score > 80 THEN 1 ELSE 0 END) AS b81_100
            FROM scans
            WHERE is_success = 1
            """
        ).fetchone()

        score_distribution = {
            "0-20": bracket_row["b0_20"] or 0 if bracket_row else 0,
            "21-40": bracket_row["b21_40"] or 0 if bracket_row else 0,
            "41-60": bracket_row["b41_60"] or 0 if bracket_row else 0,
            "61-80": bracket_row["b61_80"] or 0 if bracket_row else 0,
            "81-100": bracket_row["b81_100"] or 0 if bracket_row else 0,
        }

        return {
            "total_scans": total_scans,
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count,
            "threat_percentage": threat_percentage,
            "average_risk_score": avg_risk_score,
            "category_distribution": {
                "safe": safe_count,
                "suspicious": suspicious_count,
                "malicious": malicious_count,
            },
            "daily_scans": daily_scans,
            "score_distribution": score_distribution,
        }
    finally:
        conn.close()


def seed_baseline_records():
    """
    If the database is empty, performs actual model scans on baseline URLs
    (genuine safe URLs and known dataset phishing URLs) so the dashboard
    immediately reflects real, genuine model outputs with zero fake statistics.
    """
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM scans").fetchone()
        if row and row["cnt"] > 0:
            return  # Already populated
    finally:
        conn.close()

    try:
        from detection_engine import detect_phishing
    except ImportError:
        try:
            from backend.detection_engine import detect_phishing
        except ImportError:
            return

    # Real, genuine baseline scans across all 3 risk tiers
    baseline_targets = [
        "https://www.google.com",
        "https://en.wikipedia.org/wiki/Computer_security",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://github.com/trending",
        "http://secure-login.example.org",
        "http://paypal-security-update-account.verify.xyz/signin",
        "http://192.168.10.50/account-verification-alert/login",
        "http://update-wallet-crypto-free.pw/claim",
    ]

    for target in baseline_targets:
        try:
            res = detect_phishing(target)
            record_scan(res, is_success=True)
        except Exception:
            pass


# Automatically ensure tables exist on module import
init_db()
seed_baseline_records()
