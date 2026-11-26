import os
import re
import json
import csv
from urllib.parse import urlparse
from pathlib import Path
import joblib
import requests
from dotenv import load_dotenv
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

try:
    from threat_explainer import generate_threat_explanation
except ImportError:
    from backend.threat_explainer import generate_threat_explanation

try:
    from rag_engine import generate_rag_explanation
except ImportError:
    from backend.rag_engine import generate_rag_explanation

# Load environment variables from .env file if available
load_dotenv()

# File paths
BACKEND_DIR = Path(__file__).resolve().parent
MODEL_PATH = BACKEND_DIR / "model.joblib"
METRICS_PATH = BACKEND_DIR / "model_metrics.json"
DATASET_PATH = BACKEND_DIR / "data" / "urls_dataset.csv"

# ---------------------------------------------------------------------------
# Suspicious Keywords & TLD Lists
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "security", "account",
    "banking", "signin", "password", "credential", "paypal",
    "appleid", "support", "billing", "recover", "authenticate",
    "wallet", "crypto", "free-gift", "confirm", "claim",
    "secure-login", "webscr", "ebayisapi"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "club", "work", "loan", "click"
}

FEATURE_NAMES = [
    "url_length",
    "dot_count",
    "has_ip_address",
    "is_https",
    "suspicious_keyword_count",
    "has_at_symbol",
    "domain_length",
    "hyphen_count_domain",
    "subdomain_count",
    "has_double_slash_redirect",
    "suspicious_tld",
]


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------
def extract_url_features(url: str) -> dict:
    """
    Extracts 11 lexical, structural, and heuristic features from a given URL:
    1.  url_length: Length of entire URL string.
    2.  dot_count: Number of dots in URL.
    3.  has_ip_address: Whether hostname is an IPv4 address.
    4.  is_https: Whether protocol is HTTPS.
    5.  suspicious_keyword_count: Count of high-risk phishing keywords.
    6.  has_at_symbol: Presence of '@' (often used for URL spoofing).
    7.  domain_length: Character length of domain/hostname.
    8.  hyphen_count_domain: Number of hyphens in hostname.
    9.  subdomain_count: Number of subdomain levels.
    10. has_double_slash_redirect: Presence of '//' in URL path redirect.
    11. suspicious_tld: Whether domain uses high-abuse top-level domains.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url.lower()

    # 1. URL length
    url_length = len(url)

    # 2. Number of dots
    dot_count = url.count(".")

    # 3. IP address usage as hostname
    ip_regex = r"^(\d{1,3}\.){3}\d{1,3}$"
    has_ip_address = 1 if re.match(ip_regex, hostname) else 0

    # 4. HTTPS availability
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # 5. Suspicious keywords count
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    suspicious_keyword_count = len(matched_keywords)

    # 6. Suspicious domain patterns: '@' symbol
    has_at_symbol = 1 if "@" in url else 0

    # 7. Domain length
    domain_length = len(hostname)

    # 8. Hyphen count in hostname
    hyphen_count_domain = hostname.count("-")

    # 9. Subdomains calculation
    parts = hostname.split(".")
    subdomain_count = max(0, len(parts) - 2) if len(parts) >= 2 else 0

    # 10. Check for double slash redirection in path
    has_double_slash_redirect = 1 if "//" in path else 0

    # 11. Suspicious TLD check
    tld = parts[-1] if parts else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    features = {
        "url_length": url_length,
        "dot_count": dot_count,
        "has_ip_address": has_ip_address,
        "is_https": is_https,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_at_symbol": has_at_symbol,
        "domain_length": domain_length,
        "hyphen_count_domain": hyphen_count_domain,
        "subdomain_count": subdomain_count,
        "has_double_slash_redirect": has_double_slash_redirect,
        "suspicious_tld": suspicious_tld,
        "matched_keywords": matched_keywords,
    }

    return features


def feature_dict_to_vector(features: dict) -> list:
    """Converts feature dictionary to ordered numeric vector for ML model."""
    return [features[name] for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Machine Learning Model Trainer & Evaluator
# ---------------------------------------------------------------------------
def _load_dataset():
    """Loads URLs and binary labels from urls_dataset.csv."""
    samples = []
    if DATASET_PATH.exists():
        with open(DATASET_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url", "").strip()
                label_str = row.get("label", "").strip()
                if url and label_str in ("0", "1"):
                    samples.append((url, int(label_str)))
    return samples


def train_and_evaluate_model():
    """
    Trains a Random Forest classifier using the dataset, evaluates performance
    on a held-out test split, and saves model and performance metrics to disk.
    """
    samples = _load_dataset()
    if not samples:
        raise RuntimeError(f"Training dataset not found at {DATASET_PATH}")

    X = []
    y = []
    for sample_url, label in samples:
        feats = extract_url_features(sample_url)
        X.append(feature_dict_to_vector(feats))
        y.append(label)

    # 80/20 train/test split with stratified sampling
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=8)
    model.fit(X_train, y_train)

    # Evaluate on held-out test set
    y_pred = model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 8,
        "dataset_path": str(DATASET_PATH.name),
        "total_samples": len(samples),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "features_used": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
        },
        "confusion_matrix": {
            "true_negatives": cm[0][0] if len(cm) > 0 and len(cm[0]) > 0 else 0,
            "false_positives": cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0,
            "false_negatives": cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0,
            "true_positives": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0,
        },
    }

    # Save model and metrics
    joblib.dump(model, MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return model, metrics


_CACHED_MODEL = None
_CACHED_METRICS = None


def get_detection_model():
    """Returns the trained ML model, loading from disk or training if missing."""
    global _CACHED_MODEL
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL

    if MODEL_PATH.exists():
        try:
            _CACHED_MODEL = joblib.load(MODEL_PATH)
            return _CACHED_MODEL
        except Exception:
            pass

    _CACHED_MODEL, _ = train_and_evaluate_model()
    return _CACHED_MODEL


def get_model_metrics() -> dict:
    """Returns the evaluated model performance metrics."""
    global _CACHED_METRICS
    if _CACHED_METRICS is not None:
        return _CACHED_METRICS

    if METRICS_PATH.exists():
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                _CACHED_METRICS = json.load(f)
                return _CACHED_METRICS
        except Exception:
            pass

    _, _CACHED_METRICS = train_and_evaluate_model()
    return _CACHED_METRICS


# Pre-warm model and load metrics on startup
try:
    get_detection_model()
    get_model_metrics()
except Exception:
    pass


# ---------------------------------------------------------------------------
# Google Safe Browsing API Integration
# ---------------------------------------------------------------------------
def check_google_safe_browsing(url: str) -> dict:
    """
    Queries Google Safe Browsing Lookup API (v4) for known threat records.
    API key is read from GOOGLE_SAFE_BROWSING_API_KEY environment variable.

    Returns:
    {
        "checked": bool,
        "is_threat": bool,
        "threat_types": list,
        "message": str
    }
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        return {
            "checked": False,
            "is_threat": False,
            "threat_types": [],
            "message": "Google Safe Browsing API key not configured (set GOOGLE_SAFE_BROWSING_API_KEY).",
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "ai-sentinel",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=4)
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            if matches:
                threats = list({m.get("threatType", "THREAT") for m in matches})
                return {
                    "checked": True,
                    "is_threat": True,
                    "threat_types": threats,
                    "message": f"URL identified as malicious by Google Safe Browsing: {', '.join(threats)}.",
                }
            return {
                "checked": True,
                "is_threat": False,
                "threat_types": [],
                "message": "URL not found in Google Safe Browsing blacklist.",
            }
        else:
            return {
                "checked": False,
                "is_threat": False,
                "threat_types": [],
                "message": f"Safe Browsing API returned status {response.status_code}.",
            }
    except Exception as e:
        return {
            "checked": False,
            "is_threat": False,
            "threat_types": [],
            "message": f"Google Safe Browsing check error: {str(e)}",
        }


# ---------------------------------------------------------------------------
# Integrated Detection Engine
# ---------------------------------------------------------------------------
def detect_phishing(url: str) -> dict:
    """
    Full AI-powered phishing detection pipeline:
    1. Extract structural and lexical URL features.
    2. Query Google Safe Browsing API for known malicious intelligence.
    3. Run Machine Learning classifier on extracted feature vector.
    4. Fuse signals to output final risk score (0-100), safety status, and actionable recommendations.
    """
    # Step 1: Feature Extraction
    features = extract_url_features(url)

    # Step 2: Google Safe Browsing Check
    gsb_result = check_google_safe_browsing(url)

    # Step 3: Machine Learning Model Inference
    model = get_detection_model()
    feature_vector = [feature_dict_to_vector(features)]
    ml_probabilities = model.predict_proba(feature_vector)[0]
    # Probability of class 1 (phishing)
    if hasattr(model, "classes_"):
        classes = list(model.classes_)
        if 1 in classes:
            idx = classes.index(1)
            phishing_prob = float(ml_probabilities[idx])
        else:
            phishing_prob = float(ml_probabilities[0])
    else:
        phishing_prob = float(ml_probabilities[1]) if len(ml_probabilities) > 1 else float(ml_probabilities[0])

    ml_risk_score = round(phishing_prob * 100)

    # Step 4: Decision Fusion & Reason Building
    reasons = []

    # Add explicit feature reasons
    if features["has_ip_address"]:
        reasons.append("Direct IP address used as hostname")
    if not features["is_https"]:
        reasons.append("Unencrypted connection (HTTP without SSL)")
    if features.get("matched_keywords"):
        reasons.append(f"Suspicious phishing keywords detected: {', '.join(features['matched_keywords'])}")
    if features["suspicious_tld"]:
        reasons.append("High-risk top-level domain (TLD) pattern")
    if features["has_at_symbol"]:
        reasons.append("'@' symbol used for URL redirection/spoofing")
    if features.get("has_double_slash_redirect"):
        reasons.append("Double slash redirect sequence in URL path")
    if features["subdomain_count"] >= 3:
        reasons.append(f"Excessive subdomains ({features['subdomain_count']})")
    if features["hyphen_count_domain"] >= 3:
        reasons.append(f"Excessive hyphens in hostname ({features['hyphen_count_domain']})")

    # If Google Safe Browsing flagged it, it's definitively High Risk
    if gsb_result.get("is_threat"):
        risk_score = 100
        category = "High Risk"
        safety_status = "Malicious"
        threat_msg = gsb_result.get("message") or "Identified by Google Safe Browsing"
        reasons.insert(0, threat_msg)
        explanation = f"High Risk ({risk_score}/100): Confirmed malicious threat by Google Safe Browsing ({', '.join(gsb_result.get('threat_types', ['THREAT']))}). Immediate phishing hazard."
        recommendation = "CRITICAL: Website flagged by Google Safe Browsing! Do not visit or enter any credentials."
    else:
        # Evaluate ML prediction & heuristic factors
        risk_score = max(0, min(100, int(ml_risk_score)))

        # Categorize results according to requirements:
        # 0–30: Low Risk
        # 31–60: Medium Risk
        # 61–100: High Risk
        if risk_score <= 30:
            category = "Low Risk"
            safety_status = "Safe"
            recommendation = "Website appears safe based on AI evaluation and heuristic analysis. Continue safe browsing."
            if not reasons:
                explanation = f"Low Risk ({risk_score}/100): AI Random Forest model verified clean URL structure. No phishing patterns detected."
            else:
                explanation = f"Low Risk ({risk_score}/100): AI Random Forest model evaluated URL as low risk despite minor factors ({'; '.join(reasons)})."
        elif risk_score <= 60:
            category = "Medium Risk"
            safety_status = "Suspicious"
            recommendation = "Exercise caution. Verify the domain authenticity before proceeding or entering sensitive information."
            if not reasons:
                explanation = f"Medium Risk ({risk_score}/100): AI Random Forest model detected moderate anomalies in URL structure."
            else:
                explanation = f"Medium Risk ({risk_score}/100): AI Random Forest model flagged potential risk indicators: {'; '.join(reasons)}."
        else:
            category = "High Risk"
            safety_status = "Malicious"
            recommendation = "High risk detected by AI detection model! Do not visit this site or submit any information."
            if not reasons:
                explanation = f"High Risk ({risk_score}/100): AI Random Forest model identified strong phishing probability patterns."
            else:
                explanation = f"High Risk ({risk_score}/100): AI Random Forest model identified critical phishing indicators: {'; '.join(reasons)}."

    detection_reason = "; ".join(reasons) if reasons else "No significant phishing indicators detected by AI model."

    # Clean feature dict for response (exclude matched_keywords list from numeric dict if desired)
    serializable_features = {k: v for k, v in features.items() if k != "matched_keywords"}

    # Generate AI-powered threat explanation grounded strictly in detected evidence
    threat_explanation = generate_threat_explanation(
        url=url,
        risk_score=risk_score,
        category=category,
        features=features,
        safe_browsing=gsb_result,
    )

    # Execute Step 7 RAG Pipeline: Retrieve from vector database & generate augmented explanation
    rag_result = generate_rag_explanation(
        url=url,
        risk_score=risk_score,
        category=category,
        features=features,
        safe_browsing=gsb_result,
        top_k=3,
    )

    return {
        "url": url,
        "risk_score": risk_score,
        "category": category,
        "safety_status": safety_status,
        "explanation": rag_result["ai_generated_explanation"],
        "ai_generated_explanation": rag_result["ai_generated_explanation"],
        "rag_summary": rag_result["rag_summary"],
        "retrieved_security_info": rag_result["retrieved_security_info"],
        "detected_indicators": rag_result["detected_indicators"],
        "safety_recommendation": rag_result["safety_recommendation"],
        "classification_reason": threat_explanation["classification_reason"],
        "user_risks": threat_explanation["user_risks"],
        "recommendations": threat_explanation["recommendations"],
        "threat_explanation": threat_explanation,
        "detection_reason": detection_reason,
        "recommendation": rag_result["safety_recommendation"],
        "features": serializable_features,
        "safe_browsing": {
            "checked": gsb_result.get("checked", False),
            "is_threat": gsb_result.get("is_threat", False),
            "threat_types": gsb_result.get("threat_types", []),
            "message": gsb_result.get("message", ""),
        },
    }
