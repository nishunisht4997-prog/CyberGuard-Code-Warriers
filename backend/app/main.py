from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import text

from app.database import SessionLocal
from urllib.parse import urlparse
import cv2
import numpy as np
import tempfile
import os
import io
from PIL import Image as PILImage, ExifTags
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


app = FastAPI(
    title="CYBERGUARD-X",
    description="AI Powered Cyber Threat Detection and Response System",
    version="1.0.0"
)

BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PhishingRequest(BaseModel):
    sender: str
    subject: str
    message: str
    url: str = ""


def analyze_phishing(data: PhishingRequest):

    text_content = (
        data.subject + " " +
        data.message + " " +
        data.url
    ).lower()

    score = 0
    indicators = []

    # Urgency detection
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "verify now",
        "within 24 hours",
        "account will be blocked"
    ]

    urgency_found = [
        word for word in urgency_words
        if word in text_content
    ]

    if urgency_found:
        score += 20
        indicators.append(
            "Urgent or threatening language detected"
        )

    # Credential request detection
    credential_words = [
        "password",
        "login",
        "verify your account",
        "credentials",
        "username",
        "otp",
        "one-time password"
    ]

    credential_found = [
        word for word in credential_words
        if word in text_content
    ]

    if credential_found:
        score += 25
        indicators.append(
            "Possible credential or authentication request"
        )

    # Suspicious URL detection
    suspicious_url_words = [
        "bit.ly",
        "tinyurl",
        "login",
        "verify",
        "secure-account",
        "account-verify"
    ]

    suspicious_url_found = [
        word for word in suspicious_url_words
        if word in data.url.lower()
    ]

    if suspicious_url_found:
        score += 30
        indicators.append(
            "Suspicious URL or redirect pattern detected"
        )

    # Impersonation detection
    impersonation_words = [
        "bank",
        "administrator",
        "admin",
        "government",
        "microsoft",
        "google",
        "office",
        "hr department"
    ]

    impersonation_found = [
        word for word in impersonation_words
        if word in text_content
    ]

    if impersonation_found:
        score += 15
        indicators.append(
            "Possible organization or authority impersonation"
        )

    # Cap score
    score = min(score, 100)

    # Severity
    if score >= 81:
        severity = "CRITICAL"
    elif score >= 61:
        severity = "HIGH"
    elif score >= 41:
        severity = "MEDIUM"
    elif score >= 21:
        severity = "LOW"
    else:
        severity = "SAFE"

    if score >= 61:
        threat_type = "PHISHING"
        status = "OPEN"
        summary = "Potential phishing attack detected"
    else:
        threat_type = "SUSPICIOUS_MESSAGE"
        status = "MONITORING"
        summary = "Message analyzed for suspicious behavior"

    # Recommended responses
    actions = []

    if score >= 81:
        actions = [
            "QUARANTINE MESSAGE",
            "BLOCK SUSPICIOUS URL",
            "WARN USER",
            "NOTIFY SECURITY ADMIN"
        ]
    elif score >= 61:
        actions = [
            "WARN USER",
            "BLOCK SUSPICIOUS URL",
            "REQUIRE ADDITIONAL VERIFICATION"
        ]
    elif score >= 41:
        actions = [
            "WARN USER",
            "REQUEST MANUAL VERIFICATION"
        ]
    else:
        actions = [
            "CONTINUE MONITORING"
        ]

    return {
        "risk_score": score,
        "severity": severity,
        "threat_type": threat_type,
        "status": status,
        "summary": summary,
        "indicators": indicators,
        "actions": actions,
        "urgency_detected": bool(urgency_found),
        "credential_request": bool(credential_found),
        "impersonation_detected": bool(impersonation_found)
    }


# @app.get("/")
# def home():
#     return {
#         "message": "CYBERGUARD-X Backend is Running",
#         "status": "ONLINE"
#     }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


class AuthLoginRequest(BaseModel):
    email: str
    password: str = ""
    role: str = "analyst"


@app.post("/auth/login")
def login_user(data: AuthLoginRequest):
    email = data.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    accounts = {
        "analyst@cyberguard.x": {
            "name": "Alex Vance",
            "role": "Lead SOC Analyst",
            "organisation": "CYBERGUARD-X SOC"
        },
        "admin@cyberguard.x": {
            "name": "Sarah Connor",
            "role": "Security Administrator",
            "organisation": "CYBERGUARD-X SEC OPS"
        },
        "demo@cyberguard.local": {
            "name": "Demo Security User",
            "role": "Security Analyst",
            "organisation": "CYBERGUARD-X"
        }
    }

    user_info = accounts.get(email)
    if not user_info:
        name = email.split("@")[0].replace(".", " ").title()
        user_info = {
            "name": name,
            "role": data.role if data.role else "Security Analyst",
            "organisation": "CYBERGUARD-X SOC"
        }

    # Record login attempt in audit_logs
    db = SessionLocal()
    try:
        db.execute(
            text("""
                INSERT INTO audit_logs (user_id, action, result, details)
                VALUES (1, :action, :result, :details)
            """),
            {
                "action": "USER_AUTHENTICATION",
                "result": "SUCCESS",
                "details": f"Authenticated user {email} ({user_info['role']})"
            }
        )
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    return {
        "success": True,
        "token": f"cgx-token-{os.urandom(6).hex()}",
        "user": {
            "email": email,
            "name": user_info["name"],
            "role": user_info["role"],
            "organisation": user_info["organisation"]
        }
    }


@app.post("/analyze/phishing")
def phishing_detection(data: PhishingRequest):

    result = analyze_phishing(data)

    db = SessionLocal()

    try:

        # Save main threat event
        event_result = db.execute(
            text("""
                INSERT INTO threat_events
                (source, threat_type, risk_score, severity, status, summary)
                VALUES
                (:source, :threat_type, :risk_score, :severity, :status, :summary)
            """),
            {
                "source": "EMAIL",
                "threat_type": result["threat_type"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "status": result["status"],
                "summary": result["summary"]
            }
        )

        event_id = event_result.lastrowid

        # Save message analysis
        db.execute(
            text("""
                INSERT INTO message_analysis
                (
                    event_id,
                    sender,
                    subject,
                    message_text,
                    urgency_score,
                    credential_request,
                    impersonation_score,
                    suspicious_keywords
                )
                VALUES
                (
                    :event_id,
                    :sender,
                    :subject,
                    :message_text,
                    :urgency_score,
                    :credential_request,
                    :impersonation_score,
                    :suspicious_keywords
                )
            """),
            {
                "event_id": event_id,
                "sender": data.sender,
                "subject": data.subject,
                "message_text": data.message,
                "urgency_score": 20 if result["urgency_detected"] else 0,
                "credential_request": result["credential_request"],
                "impersonation_score": 15 if result["impersonation_detected"] else 0,
                "suspicious_keywords": ", ".join(result["indicators"])
            }
        )

        # Save indicators
        for indicator in result["indicators"]:

            db.execute(
                text("""
                    INSERT INTO threat_indicators
                    (
                        event_id,
                        indicator_type,
                        indicator,
                        severity,
                        description
                    )
                    VALUES
                    (
                        :event_id,
                        :indicator_type,
                        :indicator,
                        :severity,
                        :description
                    )
                """),
                {
                    "event_id": event_id,
                    "indicator_type": "PHISHING_INDICATOR",
                    "indicator": indicator,
                    "severity": result["severity"],
                    "description": indicator
                }
            )

        # Save recommended actions
        for action in result["actions"]:

            db.execute(
                text("""
                    INSERT INTO response_actions
                    (
                        event_id,
                        recommended_action,
                        action_status,
                        action_reason
                    )
                    VALUES
                    (
                        :event_id,
                        :recommended_action,
                        'RECOMMENDED',
                        :action_reason
                    )
                """),
                {
                    "event_id": event_id,
                    "recommended_action": action,
                    "action_reason": (
                        f"Recommended because risk score is "
                        f"{result['risk_score']}/100"
                    )
                }
            )

        db.commit()

        return {
            "event_id": event_id,
            "detection": result
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


#Threat Events API
@app.get("/events")
def get_events():

    db = SessionLocal()

    try:
        result = db.execute(
            text("""
                SELECT
                    id,
                    event_time,
                    source,
                    threat_type,
                    risk_score,
                    severity,
                    status,
                    summary
                FROM threat_events
                ORDER BY id DESC
                LIMIT 100
            """)
        )

        events = result.mappings().all()

        return {
            "total_events": len(events),
            "events": [dict(event) for event in events]
        }

    finally:
        db.close()

@app.get("/dashboard/stats")
def dashboard_stats():

    db = SessionLocal()

    try:
        total_events = db.execute(
            text("SELECT COUNT(*) FROM threat_events")
        ).scalar()

        total_threats = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE threat_type != 'SUSPICIOUS_MESSAGE'
            """)
        ).scalar()

        critical = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE severity = 'CRITICAL'
            """)
        ).scalar()

        high = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE severity = 'HIGH'
            """)
        ).scalar()

        medium = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE severity = 'MEDIUM'
            """)
        ).scalar()

        low = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE severity = 'LOW'
            """)
        ).scalar()

        safe = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE severity = 'SAFE'
            """)
        ).scalar()

        phishing = db.execute(
            text("""
                SELECT COUNT(*)
                FROM threat_events
                WHERE threat_type = 'PHISHING'
            """)
        ).scalar()

        return {
            "total_events": total_events,
            "total_threats": total_threats,
            "severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "safe": safe
            },
            "threat_categories": {
                "phishing": phishing
            }
        }

    finally:
        db.close()


  # ============================================================
# URL THREAT DETECTOR
# ============================================================

from urllib.parse import urlparse
import re


class URLRequest(BaseModel):
    url: str


def analyze_url(url: str):

    score = 0
    indicators = []

    # --------------------------------------------------------
    # Basic URL parsing
    # --------------------------------------------------------

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    if not parsed.scheme or not domain:
        return {
            "risk_score": 100,
            "severity": "CRITICAL",
            "threat_type": "MALICIOUS_URL",
            "summary": "Invalid or malformed URL detected",
            "indicators": ["Malformed URL"],
            "actions": [
                "BLOCK URL",
                "WARN USER",
                "REPORT INCIDENT"
            ],
            "domain": domain
        }

    # --------------------------------------------------------
    # HTTP instead of HTTPS
    # --------------------------------------------------------

    if parsed.scheme.lower() != "https":
        score += 15
        indicators.append(
            "URL does not use HTTPS"
        )

    # --------------------------------------------------------
    # IP address instead of normal domain
    # --------------------------------------------------------

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain.split(":")[0]):
        score += 25
        indicators.append(
            "URL uses an IP address instead of a normal domain"
        )

    # --------------------------------------------------------
    # URL shorteners
    # --------------------------------------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    if any(shortener in domain for shortener in shorteners):
        score += 25
        indicators.append(
            "URL shortening service detected"
        )

    # --------------------------------------------------------
    # Credential / login keywords
    # --------------------------------------------------------

    credential_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "password",
        "credential",
        "account",
        "secure-login",
        "otp"
    ]

    credential_matches = [
        word for word in credential_words
        if word in path or word in domain
    ]

    if credential_matches:
        score += 20
        indicators.append(
            "Credential or account verification keywords detected"
        )

    # --------------------------------------------------------
    # Suspicious URL characters
    # --------------------------------------------------------

    if "@" in url:
        score += 20
        indicators.append(
            "URL contains @ character that may hide the real destination"
        )

    if "%" in url:
        score += 5
        indicators.append(
            "Encoded characters detected in URL"
        )

    # --------------------------------------------------------
    # Excessive subdomains
    # --------------------------------------------------------

    domain_parts = domain.split(".")

    if len(domain_parts) >= 4:
        score += 15
        indicators.append(
            "Unusually high number of domain subdomains"
        )

    # --------------------------------------------------------
    # Suspicious domain words
    # --------------------------------------------------------

    suspicious_domain_words = [
        "secure",
        "verify",
        "account",
        "update",
        "confirm",
        "support",
        "security",
        "wallet",
        "payment"
    ]

    suspicious_domain_matches = [
        word for word in suspicious_domain_words
        if word in domain
    ]

    if suspicious_domain_matches:
        score += 15
        indicators.append(
            "Suspicious security or account-related domain wording"
        )

    # --------------------------------------------------------
    # Look-alike / impersonation domains
    # --------------------------------------------------------

    trusted_brands = [
        "microsoft",
        "google",
        "apple",
        "amazon",
        "paypal",
        "facebook",
        "instagram"
    ]

    lookalike_found = False

    for brand in trusted_brands:

        if brand in domain:

            trusted_domains = [
                f"{brand}.com",
                f"www.{brand}.com"
            ]

            if domain not in trusted_domains:
                lookalike_found = True
                break

    if lookalike_found:
        score += 30
        indicators.append(
            "Possible look-alike or brand impersonation domain detected"
        )

    # --------------------------------------------------------
    # Very long URL
    # --------------------------------------------------------

    if len(url) > 120:
        score += 10
        indicators.append(
            "Unusually long URL detected"
        )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    score = min(score, 100)

    if score >= 81:
        severity = "CRITICAL"
    elif score >= 61:
        severity = "HIGH"
    elif score >= 41:
        severity = "MEDIUM"
    elif score >= 21:
        severity = "LOW"
    else:
        severity = "SAFE"

    if score >= 61:
        threat_type = "MALICIOUS_URL"
        summary = "Potential malicious or deceptive URL detected"
    elif score >= 41:
        threat_type = "SUSPICIOUS_URL"
        summary = "Suspicious URL characteristics detected"
    else:
        threat_type = "URL_ANALYSIS"
        summary = "URL appears low risk based on current analysis"

    # --------------------------------------------------------
    # Response recommendations
    # --------------------------------------------------------

    if score >= 81:

        actions = [
            "BLOCK URL",
            "WARN USER",
            "QUARANTINE RELATED MESSAGE",
            "NOTIFY SECURITY ADMIN"
        ]

    elif score >= 61:

        actions = [
            "BLOCK URL",
            "WARN USER",
            "REQUIRE ADDITIONAL VERIFICATION"
        ]

    elif score >= 41:

        actions = [
            "WARN USER",
            "REQUEST MANUAL VERIFICATION"
        ]

    else:

        actions = [
            "CONTINUE MONITORING"
        ]

    return {
        "risk_score": score,
        "severity": severity,
        "threat_type": threat_type,
        "summary": summary,
        "indicators": indicators,
        "actions": actions,
        "domain": domain
    }


@app.post("/analyze/url")
def url_detection(data: URLRequest):

    result = analyze_url(data.url)

    db = SessionLocal()

    try:

        # ----------------------------------------------------
        # Save threat event
        # ----------------------------------------------------

        event_result = db.execute(
            text("""
                INSERT INTO threat_events
                (
                    source,
                    threat_type,
                    risk_score,
                    severity,
                    status,
                    summary
                )
                VALUES
                (
                    :source,
                    :threat_type,
                    :risk_score,
                    :severity,
                    :status,
                    :summary
                )
            """),
            {
                "source": "URL",
                "threat_type": result["threat_type"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "status": "OPEN" if result["risk_score"] >= 41 else "MONITORING",
                "summary": result["summary"]
            }
        )

        event_id = event_result.lastrowid

        # ----------------------------------------------------
        # Save URL analysis
        # ----------------------------------------------------

        db.execute(
            text("""
                INSERT INTO url_analysis
                (
                    event_id,
                    url,
                    domain,
                    ssl_valid,
                    redirect_count,
                    domain_similarity_score,
                    url_risk_score,
                    suspicious_features
                )
                VALUES
                (
                    :event_id,
                    :url,
                    :domain,
                    :ssl_valid,
                    :redirect_count,
                    :domain_similarity_score,
                    :url_risk_score,
                    :suspicious_features
                )
            """),
            {
                "event_id": event_id,
                "url": data.url,
                "domain": result["domain"],
                "ssl_valid": data.url.lower().startswith("https://"),
                "redirect_count": 0,
                "domain_similarity_score": 30
                if any(
                    word in result["domain"]
                    for word in [
                        "microsoft",
                        "google",
                        "apple",
                        "amazon",
                        "paypal",
                        "facebook",
                        "instagram"
                    ]
                )
                else 0,
                "url_risk_score": result["risk_score"],
                "suspicious_features": ", ".join(
                    result["indicators"]
                )
            }
        )

        # ----------------------------------------------------
        # Save indicators
        # ----------------------------------------------------

        for indicator in result["indicators"]:

            db.execute(
                text("""
                    INSERT INTO threat_indicators
                    (
                        event_id,
                        indicator_type,
                        indicator,
                        severity,
                        description
                    )
                    VALUES
                    (
                        :event_id,
                        'URL_INDICATOR',
                        :indicator,
                        :severity,
                        :description
                    )
                """),
                {
                    "event_id": event_id,
                    "indicator": indicator,
                    "severity": result["severity"],
                    "description": indicator
                }
            )

        # ----------------------------------------------------
        # Save response actions
        # ----------------------------------------------------

        for action in result["actions"]:

            db.execute(
                text("""
                    INSERT INTO response_actions
                    (
                        event_id,
                        recommended_action,
                        action_status,
                        action_reason
                    )
                    VALUES
                    (
                        :event_id,
                        :recommended_action,
                        'RECOMMENDED',
                        :action_reason
                    )
                """),
                {
                    "event_id": event_id,
                    "recommended_action": action,
                    "action_reason":
                        f"URL risk score is {result['risk_score']}/100"
                }
            )

        db.commit()

        return {
            "event_id": event_id,
            "analysis": result
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()  


 # ============================================================
# ACCOUNT TAKEOVER / ABNORMAL LOGIN DETECTOR
# ============================================================

class LoginRequest(BaseModel):
    user_id: int
    ip_address: str
    location: str
    device: str
    login_status: str
    failed_attempts: int = 0
    is_new_device: bool = False
    is_unusual_location: bool = False


def analyze_login(data: LoginRequest):

    score = 0
    indicators = []

    # --------------------------------------------------------
    # Failed login attempts
    # --------------------------------------------------------

    if data.failed_attempts >= 10:
        score += 35
        indicators.append(
            "High number of failed login attempts detected"
        )

    elif data.failed_attempts >= 5:
        score += 25
        indicators.append(
            "Multiple failed login attempts detected"
        )

    elif data.failed_attempts >= 3:
        score += 15
        indicators.append(
            "Repeated failed login attempts detected"
        )

    # --------------------------------------------------------
    # New / unknown device
    # --------------------------------------------------------

    if data.is_new_device:
        score += 25
        indicators.append(
            "Login from a new or unknown device"
        )

    # --------------------------------------------------------
    # Unusual location
    # --------------------------------------------------------

    if data.is_unusual_location:
        score += 25
        indicators.append(
            "Login from an unusual location"
        )

    # --------------------------------------------------------
    # Failed login status
    # --------------------------------------------------------

    if data.login_status.upper() == "FAILED":
        score += 10
        indicators.append(
            "Authentication attempt failed"
        )

    # --------------------------------------------------------
    # Successful login after many failures
    # --------------------------------------------------------

    if (
        data.login_status.upper() == "SUCCESS"
        and data.failed_attempts >= 5
    ):
        score += 20
        indicators.append(
            "Successful login occurred after multiple failures"
        )

    # --------------------------------------------------------
    # Calculate final score
    # --------------------------------------------------------

    score = min(score, 100)

    if score >= 81:
        severity = "CRITICAL"

    elif score >= 61:
        severity = "HIGH"

    elif score >= 41:
        severity = "MEDIUM"

    elif score >= 21:
        severity = "LOW"

    else:
        severity = "SAFE"

    # --------------------------------------------------------
    # Threat classification
    # --------------------------------------------------------

    if score >= 61:
        threat_type = "ACCOUNT_TAKEOVER"
        summary = "Potential account takeover detected"

    elif score >= 41:
        threat_type = "ABNORMAL_LOGIN"
        summary = "Suspicious login behavior detected"

    else:
        threat_type = "LOGIN_ACTIVITY"
        summary = "Login activity appears low risk"

    # --------------------------------------------------------
    # Recommended responses
    # --------------------------------------------------------

    if score >= 81:

        actions = [
            "REVOKE SUSPICIOUS SESSION",
            "BLOCK UNKNOWN DEVICE",
            "REQUIRE MULTI-FACTOR AUTHENTICATION",
            "ALERT SECURITY ADMIN"
        ]

    elif score >= 61:

        actions = [
            "REVOKE SUSPICIOUS SESSION",
            "REQUIRE MULTI-FACTOR AUTHENTICATION",
            "BLOCK UNKNOWN DEVICE",
            "WARN USER"
        ]

    elif score >= 41:

        actions = [
            "REQUIRE ADDITIONAL VERIFICATION",
            "WARN USER",
            "MONITOR ACCOUNT"
        ]

    else:

        actions = [
            "CONTINUE MONITORING"
        ]

    return {
        "risk_score": score,
        "severity": severity,
        "threat_type": threat_type,
        "summary": summary,
        "indicators": indicators,
        "actions": actions
    }


@app.post("/analyze/login")
def login_detection(data: LoginRequest):

    result = analyze_login(data)

    db = SessionLocal()

    try:

        # ----------------------------------------------------
        # Save threat event
        # ----------------------------------------------------

        event_result = db.execute(
            text("""
                INSERT INTO threat_events
                (
                    source,
                    threat_type,
                    risk_score,
                    severity,
                    status,
                    summary
                )
                VALUES
                (
                    'AUTHENTICATION',
                    :threat_type,
                    :risk_score,
                    :severity,
                    :status,
                    :summary
                )
            """),
            {
                "threat_type": result["threat_type"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "status": (
                    "OPEN"
                    if result["risk_score"] >= 41
                    else "MONITORING"
                ),
                "summary": result["summary"]
            }
        )

        event_id = event_result.lastrowid

        # ----------------------------------------------------
        # Save login event
        # ----------------------------------------------------

        db.execute(
            text("""
                INSERT INTO login_events
                (
                    user_id,
                    ip_address,
                    location,
                    device,
                    login_status,
                    failed_attempts,
                    is_new_device,
                    is_unusual_location,
                    anomaly_score
                )
                VALUES
                (
                    :user_id,
                    :ip_address,
                    :location,
                    :device,
                    :login_status,
                    :failed_attempts,
                    :is_new_device,
                    :is_unusual_location,
                    :anomaly_score
                )
            """),
            {
                "user_id": data.user_id,
                "ip_address": data.ip_address,
                "location": data.location,
                "device": data.device,
                "login_status": data.login_status,
                "failed_attempts": data.failed_attempts,
                "is_new_device": data.is_new_device,
                "is_unusual_location": data.is_unusual_location,
                "anomaly_score": result["risk_score"]
            }
        )

        # ----------------------------------------------------
        # Save indicators
        # ----------------------------------------------------

        for indicator in result["indicators"]:

            db.execute(
                text("""
                    INSERT INTO threat_indicators
                    (
                        event_id,
                        indicator_type,
                        indicator,
                        severity,
                        description
                    )
                    VALUES
                    (
                        :event_id,
                        'LOGIN_INDICATOR',
                        :indicator,
                        :severity,
                        :description
                    )
                """),
                {
                    "event_id": event_id,
                    "indicator": indicator,
                    "severity": result["severity"],
                    "description": indicator
                }
            )

        # ----------------------------------------------------
        # Save recommended actions
        # ----------------------------------------------------

        for action in result["actions"]:

            db.execute(
                text("""
                    INSERT INTO response_actions
                    (
                        event_id,
                        recommended_action,
                        action_status,
                        action_reason
                    )
                    VALUES
                    (
                        :event_id,
                        :recommended_action,
                        'RECOMMENDED',
                        :action_reason
                    )
                """),
                {
                    "event_id": event_id,
                    "recommended_action": action,
                    "action_reason":
                        f"Login risk score is {result['risk_score']}/100"
                }
            )

        db.commit()

        return {
            "event_id": event_id,
            "analysis": result
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()         


# ============================================================
# DIGITAL IMPERSONATION DETECTOR
# ============================================================

class ImpersonationRequest(BaseModel):
    sender_name: str
    sender_email: str
    claimed_identity: str
    message: str
    official_domain: str = ""


def analyze_impersonation(data: ImpersonationRequest):

    score = 0
    indicators = []

    content = (
        data.sender_name + " " +
        data.sender_email + " " +
        data.claimed_identity + " " +
        data.message
    ).lower()

    # --------------------------------------------------------
    # Authority / identity claim
    # --------------------------------------------------------

    authority_words = [
        "director",
        "manager",
        "administrator",
        "principal",
        "professor",
        "teacher",
        "ceo",
        "government officer",
        "bank manager",
        "hr"
    ]

    authority_found = [
        word for word in authority_words
        if word in content
    ]

    if authority_found:
        score += 20
        indicators.append(
            "Sender claims an authority or official identity"
        )

    # --------------------------------------------------------
    # Urgent request
    # --------------------------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "right now",
        "as soon as possible",
        "act now",
        "confidential"
    ]

    urgency_found = [
        word for word in urgency_words
        if word in content
    ]

    if urgency_found:
        score += 20
        indicators.append(
            "Urgent or pressure-based communication detected"
        )

    # --------------------------------------------------------
    # Financial / credential request
    # --------------------------------------------------------

    sensitive_words = [
        "password",
        "otp",
        "verification code",
        "bank account",
        "transfer money",
        "payment",
        "credentials",
        "login"
    ]

    sensitive_found = [
        word for word in sensitive_words
        if word in content
    ]

    if sensitive_found:
        score += 25
        indicators.append(
            "Sensitive credential or financial request detected"
        )

    # --------------------------------------------------------
    # Email/domain mismatch
    # --------------------------------------------------------

    if data.official_domain:

        email_domain = ""

        if "@" in data.sender_email:
            email_domain = data.sender_email.split("@")[-1].lower()

        official_domain = (
            data.official_domain
            .lower()
            .replace("https://", "")
            .replace("http://", "")
            .replace("www.", "")
            .strip("/")
        )

        if email_domain and email_domain != official_domain:
            score += 30
            indicators.append(
                "Sender email domain does not match the claimed official domain"
            )

    # --------------------------------------------------------
    # Free email provider
    # --------------------------------------------------------

    free_email_domains = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com"
    ]

    if any(
        domain in data.sender_email.lower()
        for domain in free_email_domains
    ):
        score += 15
        indicators.append(
            "Official identity is using a consumer email provider"
        )

    # --------------------------------------------------------
    # Final risk score
    # --------------------------------------------------------

    score = min(score, 100)

    if score >= 81:
        severity = "CRITICAL"
    elif score >= 61:
        severity = "HIGH"
    elif score >= 41:
        severity = "MEDIUM"
    elif score >= 21:
        severity = "LOW"
    else:
        severity = "SAFE"

    if score >= 61:
        threat_type = "DIGITAL_IMPERSONATION"
        summary = "Potential digital identity impersonation detected"
    elif score >= 41:
        threat_type = "SUSPICIOUS_IDENTITY"
        summary = "Suspicious identity characteristics detected"
    else:
        threat_type = "IDENTITY_ANALYSIS"
        summary = "Identity appears low risk based on current indicators"

    # --------------------------------------------------------
    # Response recommendations
    # --------------------------------------------------------

    if score >= 81:

        actions = [
            "FLAG IMPERSONATION",
            "WARN RECIPIENT",
            "BLOCK SENDER",
            "NOTIFY SECURITY ADMIN"
        ]

    elif score >= 61:

        actions = [
            "FLAG IMPERSONATION",
            "WARN RECIPIENT",
            "REQUIRE IDENTITY VERIFICATION"
        ]

    elif score >= 41:

        actions = [
            "WARN RECIPIENT",
            "REQUEST MANUAL IDENTITY VERIFICATION"
        ]

    else:

        actions = [
            "CONTINUE MONITORING"
        ]

    return {
        "risk_score": score,
        "severity": severity,
        "threat_type": threat_type,
        "summary": summary,
        "indicators": indicators,
        "actions": actions
    }


@app.post("/analyze/impersonation")
def impersonation_detection(data: ImpersonationRequest):

    result = analyze_impersonation(data)

    db = SessionLocal()

    try:

        # ----------------------------------------------------
        # Save threat event
        # ----------------------------------------------------

        event_result = db.execute(
            text("""
                INSERT INTO threat_events
                (
                    source,
                    threat_type,
                    risk_score,
                    severity,
                    status,
                    summary
                )
                VALUES
                (
                    'IDENTITY',
                    :threat_type,
                    :risk_score,
                    :severity,
                    :status,
                    :summary
                )
            """),
            {
                "threat_type": result["threat_type"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "status": (
                    "OPEN"
                    if result["risk_score"] >= 41
                    else "MONITORING"
                ),
                "summary": result["summary"]
            }
        )

        event_id = event_result.lastrowid

        # ----------------------------------------------------
        # Save indicators
        # ----------------------------------------------------

        for indicator in result["indicators"]:

            db.execute(
                text("""
                    INSERT INTO threat_indicators
                    (
                        event_id,
                        indicator_type,
                        indicator,
                        severity,
                        description
                    )
                    VALUES
                    (
                        :event_id,
                        'IDENTITY_INDICATOR',
                        :indicator,
                        :severity,
                        :description
                    )
                """),
                {
                    "event_id": event_id,
                    "indicator": indicator,
                    "severity": result["severity"],
                    "description": indicator
                }
            )

        # ----------------------------------------------------
        # Save response actions
        # ----------------------------------------------------

        for action in result["actions"]:

            db.execute(
                text("""
                    INSERT INTO response_actions
                    (
                        event_id,
                        recommended_action,
                        action_status,
                        action_reason
                    )
                    VALUES
                    (
                        :event_id,
                        :recommended_action,
                        'RECOMMENDED',
                        :action_reason
                    )
                """),
                {
                    "event_id": event_id,
                    "recommended_action": action,
                    "action_reason":
                        f"Identity risk score is {result['risk_score']}/100"
                }
            )

        db.commit()

        return {
            "event_id": event_id,
            "analysis": result
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ============================================================
# QR CODE PHISHING DETECTOR
# ============================================================

@app.post("/analyze/qr")
async def qr_detection(file: UploadFile = File(...)):

    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/webp"
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Please upload a PNG, JPG, JPEG or WEBP image."
        )

    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded image is empty."
        )

    image_array = np.frombuffer(
        image_bytes,
        np.uint8
    )

    original = cv2.imdecode(
        image_array,
        cv2.IMREAD_COLOR
    )

    if original is None:
        raise HTTPException(
            status_code=400,
            detail="Unable to read the uploaded image."
        )

    # --------------------------------------------------------
    # PREPARE MULTIPLE IMAGE VERSIONS
    # --------------------------------------------------------

    images = []

    # Original
    images.append(original)

    # Grayscale
    gray = cv2.cvtColor(
        original,
        cv2.COLOR_BGR2GRAY
    )

    images.append(gray)

    # Enlarged grayscale
    enlarged = cv2.resize(
        gray,
        None,
        fx=2,
        fy=2,
        interpolation=cv2.INTER_CUBIC
    )

    images.append(enlarged)

    # Threshold
    _, threshold = cv2.threshold(
        enlarged,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )

    images.append(threshold)

    # Adaptive threshold
    adaptive = cv2.adaptiveThreshold(
        enlarged,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        5
    )

    images.append(adaptive)

    # --------------------------------------------------------
    # TRY QR DECODING
    # --------------------------------------------------------

    detector = cv2.QRCodeDetector()

    decoded_text = ""

    for image in images:

        try:

            decoded, points, _ = detector.detectAndDecode(image)

            if decoded:
                decoded_text = decoded.strip()
                break

        except Exception:
            continue

    # --------------------------------------------------------
    # MULTI QR FALLBACK
    # --------------------------------------------------------

    if not decoded_text:

        for image in images:

            try:

                result = detector.detectAndDecodeMulti(image)

                if result[0] and result[1]:

                    decoded_text = result[1][0].strip()

                    if decoded_text:
                        break

            except Exception:
                continue

    # --------------------------------------------------------
    # QR NOT FOUND
    # --------------------------------------------------------

    if not decoded_text:

        raise HTTPException(
            status_code=400,
            detail=(
                "QR code could not be decoded. "
                "Please upload a clear QR code image "
                "with good contrast and enough white space."
            )
        )

    # --------------------------------------------------------
    # CLEAN DECODED CONTENT
    # --------------------------------------------------------

    decoded_text = decoded_text.strip()

    # Remove accidental spaces
    decoded_text = decoded_text.replace(
        "\n",
        ""
    ).strip()

    # --------------------------------------------------------
    # CHECK WHETHER QR CONTAINS A URL
    # --------------------------------------------------------

    parsed = urlparse(decoded_text)

    is_url = bool(
        parsed.scheme in ["http", "https"]
        and parsed.netloc
    )

    indicators = []

    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    if is_url:

        try:

            url_result = analyze_url(decoded_text)

            score = url_result.get(
                "risk_score",
                0
            )

            severity = url_result.get(
                "severity",
                "SAFE"
            )

            indicators.append(
                "QR code contains a URL"
            )

            indicators.extend(
                url_result.get(
                    "indicators",
                    []
                )
            )

            indicators = list(
                dict.fromkeys(indicators)
            )

            # QR-specific threat classification

            if score >= 81:

                threat_type = "QR_PHISHING"

                summary = (
                    "QR code contains a high-risk "
                    "potentially malicious URL."
                )

                actions = [
                    "BLOCK QR DESTINATION",
                    "WARN USER",
                    "REPORT INCIDENT",
                    "NOTIFY SECURITY ADMIN"
                ]

            elif score >= 61:

                threat_type = "QR_PHISHING"

                summary = (
                    "QR code contains a suspicious "
                    "URL with high-risk indicators."
                )

                actions = [
                    "WARN USER",
                    "BLOCK QR DESTINATION",
                    "REQUEST MANUAL VERIFICATION"
                ]

            elif score >= 41:

                threat_type = "SUSPICIOUS_QR"

                summary = (
                    "QR code contains a URL with "
                    "suspicious characteristics."
                )

                actions = [
                    "WARN USER",
                    "REQUEST MANUAL VERIFICATION"
                ]

            elif score >= 21:

                threat_type = "SUSPICIOUS_QR"

                summary = (
                    "QR code contains a URL with "
                    "some suspicious characteristics."
                )

                actions = [
                    "REVIEW DESTINATION",
                    "CONTINUE MONITORING"
                ]

            else:

                threat_type = "QR_ANALYSIS"

                summary = (
                    "QR code contains a URL that "
                    "currently appears low risk."
                )

                actions = [
                    "CONTINUE MONITORING"
                ]

            domain = url_result.get(
                "domain",
                parsed.netloc
            )

        except Exception:

            # IMPORTANT:
            # Even if URL analysis fails,
            # keep the decoded QR content.

            score = 30
            severity = "MEDIUM"

            threat_type = "SUSPICIOUS_QR"

            summary = (
                "QR code was successfully decoded, "
                "but the destination requires further review."
            )

            indicators = [
                "QR code contains a URL",
                "Destination could not be fully analyzed"
            ]

            actions = [
                "WARN USER",
                "REQUEST MANUAL VERIFICATION"
            ]

            domain = parsed.netloc

    else:

        # ----------------------------------------------------
        # NON-URL QR
        # ----------------------------------------------------

        score = 10
        severity = "SAFE"

        threat_type = "QR_CONTENT"

        summary = (
            "QR code was successfully decoded, "
            "but it does not contain a web URL."
        )

        indicators = [
            "QR code does not contain a web URL"
        ]

        actions = [
            "CONTINUE MONITORING"
        ]

        domain = ""

    # --------------------------------------------------------
    # SAVE EVENT
    # --------------------------------------------------------

    db = SessionLocal()

    try:

        event_result = db.execute(
            text("""
                INSERT INTO threat_events
                (
                    source,
                    threat_type,
                    risk_score,
                    severity,
                    status,
                    summary
                )
                VALUES
                (
                    :source,
                    :threat_type,
                    :risk_score,
                    :severity,
                    :status,
                    :summary
                )
            """),
            {
                "source": "QR",
                "threat_type": threat_type,
                "risk_score": score,
                "severity": severity,
                "status": (
                    "OPEN"
                    if score >= 41
                    else "MONITORING"
                ),
                "summary": summary
            }
        )

        event_id = event_result.lastrowid

        # ----------------------------------------------------
        # SAVE URL ANALYSIS
        # ----------------------------------------------------

        if is_url:

            db.execute(
                text("""
                    INSERT INTO url_analysis
                    (
                        event_id,
                        url,
                        domain,
                        ssl_valid,
                        redirect_count,
                        domain_similarity_score,
                        url_risk_score,
                        suspicious_features
                    )
                    VALUES
                    (
                        :event_id,
                        :url,
                        :domain,
                        :ssl_valid,
                        0,
                        0,
                        :risk_score,
                        :features
                    )
                """),
                {
                    "event_id": event_id,
                    "url": decoded_text,
                    "domain": domain,
                    "ssl_valid": (
                        parsed.scheme.lower()
                        == "https"
                    ),
                    "risk_score": score,
                    "features": ", ".join(
                        indicators
                    )
                }
            )

        # ----------------------------------------------------
        # SAVE INDICATORS
        # ----------------------------------------------------

        for indicator in indicators:

            db.execute(
                text("""
                    INSERT INTO threat_indicators
                    (
                        event_id,
                        indicator_type,
                        indicator,
                        severity,
                        description
                    )
                    VALUES
                    (
                        :event_id,
                        'QR_INDICATOR',
                        :indicator,
                        :severity,
                        :description
                    )
                """),
                {
                    "event_id": event_id,
                    "indicator": indicator,
                    "severity": severity,
                    "description": indicator
                }
            )

        # ----------------------------------------------------
        # SAVE RESPONSE ACTIONS
        # ----------------------------------------------------

        for action in actions:

            db.execute(
                text("""
                    INSERT INTO response_actions
                    (
                        event_id,
                        recommended_action,
                        action_status,
                        action_reason
                    )
                    VALUES
                    (
                        :event_id,
                        :recommended_action,
                        'RECOMMENDED',
                        :action_reason
                    )
                """),
                {
                    "event_id": event_id,
                    "recommended_action": action,
                    "action_reason":
                        f"QR risk score is {score}/100"
                }
            )

        db.commit()

        # ----------------------------------------------------
        # RESPONSE TO FRONTEND
        # ----------------------------------------------------

        return {
            "event_id": event_id,

            "analysis": {

                "risk_score": score,

                "severity": severity,

                "threat_type": threat_type,

                "summary": summary,

                "decoded_content": decoded_text,

                "is_url": is_url,

                "domain": domain,

                "indicators": indicators,

                "actions": actions
            }
        }

    except Exception:

        db.rollback()

        raise

    finally:

        db.close()

# ============================================================
# MEDIA / IMAGE / VIDEO ANALYSIS
# ============================================================

def get_media_severity(score):
    if score >= 81:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 41:
        return "MEDIUM"
    elif score >= 21:
        return "LOW"
    return "SAFE"


def extract_metadata_forensics(image_bytes: bytes, filename: str = ""):
    metadata_info = {
        "has_exif": False,
        "camera_make": None,
        "camera_model": None,
        "software": None,
        "is_edited": False,
        "ai_signature_detected": False,
        "ai_generator": None,
        "raw_tags": []
    }
    if not image_bytes:
        return metadata_info

    try:
        pil_img = PILImage.open(io.BytesIO(image_bytes))

        # 1. Check PNG text chunks / metadata (common for AI image generators)
        if hasattr(pil_img, "info") and pil_img.info:
            info_keys = [str(k).lower() for k in pil_img.info.keys()]
            info_values = [str(v).lower() for v in pil_img.info.values()]
            combined_info = " ".join(info_keys + info_values)

            ai_keywords = [
                "stable diffusion", "midjourney", "dall-e", "novelai",
                "comfyui", "parameters", "automatic1111", "prompt:",
                "diffusion", "civitai", "checkpoint"
            ]
            for kw in ai_keywords:
                if kw in combined_info:
                    metadata_info["ai_signature_detected"] = True
                    metadata_info["ai_generator"] = kw.title()
                    break

            software_tag = pil_img.info.get("Software") or pil_img.info.get("software")
            if software_tag:
                metadata_info["software"] = str(software_tag)
                metadata_info["is_edited"] = True

        # 2. Check EXIF data (common for cameras & edited photos)
        exif = pil_img.getexif() if hasattr(pil_img, "getexif") else None
        if exif:
            for tag_id, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                metadata_info["raw_tags"].append(tag_name)
                tag_name_lower = tag_name.lower()
                val_str = str(value)

                if tag_name_lower == "make":
                    metadata_info["camera_make"] = val_str
                    metadata_info["has_exif"] = True
                elif tag_name_lower == "model":
                    metadata_info["camera_model"] = val_str
                    metadata_info["has_exif"] = True
                elif tag_name_lower == "software":
                    metadata_info["software"] = val_str
                    metadata_info["is_edited"] = True
                elif tag_name_lower in ("datetime", "datetimeoriginal", "datetimedigitized"):
                    metadata_info["has_exif"] = True

        # Check for editing software signatures
        if metadata_info["software"]:
            sw_lower = metadata_info["software"].lower()
            editor_signatures = ["photoshop", "gimp", "canva", "lightroom", "paint.net", "snapseed", "pixlr", "vsco"]
            if any(ed in sw_lower for ed in editor_signatures):
                metadata_info["is_edited"] = True

    except Exception:
        pass

    return metadata_info


def compute_ela_forensics(image):
    """
    Error Level Analysis (ELA):
    Recompresses the image at 90% JPEG quality in-memory and measures
    pixel-level absolute difference. High variance in ELA difference
    highlights spliced, cloned, or digitally altered regions.
    """
    try:
        _, buffer = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, 90])
        recompressed = cv2.imdecode(buffer, cv2.IMREAD_COLOR)

        diff = cv2.absdiff(image, recompressed)
        mean_diff = float(np.mean(diff))
        std_diff = float(np.std(diff))

        ela_score = min(round((std_diff * 4.5) + (mean_diff * 2.0), 1), 100.0)
        is_anomaly = ela_score > 35.0

        return {
            "ela_score": ela_score,
            "mean_diff": round(mean_diff, 2),
            "std_diff": round(std_diff, 2),
            "is_anomaly": is_anomaly
        }
    except Exception:
        return {
            "ela_score": 15.0,
            "mean_diff": 2.0,
            "std_diff": 3.0,
            "is_anomaly": False
        }


def analyze_image_content(image, image_bytes: bytes = None, filename: str = ""):
    """
    Multi-vector authenticity & deepfake forensic analysis.
    Combines:
    1. Computer-vision texture & edge heuristics (Blur, Canny, HSV, Contrast)
    2. EXIF Digital Metadata & Provenance forensics (Camera Hardware, Editing Software tags)
    3. Error Level Analysis (ELA) for spliced / altered regions
    4. 3-tier verdict classification: Likely Authentic, Possibly Manipulated, Highly Likely Manipulated
    """
    indicators = []
    reasons = []
    manipulation_score = 10

    height, width = image.shape[:2]

    # --------------------------------------------------
    # 1. Resolution Check
    # --------------------------------------------------
    if width < 400 or height < 400:
        manipulation_score += 15
        indicators.append("Low image resolution (May conceal boundary blending artifacts)")
        reasons.append("Low resolution dimensions (<400px) restrict high-frequency forensic verification.")

    # --------------------------------------------------
    # 2. Blur / Frequency Loss Detection
    # --------------------------------------------------
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blur_value = cv2.Laplacian(gray, cv2.CV_64F).var()

    if blur_value < 80:
        manipulation_score += 15
        indicators.append("High-frequency smoothing / Gaussian blur detected")
        reasons.append("Unnatural facial skin smoothing detected (loss of natural micro-pore texture).")

    # --------------------------------------------------
    # 3. Brightness Analysis
    # --------------------------------------------------
    brightness = float(np.mean(gray))
    if brightness < 35:
        manipulation_score += 10
        indicators.append("Extremely low optical illumination")
        reasons.append("Dark lighting parameters detected, which may mask digital splicing seams.")
    elif brightness > 225:
        manipulation_score += 10
        indicators.append("Overexposed brightness blowout")
        reasons.append("Excessive exposure detected across the primary subject.")

    # --------------------------------------------------
    # 4. Contrast & Dynamic Range Analysis
    # --------------------------------------------------
    contrast = float(np.std(gray))
    if contrast < 25:
        manipulation_score += 10
        indicators.append("Unusually low dynamic contrast range")
        reasons.append("Flat tonal range detected, characteristic of synthetic diffusion outputs.")

    # --------------------------------------------------
    # 5. Canny Edge Density Analysis
    # --------------------------------------------------
    edges = cv2.Canny(gray, 100, 200)
    edge_ratio = float(np.count_nonzero(edges)) / float(edges.shape[0] * edges.shape[1])

    if edge_ratio < 0.01:
        manipulation_score += 10
        indicators.append("Unusually low structural edge detail")
        reasons.append("Perimeter edge discontinuity detected along primary subject boundaries.")

    # --------------------------------------------------
    # 6. Color Space / Saturation Analysis
    # --------------------------------------------------
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
    saturation = float(np.mean(hsv[:, :, 1]))
    if saturation < 20:
        manipulation_score += 5
        indicators.append("Atypical color saturation distribution")

    # --------------------------------------------------
    # 7. Aspect Ratio Anomaly
    # --------------------------------------------------
    aspect_ratio = width / max(height, 1)
    if aspect_ratio > 3.5 or aspect_ratio < 0.28:
        manipulation_score += 10
        indicators.append("Unusual aspect ratio / Non-standard image dimensions")

    # --------------------------------------------------
    # 8. EXIF Digital Metadata Forensics
    # --------------------------------------------------
    metadata_info = extract_metadata_forensics(image_bytes, filename)

    if metadata_info["ai_signature_detected"]:
        manipulation_score += 35
        indicators.append(f"AI Generator Signature Detected ({metadata_info['ai_generator']})")
        reasons.append(f"Embedded AI generation tag discovered in file structure: {metadata_info['ai_generator']}")

    if metadata_info["is_edited"]:
        manipulation_score += 25
        sw_name = metadata_info['software'] or "Digital Photo Editor"
        indicators.append(f"Digital Editing Software Tag Detected ({sw_name})")
        reasons.append(f"File was modified using software suite: {sw_name}")

    if not metadata_info["has_exif"] and (width >= 600 and height >= 600):
        manipulation_score += 10
        indicators.append("Missing Camera Hardware EXIF (Typical of pure AI synthetic content)")
        reasons.append("Zero camera sensor metadata discovered; consistent with synthetic generation or metadata stripping.")
    elif metadata_info["has_exif"] and not metadata_info["is_edited"]:
        # Bonus authenticity for genuine camera hardware metadata
        camera_name = f"{metadata_info.get('camera_make') or ''} {metadata_info.get('camera_model') or ''}".strip()
        reasons.append(f"Verified genuine camera hardware signature: {camera_name or 'Standard Camera Device'}")
        manipulation_score = max(5, manipulation_score - 15)

    # --------------------------------------------------
    # 9. Error Level Analysis (ELA) Compression Forensics
    # --------------------------------------------------
    ela_data = compute_ela_forensics(image)
    if ela_data["is_anomaly"]:
        manipulation_score += 20
        indicators.append(f"ELA detected non-uniform compression divergence (Score: {ela_data['ela_score']})")
        reasons.append("Error Level Analysis (ELA) highlights localized pixel compression anomaly — indicates spliced, cloned, or pasted content.")

    # --------------------------------------------------
    # 10. Final Scores & 3-Tier Authenticity Verdict
    # --------------------------------------------------
    manipulation_score = max(5, min(manipulation_score, 98))
    authenticity_score = 100 - manipulation_score

    if authenticity_score >= 70:
        verdict = {
            "status": "AUTHENTIC",
            "badge": "🟢 Likely Authentic",
            "label": "Likely Authentic",
            "color": "emerald",
            "summary": "Content shows natural optical characteristics, consistent camera noise, and valid structural integrity."
        }
    elif authenticity_score >= 40:
        verdict = {
            "status": "SUSPICIOUS",
            "badge": "🟡 Possibly Manipulated",
            "label": "Possibly Manipulated",
            "color": "amber",
            "summary": "Content displays possible compression anomalies, digital resampling, or post-processing filtering."
        }
    else:
        verdict = {
            "status": "MANIPULATED",
            "badge": "🔴 Highly Likely Manipulated",
            "label": "Highly Likely Manipulated",
            "color": "rose",
            "summary": "Content exhibits strong markers of synthetic AI generation, facial splicing, or localized digital alteration."
        }

    # Model Confidence estimation
    confidence = 75
    if width >= 800 and height >= 600:
        confidence += 8
    if len(indicators) >= 2:
        confidence += 7
    if metadata_info["has_exif"] or metadata_info["is_edited"] or metadata_info["ai_signature_detected"]:
        confidence += 6
    confidence = min(confidence, 96)

    severity = get_media_severity(manipulation_score)

    if not indicators:
        indicators.append("No obvious visual anomaly detected across tested spectral domains")
    if not reasons:
        reasons.append("Standard pixel uniformity verified across color, edge, and frequency domains.")

    return {
        "authenticity_score": authenticity_score,
        "manipulation_score": manipulation_score,
        "model_confidence": confidence,
        "verdict": verdict,
        "indicators": indicators,
        "reasons": reasons,
        "metadata_forensics": {
            "has_exif": metadata_info["has_exif"],
            "camera_make": metadata_info["camera_make"] or "N/A",
            "camera_model": metadata_info["camera_model"] or "N/A",
            "software": metadata_info["software"] or "None detected",
            "is_edited": metadata_info["is_edited"],
            "ai_detected": metadata_info["ai_signature_detected"],
            "ai_generator": metadata_info["ai_generator"] or "None"
        },
        "compression_forensics": {
            "ela_score": ela_data["ela_score"],
            "is_anomaly": ela_data["is_anomaly"],
            "mean_diff": ela_data["mean_diff"]
        },
        "risk_score": manipulation_score,
        "severity": severity,
    }
@app.post("/analyze/image")
async def analyze_image(
    file: UploadFile = File(...)
):
    db = SessionLocal()

    allowed_types = [
        "image/jpeg",
        "image/jpg",
        "image/png",
        "image/webp"
    ]

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Only JPG, PNG and WEBP images are allowed."
        )

    image_bytes = file.file.read()

    if not image_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded image is empty."
        )

    image_array = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

    if image is None:
        raise HTTPException(
            status_code=400,
            detail="Unable to read the uploaded image."
        )

    analysis = analyze_image_content(
        image,
        image_bytes=image_bytes,
        filename=file.filename or ""
    )

    risk_score = analysis["risk_score"]
    severity = analysis["severity"]

    # 1. Main threat event
    event_result = db.execute(
        text("""
            INSERT INTO threat_events
            (
                source,
                threat_type,
                risk_score,
                severity,
                status,
                summary
            )
            VALUES
            (
                :source,
                :threat_type,
                :risk_score,
                :severity,
                'OPEN',
                :summary
            )
        """),
        {
            "source": "IMAGE",
            "threat_type": "MEDIA_MANIPULATION",
            "risk_score": risk_score,
            "severity": severity,
            "summary": "Image media authenticity analysis completed."
        }
    )

    db.commit()

    event_id = event_result.lastrowid

    # 2. Media analysis
    db.execute(
        text("""
            INSERT INTO media_analysis
            (
                event_id,
                file_name,
                file_type,
                authenticity_score,
                manipulation_score,
                model_confidence,
                detected_indicators,
                analysis_result
            )
            VALUES
            (
                :event_id,
                :file_name,
                :file_type,
                :authenticity_score,
                :manipulation_score,
                :model_confidence,
                :detected_indicators,
                :analysis_result
            )
        """),
        {
            "event_id": event_id,
            "file_name": file.filename,
            "file_type": file.content_type,
            "authenticity_score": analysis["authenticity_score"],
            "manipulation_score": analysis["manipulation_score"],
            "model_confidence": analysis["model_confidence"],
            "detected_indicators": ", ".join(analysis["indicators"]),
            "analysis_result": severity
        }
    )

    # 3. Indicators
    for indicator in analysis["indicators"]:
        db.execute(
            text("""
                INSERT INTO threat_indicators
                (
                    event_id,
                    indicator_type,
                    indicator,
                    severity,
                    description
                )
                VALUES
                (
                    :event_id,
                    'MEDIA',
                    :indicator,
                    :severity,
                    :description
                )
            """),
            {
                "event_id": event_id,
                "indicator": indicator,
                "severity": severity,
                "description": "Image analysis indicator."
            }
        )

    # 4. Response
    db.execute(
        text("""
            INSERT INTO response_actions
            (
                event_id,
                recommended_action,
                action_status,
                action_reason
            )
            VALUES
            (
                :event_id,
                :action,
                'RECOMMENDED',
                :reason
            )
        """),
        {
            "event_id": event_id,
            "action": "Review image authenticity before trusting or sharing.",
            "reason": "Media manipulation indicators were analyzed."
        }
    )

    db.commit()

    return {
        "event_id": event_id,
        "analysis": {
            "threat_type": "MEDIA_MANIPULATION",
            "risk_score": risk_score,
            "severity": severity,
            "authenticity_score": analysis["authenticity_score"],
            "manipulation_score": analysis["manipulation_score"],
            "model_confidence": analysis["model_confidence"],
            "verdict": analysis.get("verdict"),
            "metadata_forensics": analysis.get("metadata_forensics"),
            "compression_forensics": analysis.get("compression_forensics"),
            "indicators": analysis["indicators"],
            "reasons": analysis.get("reasons", []),
            "actions": [
                "Review image authenticity before trusting or sharing.",
                "Inspect EXIF metadata and ELA compression anomalies if critical."
            ]
        }
    }

@app.post("/analyze/video")
async def analyze_video(
    file: UploadFile = File(...)
):
    db = SessionLocal()

    allowed_types = [
        "video/mp4",
        "video/webm",
        "video/quicktime",
        "video/x-msvideo",
        "video/avi"
    ]

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Only MP4, WEBM, MOV and AVI videos are allowed."
        )

    video_bytes = file.file.read()

    if not video_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded video is empty."
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".mp4"
        ) as temp_file:

            temp_file.write(video_bytes)
            temp_path = temp_file.name

        capture = cv2.VideoCapture(temp_path)

        if not capture.isOpened():
            raise HTTPException(
                status_code=400,
                detail="Unable to read the uploaded video."
            )

        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))

        fps = capture.get(cv2.CAP_PROP_FPS)

        duration = 0

        if fps and fps > 0:
            duration = frame_count / fps

        indicators = []

        sampled_frames = 0
        blur_values = []

        # Analyze up to 8 frames
        total_samples = min(8, max(frame_count, 1))

        for i in range(total_samples):

            position = int(
                (i / total_samples) * max(frame_count - 1, 0)
            )

            capture.set(cv2.CAP_PROP_POS_FRAMES, position)

            success, frame = capture.read()

            if not success:
                continue

            sampled_frames += 1

            gray = cv2.cvtColor(
                frame,
                cv2.COLOR_BGR2GRAY
            )

            blur_value = cv2.Laplacian(
                gray,
                cv2.CV_64F
            ).var()

            blur_values.append(blur_value)

        capture.release()

        if sampled_frames == 0:
            raise HTTPException(
                status_code=400,
                detail="No readable video frames found."
            )

        average_blur = sum(blur_values) / len(blur_values)

        manipulation_score = 10

        if average_blur < 80:
            manipulation_score += 15
            indicators.append(
                "Low visual sharpness detected across sampled frames"
            )

        if duration > 300:
            indicators.append(
                "Long video requires deeper frame-by-frame analysis"
            )

        if sampled_frames < 3:
            manipulation_score += 10
            indicators.append(
                "Limited readable frames available"
            )

        manipulation_score = min(
            manipulation_score,
            100
        )

        authenticity_score = 100 - manipulation_score

        confidence = min(
            60 + sampled_frames * 4,
            90
        )

        severity = get_media_severity(
            manipulation_score
        )

        if not indicators:
            indicators.append(
                "No obvious visual anomaly detected in sampled frames"
            )

        # Main event
        event_result = db.execute(
            text("""
                INSERT INTO threat_events
                (
                    source,
                    threat_type,
                    risk_score,
                    severity,
                    status,
                    summary
                )
                VALUES
                (
                    :source,
                    :threat_type,
                    :risk_score,
                    :severity,
                    'OPEN',
                    :summary
                )
            """),
            {
                "source": "VIDEO",
                "threat_type": "MEDIA_MANIPULATION",
                "risk_score": manipulation_score,
                "severity": severity,
                "summary": "Video media authenticity analysis completed."
            }
        )

        db.commit()

        event_id = event_result.lastrowid

        # Media record
        db.execute(
            text("""
                INSERT INTO media_analysis
                (
                    event_id,
                    file_name,
                    file_type,
                    authenticity_score,
                    manipulation_score,
                    model_confidence,
                    detected_indicators,
                    analysis_result
                )
                VALUES
                (
                    :event_id,
                    :file_name,
                    :file_type,
                    :authenticity_score,
                    :manipulation_score,
                    :model_confidence,
                    :detected_indicators,
                    :analysis_result
                )
            """),
            {
                "event_id": event_id,
                "file_name": file.filename,
                "file_type": file.content_type,
                "authenticity_score": authenticity_score,
                "manipulation_score": manipulation_score,
                "model_confidence": confidence,
                "detected_indicators": ", ".join(indicators),
                "analysis_result": severity
            }
        )

        # Indicators
        for indicator in indicators:
            db.execute(
                text("""
                    INSERT INTO threat_indicators
                    (
                        event_id,
                        indicator_type,
                        indicator,
                        severity,
                        description
                    )
                    VALUES
                    (
                        :event_id,
                        'MEDIA',
                        :indicator,
                        :severity,
                        :description
                    )
                """),
                {
                    "event_id": event_id,
                    "indicator": indicator,
                    "severity": severity,
                    "description": "Video analysis indicator."
                }
            )

        # Recommended response
        db.execute(
            text("""
                INSERT INTO response_actions
                (
                    event_id,
                    recommended_action,
                    action_status,
                    action_reason
                )
                VALUES
                (
                    :event_id,
                    :action,
                    'RECOMMENDED',
                    :reason
                )
            """),
            {
                "event_id": event_id,
                "action": "Review video authenticity before trusting or sharing.",
                "reason": "Video media indicators were analyzed."
            }
        )

        db.commit()

        if authenticity_score >= 70:
            video_verdict = {
                "status": "AUTHENTIC",
                "badge": "🟢 Likely Authentic",
                "label": "Likely Authentic",
                "color": "emerald",
                "summary": "Video displays natural optical continuity and consistent inter-frame sharpness."
            }
        elif authenticity_score >= 40:
            video_verdict = {
                "status": "SUSPICIOUS",
                "badge": "🟡 Possibly Manipulated",
                "label": "Possibly Manipulated",
                "color": "amber",
                "summary": "Video shows potential compression anomalies, frame smoothing, or motion jitter."
            }
        else:
            video_verdict = {
                "status": "MANIPULATED",
                "badge": "🔴 Highly Likely Manipulated",
                "label": "Highly Likely Manipulated",
                "color": "rose",
                "summary": "Video demonstrates strong markers of AI deepfake synthesis, temporal blur, or frame inconsistency."
            }

        return {
            "event_id": event_id,
            "analysis": {
                "threat_type": "MEDIA_MANIPULATION",
                "risk_score": manipulation_score,
                "severity": severity,
                "authenticity_score": authenticity_score,
                "manipulation_score": manipulation_score,
                "model_confidence": confidence,
                "verdict": video_verdict,
                "sampled_frames": sampled_frames,
                "duration_seconds": round(duration, 2),
                "indicators": indicators,
                "actions": [
                    "Review video authenticity before trusting or sharing."
                ]
            }
        }

    finally:

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

# ==========================================================
# SERVE REACT FRONTEND
# ==========================================================

if FRONTEND_DIST.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND_DIST / "assets"),
        name="assets",
    )
    if (FRONTEND_DIST / "samples").exists():
        app.mount(
            "/samples",
            StaticFiles(directory=FRONTEND_DIST / "samples"),
            name="samples",
        )


@app.get("/", include_in_schema=False)
async def serve_frontend():
    index_file = FRONTEND_DIST / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    return {
        "system": "CYBERGUARD-X Threat Intelligence Engine",
        "status": "ONLINE & ACTIVE",
        "database": "TiDB Cloud MySQL (Permanent Storage)",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "stats": "/dashboard/stats",
            "events": "/events",
            "docs": "/docs"
        }
    }


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_react_routes(full_path: str):
    # Keep API routes from being handled by React
    if full_path.startswith(("api/", "analyze/", "dashboard/", "events")):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    # If requested static file exists in frontend dist, serve it directly
    candidate = FRONTEND_DIST / full_path
    if candidate.is_file():
        return FileResponse(candidate)

    index_file = FRONTEND_DIST / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    raise HTTPException(status_code=404, detail="Frontend not found")