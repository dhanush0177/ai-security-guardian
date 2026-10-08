import re
from typing import List
from .risk_engine import (
    ThreatIndicator,
    AnalysisResponse,
    RiskLevel,
    calculate_score,
    determine_risk_level,
    INDICATOR_WEIGHTS
)

# Pattern lists for message analysis
URGENCY_PATTERNS = [
    r"\b(act (now|fast|immediately))\b",
    r"\b(urgent(ly)?|immediate action required)\b",
    r"\b(account (will be|has been) (suspended|blocked|terminated|disabled))\b",
    r"\b(within 24 hours|expire(s)? soon|time sensitive)\b"
]

CREDENTIAL_PATTERNS = [
    r"\b(send|provide|enter|confirm|verify) (your )?(password|passcode|pin|ssn|social security)\b",
    r"\b(login|credentials|security details)\b"
]

OTP_PATTERNS = [
    r"\b(share|send|provide|tell us|verify|enter|confirm) (the |your )?(otp|code|one-time passcode|2fa code|verification code)\b",
    r"\b(6-digit code|auth code|otp passcode|otp code|otp)\b"
]

PAYMENT_PATTERNS = [
    r"\b(buy|purchase) (gift cards?|apple card|vanilla card)\b",
    r"\b(wire transfer|crypto(currency)?|bitcoin|usdt|send money|unpaid invoice)\b",
    r"\b(claim (your )?(prize|reward|refund|inheritance))\b"
]

THREAT_PATTERNS = [
    r"\b(legal action|police|arrest|lawsuit|court summons|warrant|penalty)\b"
]

IMPERSONATION_PATTERNS = [
    r"\b(helpdesk|it support|security team|bank (support|alert)|irs|tax office|amazon support|apple security)\b"
]

LINK_PATTERNS = [
    r"https?://[^\s]+",
    r"\b(click (here|link|below)|verify (here|at)|login (here|below))\b"
]

def analyze_message(message_text: str) -> AnalysisResponse:
    """
    Deterministically score scam/phishing message content using behavioral patterns.
    """
    text_clean = message_text.strip()
    if not text_clean:
        raise ValueError("Message text cannot be empty.")
    
    if len(text_clean) > 5000:
        raise ValueError("Message exceeds maximum length limit of 5000 characters.")

    indicators: List[ThreatIndicator] = []
    text_lower = text_clean.lower()

    # 1. Urgency / Artificial Time Pressure
    for pat in URGENCY_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="social_engineering",
                name="Urgency & Pressure Language",
                weight=INDICATOR_WEIGHTS["urgency_pressure"],
                detail="Message creates artificial time pressure to force hasty decisions."
            ))
            break

    # 2. Credential Theft Request
    for pat in CREDENTIAL_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="credential_theft",
                name="Direct Credential Request",
                weight=INDICATOR_WEIGHTS["credential_request"],
                detail="Asks the user to reveal sensitive credentials or passwords."
            ))
            break

    # 3. One-Time Passcode (OTP) Request
    for pat in OTP_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="credential_theft",
                name="OTP / 2FA Code Solicit",
                weight=25,
                detail="Attempts to harvest multi-factor authentication (OTP) codes."
            ))
            break

    # 4. Payment / Gift Card / Crypto Demand
    for pat in PAYMENT_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="financial_scam",
                name="Unusual Payment / Gift Card Solicit",
                weight=25,
                detail="Requests non-standard payment methods such as wire transfer or gift cards."
            ))
            break

    # 5. Threat & Coercion Language
    for pat in THREAT_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="social_engineering",
                name="Threat & Coercion Tactics",
                weight=INDICATOR_WEIGHTS["threat_language"],
                detail="Uses intimidating threats of legal or law enforcement action."
            ))
            break

    # 6. Authority / Support Impersonation
    for pat in IMPERSONATION_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="impersonation",
                name="Trusted Authority / Brand Impersonation",
                weight=INDICATOR_WEIGHTS["impersonation"],
                detail="Claims to represent a bank, IT department, government, or tech vendor."
            ))
            break

    # 7. Embedded Suspicious Call to Action / Link
    for pat in LINK_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="phishing_link",
                name="Embedded Link Call-to-Action",
                weight=20,
                detail="Contains a direct link or prompt encouraging navigation to an unverified web form."
            ))
            break

    # Calculate Score & Level
    score = calculate_score(indicators)
    risk_level = determine_risk_level(score)

    # Human-readable explanations
    if risk_level == RiskLevel.LOW:
        explanation = "The message displays standard communication patterns without social engineering or phishing indicators."
    elif risk_level == RiskLevel.MEDIUM:
        explanation = "Moderate risk. The message includes mild urgency or embedded links; verify the sender's identity."
    elif risk_level == RiskLevel.HIGH:
        explanation = "High risk detected. The message uses strong urgency, brand impersonation, or credential harvesting techniques."
    else:
        explanation = "CRITICAL PHISHING THREAT. The message attempts credential theft, OTP harvesting, or financial extortion."

    # Recommendations
    recommendations = []
    if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        recommendations.append("Do NOT reply to this message or click any included links.")
        recommendations.append("Never share OTP codes, passwords, or SSN over email or SMS.")
        recommendations.append("Contact the organization directly using their official published phone number.")
    elif risk_level == RiskLevel.MEDIUM:
        recommendations.append("Inspect the sender email address / phone number carefully.")
        recommendations.append("Do not click shortened links; type the official website directly into your browser.")
    else:
        recommendations.append("Standard message hygiene applies. Remain alert for unexpected requests.")

    return AnalysisResponse(
        type="message",
        input_preview=text_clean[:100] + ("..." if len(text_clean) > 100 else ""),
        score=score,
        risk_level=risk_level,
        indicators=indicators,
        explanation=explanation,
        recommendations=recommendations
    )
