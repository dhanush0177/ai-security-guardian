import re
from urllib.parse import urlparse, unquote
from typing import List
from .risk_engine import (
    ThreatIndicator,
    AnalysisResponse,
    RiskLevel,
    calculate_score,
    determine_risk_level,
    INDICATOR_WEIGHTS
)

SUSPICIOUS_TLDS = {".xyz", ".top", ".work", ".click", ".monster", ".zip", ".mov", ".cc", ".tk", ".fit", ".rest"}
LOGIN_KEYWORDS = ["login", "verify", "signin", "account", "banking", "secure", "auth", "credential", "update-info"]
PAYMENT_KEYWORDS = ["paypal", "crypto", "wallet", "billing", "invoice", "payment", "refund", "payout"]
SECURITY_KEYWORDS = ["suspended", "restricted", "verify-account", "security-alert", "reactivate", "support-team"]

def analyze_url(url_string: str) -> AnalysisResponse:
    """
    Safely inspect a URL string using deterministic heuristics.
    NOTE: Performs NO external network requests.
    """
    url_clean = url_string.strip()
    if not url_clean:
        raise ValueError("URL string cannot be empty.")
    
    # Input length check
    if len(url_clean) > 2048:
        raise ValueError("URL exceeds maximum length limit of 2048 characters.")

    indicators: List[ThreatIndicator] = []
    
    # Prepend scheme if missing for parsing purposes
    parse_target = url_clean if "://" in url_clean else f"http://{url_clean}"
    try:
        parsed = urlparse(parse_target)
    except Exception:
        parsed = None

    hostname = (parsed.hostname or "").lower() if parsed else url_clean.lower()

    # Signal 1: HTTP instead of HTTPS
    if url_clean.lower().startswith("http://"):
        indicators.append(ThreatIndicator(
            category="transport",
            name="Unencrypted HTTP Transport",
            weight=INDICATOR_WEIGHTS["http_unencrypted"],
            detail="The URL uses cleartext HTTP instead of encrypted HTTPS."
        ))

    # Signal 2: Raw IP address hostname
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ip_pattern, hostname):
        indicators.append(ThreatIndicator(
            category="network",
            name="Raw IP Address Hostname",
            weight=INDICATOR_WEIGHTS["ip_hostname"],
            detail="Hostname is a numeric IP address, frequently used to bypass domain reputation checks."
        ))

    # Signal 3: Punycode / IDN Homograph
    if "xn--" in hostname:
        indicators.append(ThreatIndicator(
            category="domain",
            name="Punycode Homograph Indicator",
            weight=INDICATOR_WEIGHTS["punycode_homograph"],
            detail="Contains IDN punycode prefix ('xn--') which can be used for visual domain spoofing."
        ))

    # Signal 4: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            indicators.append(ThreatIndicator(
                category="domain",
                name=f"High-Risk TLD ({tld})",
                weight=INDICATOR_WEIGHTS["suspicious_tld"],
                detail=f"Domain uses high-abuse top-level domain '{tld}'."
            ))
            break

    # Signal 5: Excessive subdomains (>3 domain levels)
    domain_parts = [p for p in hostname.split(".") if p]
    if len(domain_parts) > 4:
        indicators.append(ThreatIndicator(
            category="structure",
            name="Excessive Subdomain Nesting",
            weight=INDICATOR_WEIGHTS["excessive_subdomains"],
            detail=f"URL contains {len(domain_parts)} domain levels, often used to disguise brand names."
        ))

    # Signal 6: Suspicious characters (@ symbol or multiple slashes in path)
    if "@" in url_clean:
        indicators.append(ThreatIndicator(
            category="structure",
            name="User Authority Embedding (@)",
            weight=INDICATOR_WEIGHTS["suspicious_url"],
            detail="URL uses '@' symbol in authority string, hiding the true destination host."
        ))

    # Signal 7: Suspicious URL Encoding
    if "%" in url_clean:
        decoded_once = unquote(url_clean)
        if "%" in decoded_once or url_clean.count("%") > 4:
            indicators.append(ThreatIndicator(
                category="obfuscation",
                name="Suspicious URL Encoding / Obfuscation",
                weight=INDICATOR_WEIGHTS["suspicious_encoding"],
                detail="Excessive percent-encoding or double-encoding detected."
            ))

    # Signal 8: Login & Authentication Keywords
    url_lower = url_clean.lower()
    found_login_keywords = [kw for kw in LOGIN_KEYWORDS if kw in url_lower]
    if found_login_keywords:
        indicators.append(ThreatIndicator(
            category="credential_risk",
            name="Authentication Trigger Keywords",
            weight=INDICATOR_WEIGHTS["credential_request"],
            detail=f"URL path/domain contains credential keywords: {', '.join(found_login_keywords[:3])}."
        ))

    # Signal 9: Payment & Financial Keywords
    found_payment_keywords = [kw for kw in PAYMENT_KEYWORDS if kw in url_lower]
    if found_payment_keywords:
        indicators.append(ThreatIndicator(
            category="financial_risk",
            name="Payment & Financial Target Keywords",
            weight=20,
            detail=f"URL contains financial keyword triggers: {', '.join(found_payment_keywords[:3])}."
        ))

    # Signal 10: Security / Account Suspension Keywords
    found_sec_keywords = [kw for kw in SECURITY_KEYWORDS if kw in url_lower]
    if found_sec_keywords:
        indicators.append(ThreatIndicator(
            category="social_engineering",
            name="Urgency & Account Warning Trigger",
            weight=INDICATOR_WEIGHTS["urgency_pressure"],
            detail=f"URL contains account warning keywords: {', '.join(found_sec_keywords[:3])}."
        ))

    # Signal 11: Unusually long URL (>75 characters)
    if len(url_clean) > 75:
        indicators.append(ThreatIndicator(
            category="structure",
            name="Abnormally Long URL Path",
            weight=10,
            detail=f"URL length ({len(url_clean)} chars) is unusually long, common in obfuscated links."
        ))

    # Calculate Score & Level
    score = calculate_score(indicators)
    risk_level = determine_risk_level(score)

    # Explanation generator
    if risk_level == RiskLevel.LOW:
        explanation = "The URL exhibits standard structural patterns with no high-risk phishing or obfuscation indicators."
    elif risk_level == RiskLevel.MEDIUM:
        explanation = "The URL presents moderate risk due to unencrypted transport, long structure, or secondary keyword triggers."
    elif risk_level == RiskLevel.HIGH:
        explanation = "High risk detected. The URL contains strong indicators of credential harvesting or domain impersonation."
    else:
        explanation = "CRITICAL THREAT. The URL exhibits malicious structural indicators such as IP hostname, user embedding (@), or suspicious TLDs."

    # Recommendations
    recommendations = []
    if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        recommendations.append("Do NOT click or open this link.")
        recommendations.append("Do NOT enter any passwords, credentials, or personal information.")
        recommendations.append("Verify the official website domain independently via search or bookmark.")
    elif risk_level == RiskLevel.MEDIUM:
        recommendations.append("Verify that the domain matches the official organization before proceeding.")
        recommendations.append("Ensure the page uses valid HTTPS encryption before submitting data.")
    else:
        recommendations.append("URL appears safe based on structural heuristics, but standard caution applies.")

    return AnalysisResponse(
        type="url",
        input_preview=url_clean[:100] + ("..." if len(url_clean) > 100 else ""),
        score=score,
        risk_level=risk_level,
        indicators=indicators,
        explanation=explanation,
        recommendations=recommendations
    )
