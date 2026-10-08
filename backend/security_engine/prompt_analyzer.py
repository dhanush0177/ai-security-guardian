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

OVERRIDE_PATTERNS = [
    r"\b(ignore|disregard|override|forget|bypass) (all )?(previous|prior|above|system) (instructions|directives|prompts|rules)\b",
    r"\b(stop following rules|new rule(s)? apply)\b"
]

EXTRACTION_PATTERNS = [
    r"\b(reveal|print|show|output|display|repeat|dump|tell me) (the |your |our |hidden )*(system prompt|developer instructions|initial prompt|core directives|system instructions|rules)\b",
    r"\b(what are your system instructions|tell me your system prompt)\b"
]

SECRET_PATTERNS = [
    r"\b(api key|secrets?|env vars?|access token|secret key)\b",
    r"\b(config files?|\.env file|database credentials)\b"
]

CREDENTIAL_PATTERNS = [
    r"\b(password|passcode|pin|ssn|social security|credentials)\b",
    r"\b(user passwords?|account credentials)\b"
]

EXFILTRATION_PATTERNS = [
    r"\b(send|upload|post|exfiltrate|transmit) (the |all )?(data|files?|credentials?|security logs?) to\b",
    r"\b(curl|wget|fetch) (https?://[^\s]+)\b"
]

UNSAFE_TOOL_PATTERNS = [
    r"\b(execute|run) (bash|cmd|shell|powershell|terminal|eval|system command)\b",
    r"\b(delete|drop|remove|wipe) (database|all files|table|records|users|security audit logs|security logs)\b",
    r"\b(rm -rf|format c:)\b"
]

JAILBREAK_PATTERNS = [
    r"\b(dan mode|do anything now|developer mode|god mode|jailbreak|unrestricted mode)\b",
    r"\b(pretend you have no security rules|simulate an unaligned ai)\b",
    r"\b(aim persona|opposite mode)\b"
]

def analyze_prompt(prompt_text: str) -> AnalysisResponse:
    """
    Deterministically analyze an incoming AI prompt for injection, exfiltration, and jailbreak vectors.
    """
    text_clean = prompt_text.strip()
    if not text_clean:
        raise ValueError("Prompt text cannot be empty.")
    
    if len(text_clean) > 5000:
        raise ValueError("Prompt exceeds maximum length limit of 5000 characters.")

    indicators: List[ThreatIndicator] = []
    text_lower = text_clean.lower()

    # 1. System Instruction Override
    for pat in OVERRIDE_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="prompt_injection",
                name="Instruction Override Attempt",
                weight=INDICATOR_WEIGHTS["prompt_override"],
                detail="Prompt attempts to invalidate previous system instructions."
            ))
            break

    # 2. System Prompt Extraction
    for pat in EXTRACTION_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="prompt_injection",
                name="System Prompt Extraction",
                weight=INDICATOR_WEIGHTS["system_prompt_extraction"],
                detail="Prompt explicitly requests revealing secret system instructions."
            ))
            break

    # 3. Credential Harvesting Solicit
    for pat in CREDENTIAL_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="credential_theft",
                name="Credential Harvesting Solicit",
                weight=INDICATOR_WEIGHTS["credential_request"],
                detail="Attempts to harvest passwords, SSN, or sensitive user credentials."
            ))
            break

    # 4. Secret & Token Extraction
    for pat in SECRET_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="secret_extraction",
                name="Secret & Token Extraction",
                weight=INDICATOR_WEIGHTS["secret_extraction"],
                detail="Attempts to harvest API keys, environment variables, or tokens."
            ))
            break

    # 5. Data Exfiltration
    for pat in EXFILTRATION_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="exfiltration",
                name="Data Exfiltration Vector",
                weight=INDICATOR_WEIGHTS["data_exfiltration"],
                detail="Contains web request or outbound transmission patterns to exfiltrate data."
            ))
            break

    # 6. Unsafe System Command / Tool Execution
    for pat in UNSAFE_TOOL_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="unsafe_tool",
                name="Unsafe Tool Execution Vector",
                weight=INDICATOR_WEIGHTS["unsafe_tool_request"],
                detail="Requests dangerous local command execution or database destruction."
            ))
            break

    # 7. Jailbreak Persona / Bypass Modes
    for pat in JAILBREAK_PATTERNS:
        if re.search(pat, text_lower):
            indicators.append(ThreatIndicator(
                category="jailbreak",
                name="Jailbreak Persona / Bypass Mode",
                weight=INDICATOR_WEIGHTS["jailbreak_pattern"],
                detail="Uses known jailbreak frameworks (e.g. DAN, God Mode, Unrestricted Mode)."
            ))
            break

    # Calculate Score & Level
    score = calculate_score(indicators)
    risk_level = determine_risk_level(score)

    # Human-readable explanations
    if risk_level == RiskLevel.LOW:
        explanation = "The prompt appears safe and aligns with standard conversational AI interaction."
    elif risk_level == RiskLevel.MEDIUM:
        explanation = "Moderate risk. The prompt contains ambiguous boundary tests or mild roleplay framing."
    elif risk_level == RiskLevel.HIGH:
        explanation = "HIGH THREAT DETECTED. The prompt attempts instruction override, system prompt extraction, or jailbreak bypass."
    else:
        explanation = "CRITICAL ADVERSARIAL PROMPT. Multiple severe injection vectors detected (data exfiltration, secret leakage, or system destruction)."

    # Recommendations
    recommendations = []
    if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        recommendations.append("Block this prompt from reaching the LLM application layer.")
        recommendations.append("Enforce strict server-side system prompt isolation.")
        recommendations.append("Log the session ID for security audit review.")
    elif risk_level == RiskLevel.MEDIUM:
        recommendations.append("Sanitize prompt input before passing to downstream agents.")
        recommendations.append("Restrict tool execution privileges for this session.")
    else:
        recommendations.append("Prompt is safe to execute under standard application permissions.")

    return AnalysisResponse(
        type="prompt",
        input_preview=text_clean[:100] + ("..." if len(text_clean) > 100 else ""),
        score=score,
        risk_level=risk_level,
        indicators=indicators,
        explanation=explanation,
        recommendations=recommendations
    )
