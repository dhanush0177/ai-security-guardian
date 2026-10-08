from enum import Enum
from typing import List, Dict, Any
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatIndicator(BaseModel):
    category: str
    name: str
    weight: int
    detail: str

class AnalysisResponse(BaseModel):
    type: str
    input_preview: str
    score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    indicators: List[ThreatIndicator]
    explanation: str
    recommendations: List[str]

# Standard Indicator Weights (deterministic baseline)
INDICATOR_WEIGHTS: Dict[str, int] = {
    "urgency_pressure": 15,
    "credential_request": 25,
    "suspicious_url": 25,
    "impersonation": 15,
    "threat_language": 10,
    "prompt_override": 30,
    "system_prompt_extraction": 30,
    "secret_extraction": 35,
    "data_exfiltration": 40,
    "unsafe_tool_request": 35,
    "suspicious_tld": 15,
    "ip_hostname": 30,
    "punycode_homograph": 25,
    "suspicious_encoding": 15,
    "excessive_subdomains": 15,
    "http_unencrypted": 10,
    "jailbreak_pattern": 35,
    "obfuscation_attempt": 20,
}

def determine_risk_level(score: int) -> RiskLevel:
    """Classify 0-100 score into deterministic RiskLevel categories."""
    if score <= 24:
        return RiskLevel.LOW
    elif score <= 49:
        return RiskLevel.MEDIUM
    elif score <= 74:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL

def calculate_score(indicators: List[ThreatIndicator]) -> int:
    """Calculate total risk score bounded rigidly between 0 and 100."""
    total_weight = sum(ind.weight for ind in indicators)
    return min(100, max(0, total_weight))
