import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from .risk_engine import RiskLevel
from .event_logger import event_store, SecurityEvent

class ToolDefinition(BaseModel):
    name: str
    description: str
    risk_level: RiskLevel
    base_score: int
    is_simulated: bool
    requires_approval: bool

# Registered Tools Specification
TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    "analyze_url": ToolDefinition(
        name="analyze_url",
        description="Inspect domain structures and URL string signals safely",
        risk_level=RiskLevel.LOW,
        base_score=0,
        is_simulated=False,
        requires_approval=False
    ),
    "analyze_message": ToolDefinition(
        name="analyze_message",
        description="Analyze email/SMS message text for phishing indicators",
        risk_level=RiskLevel.LOW,
        base_score=0,
        is_simulated=False,
        requires_approval=False
    ),
    "generate_report": ToolDefinition(
        name="generate_report",
        description="Compile security summary and audit logs into report format",
        risk_level=RiskLevel.LOW,
        base_score=10,
        is_simulated=False,
        requires_approval=False
    ),
    "view_security_log": ToolDefinition(
        name="view_security_log",
        description="Read-only access to system audit logs",
        risk_level=RiskLevel.LOW,
        base_score=0,
        is_simulated=False,
        requires_approval=False
    ),
    # High-Risk Simulated Actions (SAFE SIMULATIONS ONLY)
    "external_data_transfer": ToolDefinition(
        name="external_data_transfer",
        description="SIMULATED: Exfiltrate or post data payload to external webhook",
        risk_level=RiskLevel.HIGH,
        base_score=70,
        is_simulated=True,
        requires_approval=True
    ),
    "delete_data": ToolDefinition(
        name="delete_data",
        description="SIMULATED: Bulk purge records or database tables",
        risk_level=RiskLevel.CRITICAL,
        base_score=90,
        is_simulated=True,
        requires_approval=True
    ),
    "execute_external_action": ToolDefinition(
        name="execute_external_action",
        description="SIMULATED: Trigger remote API or cloud state modification",
        risk_level=RiskLevel.HIGH,
        base_score=75,
        is_simulated=True,
        requires_approval=True
    )
}

# Input bounds for ToolRequest. These values are written into the in-memory
# audit log, so they must be bounded. Parameters are measured as compact JSON
# length in characters (not UTF-8 bytes) so a maximum-length agent task in any
# script (<= 2048 characters) can never exceed the limit.
MAX_TOOL_NAME_LENGTH = 64
MAX_SOURCE_AGENT_LENGTH = 64
MAX_USER_ROLE_LENGTH = 32
MAX_PARAMETERS_CHARS = 4096

class ToolRequest(BaseModel):
    tool_name: str = Field(..., max_length=MAX_TOOL_NAME_LENGTH)
    parameters: Dict[str, Any] = {}
    source_agent: str = Field("secure_agent", max_length=MAX_SOURCE_AGENT_LENGTH)
    user_role: str = Field("operator", max_length=MAX_USER_ROLE_LENGTH)

    @field_validator("parameters")
    @classmethod
    def _limit_parameters_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        # Stream-encode and stop as soon as the limit is exceeded, so validating
        # a huge payload costs O(limit) instead of building a second huge string.
        encoder = json.JSONEncoder(separators=(",", ":"), ensure_ascii=False)
        total = 0
        try:
            for chunk in encoder.iterencode(value):
                total += len(chunk)
                if total > MAX_PARAMETERS_CHARS:
                    raise ValueError(
                        f"parameters must serialize to at most {MAX_PARAMETERS_CHARS} characters of JSON."
                    )
        except (TypeError, RecursionError):
            raise ValueError("parameters must be JSON-serializable and not excessively nested.")
        return value

class ToolResponse(BaseModel):
    tool_name: str
    decision: str  # ALLOW, BLOCK, REVIEW
    status: str    # ALLOWED, BLOCKED, REVIEW
    event_id: str
    risk_level: str
    score: int
    reason: str
    is_simulated: bool
    requires_human_approval: bool

def _display_name(name: str) -> str:
    """Bound a caller-supplied tool name before it is written into events or responses."""
    if len(name) <= MAX_TOOL_NAME_LENGTH:
        return name
    return name[:MAX_TOOL_NAME_LENGTH] + "..."

class PermissionGateway:
    """
    Deterministic Server-Side Gateway.
    Prevents unauthorized or unvetted AI tool execution.
    """
    def evaluate_request(self, request: ToolRequest) -> ToolResponse:
        tool_name = request.tool_name.strip()
        
        # 1. Unknown Tool Check
        if tool_name not in TOOL_REGISTRY:
            shown_name = _display_name(tool_name)
            event = event_store.log_event(
                event_type="tool_request",
                source=request.source_agent,
                action=f"Request unregistered tool: '{shown_name}'",
                risk_level=RiskLevel.CRITICAL.value,
                score=100,
                status="BLOCKED",
                reason=f"SECURITY VIOLATION: Tool '{shown_name}' is not registered in the Permission Gateway.",
                metadata={"tool_name": shown_name, "parameters": request.parameters}
            )
            return ToolResponse(
                tool_name=shown_name,
                decision="BLOCK",
                status="BLOCKED",
                event_id=event.event_id,
                risk_level=RiskLevel.CRITICAL.value,
                score=100,
                reason=f"SECURITY VIOLATION: Tool '{shown_name}' is not registered.",
                is_simulated=False,
                requires_human_approval=False
            )

        tool = TOOL_REGISTRY[tool_name]

        # 2. Policy Evaluation
        if tool.risk_level == RiskLevel.LOW:
            decision = "ALLOW"
            status = "ALLOWED"
            reason = f"Tool '{tool_name}' is registered as LOW risk and pre-approved for execution."
        elif tool.risk_level == RiskLevel.MEDIUM:
            decision = "ALLOW"
            status = "ALLOWED"
            reason = f"Tool '{tool_name}' is MEDIUM risk; execution allowed with security audit logging."
        elif tool.risk_level == RiskLevel.HIGH:
            decision = "REVIEW"
            status = "REVIEW"
            reason = f"Tool '{tool_name}' is HIGH risk. Execution paused pending human operator approval."
        else: # CRITICAL
            decision = "BLOCK"
            status = "BLOCKED"
            reason = f"Tool '{tool_name}' carries CRITICAL security risk and is automatically blocked by rule policy."

        # 3. Security Event Logging
        event = event_store.log_event(
            event_type="tool_request",
            source=request.source_agent,
            action=f"Tool invocation: '{tool_name}'",
            risk_level=tool.risk_level.value,
            score=tool.base_score,
            status=status,
            reason=reason,
            metadata={
                "tool_name": tool_name,
                "is_simulated": tool.is_simulated,
                "parameters": request.parameters
            }
        )

        return ToolResponse(
            tool_name=tool_name,
            decision=decision,
            status=status,
            event_id=event.event_id,
            risk_level=tool.risk_level.value,
            score=tool.base_score,
            reason=reason,
            is_simulated=tool.is_simulated,
            requires_human_approval=tool.requires_approval
        )

# Global Gateway Instance
permission_gateway = PermissionGateway()
