from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from security_engine.risk_engine import AnalysisResponse
from security_engine.url_analyzer import analyze_url
from security_engine.message_analyzer import analyze_message
from security_engine.prompt_analyzer import analyze_prompt
from security_engine.permission_gateway import permission_gateway, ToolRequest, ToolResponse
from security_engine.event_logger import event_store, SecurityEvent
from security_engine.agent_service import secure_agent_service, AgentTaskResponse
from security_engine.approval_manager import approval_manager, ApprovalRecord
from security_engine.attack_lab import run_all_attack_lab_scenarios, run_attack_lab_scenario, AttackLabSuiteResult, ScenarioResult
from security_engine.report_generator import generate_security_report, SecurityReport

app = FastAPI(
    title="AI Security Guardian API",
    description="Deterministic Security Rule Engine & Permission Gateway for AI Systems",
    version="1.0.0"
)

# Enable CORS for local development frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL string to analyze")

class MessageScanRequest(BaseModel):
    message: str = Field(..., description="Email or SMS message content to analyze")

class PromptScanRequest(BaseModel):
    prompt: str = Field(..., description="AI prompt input text to inspect for injections")

class AgentTaskRequest(BaseModel):
    task: str = Field(..., description="User security task description for the agent")

class ApprovalRequest(BaseModel):
    event_id: str = Field(..., description="Security event ID to review")
    decision: str = Field(..., description="APPROVED or REJECTED")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "AI Security Guardian",
        "tagline": "Analyze threats. Control AI actions. Stay in control.",
        "version": "1.0.0"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "components": {
            "risk_engine": "active",
            "url_analyzer": "active",
            "message_analyzer": "active",
            "prompt_analyzer": "active",
            "permission_gateway": "active",
            "event_logger": "active",
            "secure_agent": "active",
            "approval_manager": "active",
            "attack_lab": "active",
            "report_generator": "active"
        }
    }

# 1. URL Threat Scanner Endpoint
@app.post("/api/analyze/url", response_model=AnalysisResponse)
def analyze_url_endpoint(payload: URLScanRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL input cannot be empty.")
    try:
        result = analyze_url(payload.url)
        event_store.log_event(
            event_type="url_scan",
            source="threat_scanner",
            action=f"Scanned URL: {payload.url[:60]}",
            risk_level=result.risk_level.value,
            score=result.score,
            status="BLOCKED" if result.risk_level.value in ["HIGH", "CRITICAL"] else "ALLOWED",
            reason=result.explanation,
            metadata={"indicators_count": len(result.indicators)}
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing the URL scan.")

# 2. Message Threat Scanner Endpoint
@app.post("/api/analyze/message", response_model=AnalysisResponse)
def analyze_message_endpoint(payload: MessageScanRequest):
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message input cannot be empty.")
    try:
        result = analyze_message(payload.message)
        event_store.log_event(
            event_type="message_scan",
            source="threat_scanner",
            action=f"Scanned Message: {payload.message[:60]}",
            risk_level=result.risk_level.value,
            score=result.score,
            status="BLOCKED" if result.risk_level.value in ["HIGH", "CRITICAL"] else "ALLOWED",
            reason=result.explanation,
            metadata={"indicators_count": len(result.indicators)}
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing the message scan.")

# 3. AI Prompt Injection Scanner Endpoint
@app.post("/api/analyze/prompt", response_model=AnalysisResponse)
def analyze_prompt_endpoint(payload: PromptScanRequest):
    if not payload.prompt or not payload.prompt.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Prompt input cannot be empty.")
    try:
        result = analyze_prompt(payload.prompt)
        event_store.log_event(
            event_type="prompt_scan",
            source="threat_scanner",
            action=f"Scanned Prompt: {payload.prompt[:60]}",
            risk_level=result.risk_level.value,
            score=result.score,
            status="BLOCKED" if result.risk_level.value in ["HIGH", "CRITICAL"] else "ALLOWED",
            reason=result.explanation,
            metadata={"indicators_count": len(result.indicators)}
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing the prompt injection scan.")

# 4. Agent Task Dispatcher Endpoint
@app.post("/api/agent/task", response_model=AgentTaskResponse)
def agent_task_endpoint(payload: AgentTaskRequest):
    if not payload.task or not payload.task.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Task description cannot be empty.")
    try:
        return secure_agent_service.execute_task(payload.task)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while executing the agent task.")

# 5. Tool Request Endpoint (Direct Gateway Access)
@app.post("/api/agent/tool-request", response_model=ToolResponse)
def tool_request_endpoint(payload: ToolRequest):
    if not payload.tool_name or not payload.tool_name.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tool name cannot be empty.")
    try:
        return permission_gateway.evaluate_request(payload)
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred in the Permission Gateway.")

# 6. Get Pending Human Approvals Endpoint
@app.get("/api/agent/approvals", response_model=List[ApprovalRecord])
def get_pending_approvals_endpoint():
    return approval_manager.get_pending_approvals()

# 7. Approve Human Gate Endpoint
@app.post("/api/agent/approvals/{approval_id}/approve")
def approve_human_gate_endpoint(approval_id: str):
    try:
        return approval_manager.approve_request(approval_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing approval.")

# 8. Reject Human Gate Endpoint
@app.post("/api/agent/approvals/{approval_id}/reject")
def reject_human_gate_endpoint(approval_id: str):
    try:
        return approval_manager.reject_request(approval_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing rejection.")

# 9. Attack Lab Suite Runner Endpoint
@app.get("/api/attack-lab/suite", response_model=AttackLabSuiteResult)
def run_attack_lab_suite_endpoint():
    return run_all_attack_lab_scenarios()

# 10. Attack Lab Single Scenario Runner Endpoint
@app.post("/api/attack-lab/scenario/{scenario_id}", response_model=ScenarioResult)
def run_attack_lab_scenario_endpoint(scenario_id: str):
    try:
        return run_attack_lab_scenario(scenario_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while running the Attack Lab scenario.")

# 11. Security Reports Generator Endpoint
@app.get("/api/reports/security", response_model=SecurityReport)
def get_security_report_endpoint():
    return generate_security_report()

# 12. Security Event Log Feed with Query Filtering
@app.get("/api/security/events", response_model=List[SecurityEvent])
def get_security_events(limit: int = Query(50, ge=1, le=200), status: Optional[str] = None):
    return event_store.get_events(limit=limit, status=status)

# 13. Security System Statistics
@app.get("/api/security/stats")
def get_security_stats():
    return event_store.get_stats()

# 14. Legacy Human Approval Endpoint for Event Log
@app.post("/api/security/approval")
def security_approval_endpoint(payload: ApprovalRequest):
    decision_clean = payload.decision.upper().strip()
    if decision_clean not in ["APPROVED", "REJECTED"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Decision must be 'APPROVED' or 'REJECTED'.")
    
    event = event_store.get_event_by_id(payload.event_id)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Security event '{payload.event_id}' not found.")
    
    updated_event = event_store.update_event_status(
        event_id=payload.event_id,
        new_status=decision_clean,
        reason_update=f"Human Operator Decision: {decision_clean}"
    )
    return {
        "status": "success",
        "event_id": payload.event_id,
        "new_status": decision_clean,
        "event": updated_event
    }
