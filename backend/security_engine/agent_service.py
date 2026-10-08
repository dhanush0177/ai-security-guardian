import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from .permission_gateway import permission_gateway, ToolRequest, TOOL_REGISTRY
from .url_analyzer import analyze_url
from .message_analyzer import analyze_message
from .prompt_analyzer import analyze_prompt
from .approval_manager import approval_manager, ApprovalRecord
from .simulated_tools import execute_simulated_tool

class AgentPlanStep(BaseModel):
    step_number: int
    title: str
    description: str
    status: str  # COMPLETED, IN_PROGRESS, WAITING_HUMAN, BLOCKED, FAILED

class TimelineEvent(BaseModel):
    timestamp: str
    label: str
    detail: str
    type: str  # info, gateway_allow, gateway_review, gateway_block, execution

class AgentTaskResponse(BaseModel):
    task_id: str
    user_task: str
    selected_tool: Optional[str] = None
    plan: List[AgentPlanStep]
    gateway_decision: str  # ALLOW, BLOCK, REVIEW, NONE
    risk_level: str
    score: int
    status: str  # COMPLETED, WAITING_APPROVAL, BLOCKED, UNKNOWN_TASK
    explanation: str
    timeline: List[TimelineEvent]
    execution_result: Optional[Dict[str, Any]] = None
    approval_request: Optional[ApprovalRecord] = None

class SecureAgentService:
    """
    Deterministic Agent Planner & Security Gateway Interface.
    Agent plans & selects tools, but backend Permission Gateway makes the final security decision.
    """
    def execute_task(self, task_input: str) -> AgentTaskResponse:
        task_clean = task_input.strip()
        if not task_clean:
            raise ValueError("Task description cannot be empty.")

        if len(task_clean) > 2048:
            raise ValueError("Task description exceeds maximum length of 2048 characters.")

        now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        timeline: List[TimelineEvent] = []
        
        timeline.append(TimelineEvent(
            timestamp=now_str,
            label="User Task Received",
            detail=f"Task: '{task_clean[:80]}'",
            type="info"
        ))

        # 1. Intent Recognition & Tool Selection
        selected_tool, params = self._select_tool_for_task(task_clean)

        if not selected_tool:
            timeline.append(TimelineEvent(
                timestamp=now_str,
                label="Intent Parser",
                detail="Unable to map request to a registered security tool.",
                type="info"
            ))
            return AgentTaskResponse(
                task_id=f"task_{datetime.now(timezone.utc).strftime('%M%S')}",
                user_task=task_clean,
                selected_tool=None,
                plan=[
                    AgentPlanStep(step_number=1, title="Understand Request", description="Parsed user task", status="COMPLETED"),
                    AgentPlanStep(step_number=2, title="Tool Selection", description="No valid tool matched", status="FAILED")
                ],
                gateway_decision="NONE",
                risk_level="LOW",
                score=0,
                status="UNKNOWN_TASK",
                explanation="Agent could not identify a valid registered tool for this request. No actions were executed.",
                timeline=timeline
            )

        timeline.append(TimelineEvent(
            timestamp=now_str,
            label="Tool Selected",
            detail=f"Selected tool '{selected_tool}' from tool registry.",
            type="info"
        ))

        # 2. Plan Generation
        plan = [
            AgentPlanStep(step_number=1, title="Understand Request", description=f"Identified intent for task '{selected_tool}'", status="COMPLETED"),
            AgentPlanStep(step_number=2, title="Select Security Tool", description=f"Selected tool '{selected_tool}'", status="COMPLETED"),
            AgentPlanStep(step_number=3, title="Permission Gateway", description="Submitting tool request to server gateway", status="IN_PROGRESS"),
            AgentPlanStep(step_number=4, title="Safe Execution", description="Pending gateway clearance", status="IN_PROGRESS")
        ]

        # 3. Server-Side Permission Gateway Evaluation
        tool_req = ToolRequest(
            tool_name=selected_tool,
            parameters=params,
            source_agent="secure_agent",
            user_role="operator"
        )
        gw_res = permission_gateway.evaluate_request(tool_req)

        # 4. Handle Gateway Decisions (ALLOW, REVIEW, BLOCK)
        if gw_res.decision == "ALLOW":
            plan[2].status = "COMPLETED"
            plan[3].status = "COMPLETED"
            
            timeline.append(TimelineEvent(
                timestamp=now_str,
                label="Permission Gateway",
                detail=f"Decision: ALLOWED (Risk: {gw_res.risk_level})",
                type="gateway_allow"
            ))

            # Execute safe tool logic
            exec_result = self._execute_tool_logic(selected_tool, params)

            timeline.append(TimelineEvent(
                timestamp=now_str,
                label="Tool Execution",
                detail=f"Tool '{selected_tool}' executed successfully.",
                type="execution"
            ))

            return AgentTaskResponse(
                task_id=f"task_{datetime.now(timezone.utc).strftime('%M%S')}",
                user_task=task_clean,
                selected_tool=selected_tool,
                plan=plan,
                gateway_decision="ALLOW",
                risk_level=gw_res.risk_level,
                score=gw_res.score,
                status="COMPLETED",
                explanation=gw_res.reason,
                timeline=timeline,
                execution_result=exec_result
            )

        elif gw_res.decision == "REVIEW":
            plan[2].status = "COMPLETED"
            plan[3].status = "WAITING_HUMAN"

            timeline.append(TimelineEvent(
                timestamp=now_str,
                label="Permission Gateway",
                detail=f"Decision: REVIEW REQUIRED (Risk: {gw_res.risk_level})",
                type="gateway_review"
            ))

            # Create human approval record in backend
            approval_rec = approval_manager.create_approval(
                tool_name=selected_tool,
                task_request=task_clean,
                risk_level=gw_res.risk_level,
                reason=gw_res.reason,
                parameters=params,
                event_id=gw_res.event_id
            )

            timeline.append(TimelineEvent(
                timestamp=now_str,
                label="Human Approval Gate",
                detail=f"Approval ID '{approval_rec.approval_id}' created. Execution paused.",
                type="gateway_review"
            ))

            return AgentTaskResponse(
                task_id=f"task_{datetime.now(timezone.utc).strftime('%M%S')}",
                user_task=task_clean,
                selected_tool=selected_tool,
                plan=plan,
                gateway_decision="REVIEW",
                risk_level=gw_res.risk_level,
                score=gw_res.score,
                status="WAITING_APPROVAL",
                explanation=gw_res.reason,
                timeline=timeline,
                approval_request=approval_rec
            )

        else: # BLOCK
            plan[2].status = "COMPLETED"
            plan[3].status = "BLOCKED"

            timeline.append(TimelineEvent(
                timestamp=now_str,
                label="Permission Gateway",
                detail=f"Decision: BLOCKED (Risk: {gw_res.risk_level})",
                type="gateway_block"
            ))

            return AgentTaskResponse(
                task_id=f"task_{datetime.now(timezone.utc).strftime('%M%S')}",
                user_task=task_clean,
                selected_tool=selected_tool,
                plan=plan,
                gateway_decision="BLOCK",
                risk_level=gw_res.risk_level,
                score=gw_res.score,
                status="BLOCKED",
                explanation=gw_res.reason,
                timeline=timeline
            )

    def _select_tool_for_task(self, text: str) -> tuple[Optional[str], Dict[str, Any]]:
        """Deterministically map task intent to registered tool name."""
        t_lower = text.lower()

        # HIGH / CRITICAL RISK ACTION VERBS FIRST
        if any(k in t_lower for k in ["delete", "purge", "wipe", "drop table", "remove logs"]):
            return "delete_data", {"target": "security_logs"}

        if ("transfer" in t_lower or "exfiltrate" in t_lower) and ("external" in t_lower or "webhook" in t_lower or "remote" in t_lower or "report" in t_lower):
            return "external_data_transfer", {"payload": "security_report"}

        if "execute external action" in t_lower or "run remote command" in t_lower:
            return "execute_external_action", {"action": "cloud_sync"}

        # SAFE READ-ONLY ACTIONS NEXT
        if "url" in t_lower or "http" in t_lower or "domain" in t_lower or "link" in t_lower:
            url_match = re.search(r"https?://[^\s]+", text)
            target_url = url_match.group(0) if url_match else "https://example.com"
            return "analyze_url", {"url": target_url}

        if "phish" in t_lower or "message" in t_lower or "sms" in t_lower or "email" in t_lower:
            return "analyze_message", {"message": text}

        if "generate report" in t_lower or "create report" in t_lower or "security report" in t_lower:
            return "generate_report", {"type": "executive_summary"}

        if "view log" in t_lower or "show logs" in t_lower or "security events" in t_lower or "audit log" in t_lower:
            return "view_security_log", {"limit": 10}

        return None, {}

    def _execute_tool_logic(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute safe internal logic or simulation for approved tools."""
        if tool_name == "analyze_url":
            res = analyze_url(params.get("url", "https://example.com"))
            return res.model_dump()
        elif tool_name == "analyze_message":
            res = analyze_message(params.get("message", "Test message"))
            return res.model_dump()
        elif tool_name == "analyze_prompt":
            res = analyze_prompt(params.get("prompt", "Test prompt"))
            return res.model_dump()
        else:
            return execute_simulated_tool(tool_name, params)

# Global Agent Service Instance
secure_agent_service = SecureAgentService()
