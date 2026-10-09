# AI Security Guardian

> **Tagline:** *"Analyze threats. Control AI actions. Stay in control."*
>
> **Hackathon Track:** AI-Powered Cybersecurity & Digital Safety

---

## 🛡️ Executive Summary

**AI Security Guardian** is an enterprise-grade cybersecurity control system and server-side Permission Gateway designed to protect modern applications and autonomous AI agent workflows from adversarial threats.

As organizations deploy LLM agents capable of calling tools, accessing databases, and executing web hooks, security cannot rely on prompt engineering or LLM self-governance alone. **AI Security Guardian enforces a fundamental security principle:**

> ⚠️ **Core Security Principle:** The LLM is NEVER the sole authority for security decisions. Security decisions MUST be enforced by deterministic server-side backend logic.

---

## 🎯 The Problem

1. **AI Prompt Injection & Jailbreaks:** Attackers can trick LLMs into overriding developer instructions, leaking secret API keys, or executing unauthorized system actions.
2. **Unrestricted Agent Tools:** Autonomous AI agents given access to APIs or databases can be manipulated into transferring data externally or deleting records.
3. **Phishing & Social Engineering:** Users and automated systems are constantly targeted with malicious URLs, homograph domain attacks, and urgent phishing messages.

---

## 💡 The Solution

AI Security Guardian provides a multi-layer deterministic defense system:

```
[ Frontend Shell ]
       ↓
[ Backend API ]
       ↓
[ Security Rules / Engine ]
       ↓
[ Deterministic Risk Engine (0–100) ]
       ↓
[ Server-Side Permission Gateway ]
       ↓
 ┌───────────────┬──────────────────────────┬──────────────┐
 │ ALLOW (Low)   │ REVIEW (High / Human Gate)│ BLOCK (Crit) │
 │               │                          │              │
 │ Safe execution│ Pauses; Requires Human   │ Execution    │
 │               │ Operator Approval        │ Intercepted  │
 └───────────────┴──────────────────────────┴──────────────┘
       ↓
[ Simulated Tool Execution (Zero Real Risk) ]
       ↓
[ Append-Only Event Logger ]
```

---

## ✨ Key Features

1. **Deterministic Threat Scanner:**
   * **URL Scanner:** Safe string-based analysis for IP hostnames, punycode homographs, unencrypted HTTP, suspicious TLDs (`.top`, `.xyz`), and user embedding (`@`).
   * **Phishing Message Analyzer:** Identifies urgency tactics, credential harvesting, OTP soliciting, and financial scams.
   * **AI Prompt Injection Detector:** Flags instruction overrides, system prompt extraction, secret leakage attempts, and jailbreak frameworks (DAN mode).
2. **Secure AI Agent Playground:**
   * Autonomous agent planner that constructs a 4-step execution plan for user security tasks.
   * Tool calls pass through the server-side Permission Gateway before execution.
3. **Server-Side Permission Gateway & Human Approval Gate:**
   * Tool permissions categorized by risk: `LOW` (ALLOW), `MEDIUM` (ALLOW + LOG), `HIGH` (REVIEW - Human Approval Required), `CRITICAL` (BLOCK).
   * High-risk actions automatically pause agent execution until a human operator approves or rejects the request via backend API.
4. **Real-Time Security Event Monitoring:**
   * Append-only telemetry log table, filterable by Risk Level, Gateway Status, and Event Type.
   * Includes clickable Event Detail Modals and dynamic KPI cards.
5. **Defensive Attack Lab Sandbox:**
   * Local testing sandbox with 6 preloaded adversarial scenarios evaluating live rule resilience and calculating an objective Protection Score percentage.
6. **Executive Security Assessment Reports:**
   * Dynamically compiled security report summarizing threat breakdown and actionable security recommendations with browser print output support.

---

## 🛠️ Technology Stack

* **Frontend:** React 19, Vite, TypeScript, Vanilla CSS Modules (`theme.css`), Lucide Icons.
* **Backend:** Python 3.13, FastAPI, Pydantic v2, Uvicorn, Python `unittest` test suite.
* **Security & Testing:** 100% deterministic rule algorithms, zero external network requests during scans, safe simulated high-risk tool actions.

---

## ⚡ Quick Start & Local Setup

### Prerequisites
* **Node.js:** v18+ (Tested on Node v24)
* **Python:** v3.10+ (Tested on Python 3.13)

### 1. Start Backend API Server
```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```
* API Root: `http://localhost:8000`
* Interactive API Docs (Swagger): `http://localhost:8000/docs`

### 2. Start Frontend UI
```bash
cd frontend
npm install
npm run dev
```
* Frontend Application: `http://localhost:5173`

---

## 🧪 Automated Testing

The project includes 44 automated backend unit and integration tests covering all risk engine logic, gateway policies, agent workflows, attack lab scenarios, and API endpoints:

```bash
# Run all backend test suites
python backend/tests/test_security_engine.py
python backend/tests/test_agent_workflow.py
python backend/tests/test_phase4.py
python backend/tests/verify_endpoints.py
```
**Test Result:** `44/44 Passed (100% Success)`

---

## 🔒 Security Considerations & Demo Disclosures

1. **Safe High-Risk Simulation:** High-risk actions (`external_data_transfer`, `delete_data`, `execute_external_action`) are strictly simulated. **No real files are deleted, no shell commands are executed, and no external web traffic is generated.**
2. **Demo Data Disclosure:** Initial event logger telemetry includes seeded baseline demonstration events clearly tagged with a `DEMO` badge.
3. **No External URL Fetching:** The URL analyzer inspects string structures and heuristics without making HTTP requests to external domains.

---

## 🌐 Deployment & Live Demo

### Live Application

- **Frontend:** https://ai-security-guardian.vercel.app/
- **Backend API:** https://ai-security-guardian-api.onrender.com/
- **Interactive API Documentation:** https://ai-security-guardian-api.onrender.com/docs

The frontend is deployed on Vercel, and the backend API is hosted on Render. The frontend communicates with the backend to perform security analysis and enforce server-side permission decisions.

*Note: The backend may take some time to respond after periods of inactivity.*

### Frontend Deployment (Vercel)

- **Build Command:** `npm run build`
- **Output Directory:** `dist`
- **Environment Variable:** `VITE_API_URL=https://ai-security-guardian-api.onrender.com`

### Backend Deployment (Render)

- **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Python Version:** `3.13`
- **Dependencies:** Defined in `backend/requirements.txt`

### Local Development

Follow the Quick Start & Local Setup instructions above to run the frontend and backend locally.
---

## 🎬 Hackathon Judge Demo Walkthrough (9 Steps)

1. **Step 1 — Dashboard Overview:** Open `http://localhost:5173`. Highlight the dynamic System Status (`PROTECTED` / `ATTENTION REQUIRED`), live health KPI cards, and quick action buttons.
2. **Step 2 — Safe URL Scan:** Click **Threat Scanner** $\rightarrow$ **URL Scanner**. Click preset `"Safe University URL"`. Click **Analyze Threat**. Observe `LOW` risk score (0-24) and safe explanation.
3. **Step 3 — Phishing Message Analysis:** Click **Phishing Message Analyzer** tab. Click preset `"Phishing SMS & OTP Harvesting"`. Observe `HIGH / CRITICAL` risk score and detected threat indicators.
4. **Step 4 — Prompt Injection Detection:** Click **AI Prompt Injection Detector** tab. Click preset `"System Prompt Extraction"`. Observe `HIGH` risk rating blocking prompt override.
5. **Step 5 — Secure Agent (Safe Task):** Click **Secure Agent**. Click scenario `"1. Safe URL Scan"`. Observe the 4-step plan visualization and `ALLOWED` gateway decision.
6. **Step 6 — Secure Agent (Human Approval Gate):** Click scenario `"3. Data Transfer (HIGH Risk)"`. Observe task status pause at `WAITING FOR HUMAN APPROVAL`. Click **APPROVE** to demonstrate backend verification and safe simulation execution.
7. **Step 7 — Attack Lab Sandbox:** Click **Attack Lab**. Click **RUN ALL TESTS**. Observe 6/6 scenarios executing against live backend engines achieving a `100% Protection Score`.
8. **Step 8 — Monitoring Telemetry:** Click **Monitoring**. Filter events by status `BLOCKED` or risk `HIGH`. Click an event row to inspect the detail modal.
9. **Step 9 — Executive Security Report:** Click **Reports**. Click **Generate Report**. Review executive metrics, risk breakdown, and actionable recommendations. Click **Print Report** for PDF export.
