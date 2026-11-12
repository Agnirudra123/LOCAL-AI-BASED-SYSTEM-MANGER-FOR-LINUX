# 🛡️ selfheal: Local AI-Based System Manager for Linux

> An intelligent, local-first infrastructure control loop that monitors Linux systems, diagnoses runtime anomalies, and executes multi-step remediation workflows autonomously, with **zero cloud dependency** and **rigid security guardrails**.

---
<img width="1914" height="1004" alt="Screenshot From 2026-11-12 12-34-59" src="https://github.com/user-attachments/assets/c70681fb-89e4-4c4c-880b-10b324d7cc4e" />

## 🌟 Overview

Traditional system administration relies on fragile static scripts or manual intervention during outages. **selfheal** bridges the gap between AI reasoning and deterministic systems engineering by treating a local LLM as a problem-solving agent operating inside a secure feedback loop.

### Architecture

```text
[ System Telemetry & Logs ]
            ↓
[ Evidence Packaging (diagnose.py) ]
            ↓
[ Multi-Step ReAct Reasoning (agent.py + Ollama Qwen 2.5) ]
            ↓
[ Deterministic Security Gatekeeper (policy.py) ]
            ↓
[ Sandboxed OS Actuation & Verification ]
```
<img width="1914" height="1004" alt="Screenshot From 2026-11-12 12-34-50" src="https://github.com/user-attachments/assets/46630ba3-f079-41b5-b3ce-798cde07e340" />

---

## 📂 Codebase Module Breakdown

The project is organized into a modular, security-focused architecture:

| Module | Purpose & Functionality |
|--------|-------------------------|
| `agent.py` | Implements the multi-step **ReAct (Reason + Act)** loop. Guides the local model through iterative diagnostic investigations (using read-only commands) before committing to a structured fix plan. |
| `policy.py` | The **deterministic security gatekeeper**. Intercepts every proposed remediation command, enforcing strict path whitelists, argument validation, and blocking dangerous patterns (wildcards, privilege escalation, arbitrary shell piping). |
| `llm.py` | Manages communication with Ollama and handles context-window budgeting so long investigation traces never overflow the model's memory limits. |
| `diagnose.py` | Packages live system telemetry, health probes, and `journalctl` logs into structured **Evidence Packets** for the LLM to analyze. |
| `health.py` | Continuous probe monitor that tracks service states, socket bindings, and system metrics. |
| `inject.py` | Chaos-engineering module for testing resilience by deliberately introducing configuration faults, permission locks, and poisoned package repositories. |

---
<img width="1914" height="1004" alt="Screenshot From 2026-11-12 12-33-43" src="https://github.com/user-attachments/assets/b71bd8b6-f6b8-42cd-a69b-41f21c22c5a3" />

## ⚙️ Key Technical Highlights

- **🔒 100% Local Execution:** Runs entirely offline on open-weight models (`selfheal-qwen` / `llama3.2:3b`) via Ollama, giving full data privacy and zero cloud API latency.
- **🚧 Bounded Autonomy:** The LLM never writes raw shell commands to the terminal. It outputs *structured intent*, which is translated and validated by rigid Python security checks.
- **🔁 Closed-Loop Verification:** The agent evaluates the output of each investigative command, letting it adapt dynamically to cascading system errors in real time.

---

## 🧰 Tech Stack

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-000000?logo=ollama&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)
![systemd](https://img.shields.io/badge/systemd-journalctl-lightgrey)
