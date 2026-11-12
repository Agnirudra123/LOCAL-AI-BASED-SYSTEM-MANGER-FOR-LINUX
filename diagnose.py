import json
import re

import requests

from config import MODEL, LLM_URL, REPAIRS

PROMPT = """You are a careful Linux site-reliability assistant. A monitored application is unhealthy.
Read the evidence and choose ONE repair.

Repairs:
__REPAIRS__

Rules:
- Base your choice on the logs and the probes (measurements taken by the monitor). Do not guess.
- If a repair was already tried and failed, do NOT choose the same repair again.
- Choose alert_human when no listed repair can fix the cause.

Reply in English with ONLY a JSON object:
{"cause": "<short root cause>", "repair": "<repair id>", "reason": "<one sentence>"}

Examples:
Problem: HTTP 503. Previous attempts: none. Logs: worker terminated by the OOM killer, memory grew to 2.1 GB
{"cause": "worker killed after running out of memory", "repair": "restart", "reason": "A restart frees the memory and restores the worker."}
Problem: HTTP 500. Previous attempts: none. Logs: could not connect to upstream database 10.0.0.5:5432, timed out
{"cause": "upstream database unreachable", "repair": "alert_human", "reason": "The failure is outside this service and no listed repair addresses it."}"""

SYSTEM_PROMPT = PROMPT.replace(
    "__REPAIRS__", "\n".join(f'- "{k}": {v["desc"]}' for k, v in REPAIRS.items()))


def format_evidence(ev):
    attempts = ", ".join(ev["attempts"]) or "none"
    probes = "\n".join(f"  {k}: {v}" for k, v in ev["probes"].items())
    return (f"Service: {ev['service']}\n"
            f"Problem: {ev['problem']}\n"
            f"Unit state: {ev['unit']}\n"
            f"Probes:\n{probes}\n"
            f"Previous attempts: {attempts}\n"
            f"Recent logs:\n{ev['logs'] or '(no logs)'}")


def llm_decide(ev):
    for _ in range(2):
        try:
            r = requests.post(LLM_URL, json={"model": MODEL,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": format_evidence(ev)}],
                "temperature": 0,
                "max_tokens": 200,
                "response_format": {"type": "json_object"},
            }, timeout=60)
            text = r.json()["choices"][0]["message"]["content"]
            text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
            m = re.search(r"\{.*\}", text, flags=re.S)
            if m:
                d = json.loads(m.group(0))
                d["source"] = "llm"
                return d
        except Exception as e:
            print("[llm]", e)
    repair = "restart" if not ev["attempts"] else "alert_human"
    return {"cause": "model unavailable", "repair": repair,
            "reason": "fallback", "source": "fallback"}


# ---- baselines for the evaluation (no AI) ----

def restart_decide(ev):
    return {"cause": "unknown", "repair": "restart",
            "reason": "always restart", "source": "baseline"}


def rule_decide(ev):
    t = (ev["logs"] + " " + json.dumps(ev["probes"])).lower()
    if "no space left" in t:
        repair = "clear_cache"
    elif "address already in use" in t:
        repair = "free_port"
    elif "permission denied" in t:
        repair = "fix_permissions"
    elif "invalid config" in t:
        repair = "restore_config"
    elif ev["attempts"]:
        repair = "alert_human"
    else:
        repair = "restart"
    return {"cause": "keyword rule", "repair": repair,
            "reason": "keyword rules", "source": "rules"}


DECIDERS = {"llm": llm_decide, "rules": rule_decide, "restart": restart_decide}
