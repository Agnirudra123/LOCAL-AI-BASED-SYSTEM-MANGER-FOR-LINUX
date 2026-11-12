import json
import os
import re

import requests

from config import MODEL, LLM_URL, SERVICES
from diagnose import format_evidence

CFG = SERVICES["demo-app"]

PROMPT = """You are a careful Linux site-reliability assistant. A monitored application is unhealthy.
Diagnose it from the evidence and propose a short PLAN of 1 to 3 shell commands, run in order, that fixes it.

Each command is checked by a strict policy before it runs. Only these forms are allowed.
Always use absolute paths. Never use pipes, redirects, quotes, wildcards, semicolons, $, or sudo.
- systemctl --user restart __UNIT__        (also: start, reset-failed, status, is-active)
- systemctl --user stop __UNIT__           (high risk)
- journalctl --user -u __UNIT__ -n 30
- ss -ltnp
- ls -l <path>, df -h <path>, cat <path>, stat <path>   (paths inside __ROOT__/demo or __ROOT__/runtime)
- chmod 600 <path>                         (modes 600, 644, 700, 755; same folders)
- mkdir -p <path>                          (same folders)
- cp __GOOD__ __CONFIG__                   (the only file that may be overwritten is the config)
- rm -f <one named file>                   (only files directly inside __CACHE__)
- kill <pid>                               (only a foreign process listening on port __PORT__)

Rules:
- Base your plan on the logs and the probes (measurements taken by the monitor). Do not guess.
- A fix often has two steps: first remove the cause, then start the service again if it is not running.
  The service is only healthy once it is running and answering again.
- Do not repeat a plan that already failed or was blocked. If a command was blocked, read the reason and fix the form.
- If no allowed command can fix the cause, use an empty plan [].

Reply in English with ONLY a JSON object:
{"cause": "<short root cause>", "commands": ["<command 1>", "<command 2>"], "reason": "<one sentence>"}

Examples:
Problem: HTTP 503. Previous attempts: none. Logs: worker terminated by the OOM killer, memory grew to 2.1 GB
{"cause": "worker killed after running out of memory", "commands": ["systemctl --user restart __UNIT__"], "reason": "A restart frees the memory and restores the worker."}
Problem: HTTP 500. Previous attempts: none. Logs: could not connect to upstream database 10.0.0.5:5432, timed out
{"cause": "upstream database unreachable", "commands": [], "reason": "The failure is outside this service and no allowed command addresses it."}"""

SYSTEM_PROMPT = (PROMPT
                 .replace("__UNIT__", CFG["unit"])
                 .replace("__ROOT__", os.path.dirname(os.path.dirname(CFG["config"])))
                 .replace("__GOOD__", CFG["good_config"])
                 .replace("__CONFIG__", CFG["config"])
                 .replace("__CACHE__", CFG["cache_dir"])
                 .replace("__PORT__", str(CFG["port"])))


def _cache_listing():
    try:
        items = []
        for e in os.scandir(CFG["cache_dir"]):
            if e.is_file(follow_symlinks=False):
                items.append(f"{e.name} ({e.stat().st_size / 1e6:.1f} MB)")
        return ", ".join(items[:10]) or "empty"
    except OSError:
        return "unavailable"


def _normalize(d):
    cmds = d.get("commands", d.get("command", []))
    if isinstance(cmds, str):
        cmds = [cmds]
    if not isinstance(cmds, list):
        cmds = []
    d["command"] = [str(c).strip() for c in cmds
                    if str(c).strip() and str(c).strip().lower() != "none"][:3]
    return d


def command_decide(ev):
    text_in = format_evidence(ev) + f"\nCache directory files: {_cache_listing()}"
    for _ in range(2):
        try:
            r = requests.post(LLM_URL, json={"model": MODEL,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": text_in}],
                "temperature": 0,
                "max_tokens": 300,
                "response_format": {"type": "json_object"},
            }, timeout=60)
            text = r.json()["choices"][0]["message"]["content"]
            text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
            m = re.search(r"\{.*\}", text, flags=re.S)
            if m:
                d = _normalize(json.loads(m.group(0)))
                d["source"] = "llm-commands"
                return d
        except Exception as e:
            print("[llm]", e)
    cmds = [f"systemctl --user restart {CFG['unit']}"] if not ev["attempts"] else []
    return {"cause": "model unavailable", "command": cmds,
            "reason": "fallback", "source": "fallback"}
