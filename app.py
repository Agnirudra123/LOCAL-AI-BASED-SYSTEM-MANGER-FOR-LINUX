"""SelfHeal Unified: Massive Multi-Domain Autonomous SRE Sentinel & Copilot."""
import json, os, re, shutil, subprocess, threading, time, requests, socket
from flask import Flask, jsonify, request

app = Flask(__name__)
HISTORY_FILE = "runtime/history.json"
OLLAMA_URL = "http://127.0.0.1:11434/v1/chat/completions"
MODEL = "selfheal-qwen"

os.makedirs("runtime", exist_ok=True)
current_incident = None
incident_lock = threading.Lock()

COPILOT_PROMPT = """You are an interactive Linux SRE Copilot on Fedora.
Always maintain conversational context.
If you need system data or need to install/fix software, reply ONLY with:
EXEC: <bash command>

PACKAGE RULES:
- VS Code on Fedora: EXEC: sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc && sudo sh -c 'echo -e "[code]\\nname=Visual Studio Code\\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\\nenabled=1\\ngpgcheck=1\\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo' && sudo dnf install -y code
- Spotify: EXEC: flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo && flatpak install -y flathub com.spotify.Client
- Generic Packages: EXEC: sudo dnf install -y <package_name>

CRITICAL RULES:
1. Do NOT output conversational sentences before or inside EXEC.
2. If a command returns 'requires superuser privileges' or 'Permission denied', prepend 'sudo ' to it and execute it immediately."""

SAFE_PATTERN = re.compile(r"^[A-Za-z0-9 _./:=@+,%'-]+$")

def policy_check(cmd):
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 200:
        return False, "empty or too long"
    cmd = cmd.strip()

    # exact-match exception for the DNS fix (needs quotes and >)
    if re.fullmatch(r"sudo sh -c 'echo \"nameserver (\d{1,3}\.){3}\d{1,3}\" > /etc/resolv\.conf'", cmd):
        return True, "ok"

    if not SAFE_PATTERN.match(cmd) or ".." in cmd:
        return False, "forbidden characters"    
    allowed = [
        r"^sudo rm -rf /etc/systemd/system/[a-zA-Z0-9._-]+(\.service)?\.d$",
        r"^sudo rm -f /etc/yum\.repos\.d/[a-zA-Z0-9._-]+\.repo$",
        r"^sudo rm -f /var/lib/rpm/\.rpm\.lock$",
        r"^sudo chmod 644 /etc/(hosts|resolv\.conf)$",
        r"^sudo kill -9 \d+$",
        r"^sudo fuser -k \d{2,5}/tcp$",
        r"^sudo systemctl (daemon-reload|reset-failed)$",
        r"^sudo systemctl (start|restart|stop|enable) [a-zA-Z0-9@._-]+(\.service)?$",
        r"^sudo dnf (clean dbcache|install -y [a-zA-Z0-9._+-]+)$",
        r"^kill -STOP \d+$",
        r"^pkill -KILL -P \d+$",
        r"^sudo sh -c 'echo \"nameserver [0-9.]+\" > /etc/resolv\.conf'$",
    ]
    for pat in allowed:
        if re.fullmatch(pat, cmd):
            return True, "ok"
    return False, "command not whitelisted in policy"

def sudo_cached():
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0

def run_cmd(cmd, sudo_pwd=None, timeout=180):
    try:
        if "sudo " in cmd:
            t = subprocess.run("sudo -n true", shell=True, capture_output=True, text=True, timeout=3)
            if t.returncode != 0 and not sudo_pwd:
                return 401, "SUDO_PASSWORD_REQUIRED"
            if sudo_pwd:
                sudo_cmd = cmd.replace("sudo ", "sudo -S -p '' ", 1)
                r = subprocess.run(sudo_cmd, input=f"{sudo_pwd}\n", shell=True, capture_output=True, text=True, timeout=timeout)
                return r.returncode, (r.stdout + r.stderr).strip()
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return r.returncode, (r.stdout + r.stderr).strip()

        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, f"Command timed out after {timeout} seconds."
    except Exception as e:
        return 1, str(e)

def ask_llm(messages, json_mode=False):
    payload = {"model": MODEL, "messages": messages, "temperature": 0.2, "max_tokens": 500}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=45)
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return json.dumps({"error": str(e)}) if json_mode else f"[AI Error: {e}]"

def extract_command(text):
    cmd = None
    m = re.search(r"EXEC:\s*`?([^\n`]+)`?", text)
    if m:
        cmd = m.group(1).strip()
    else:
        m2 = re.search(r"```(?:bash|sh)?\s*\n([^`]+?)\n```", text)
        if m2:
            lines = [l.strip() for l in m2.group(1).splitlines() if l.strip() and not l.strip().startswith("#")]
            if lines:
                cmd = " && ".join(lines)

    if cmd:
        first_word = cmd.split()[0].lower() if cmd.split() else ""
        if first_word in ["if", "here", "to", "you", "let", "the", "please", "this", "can", "note"]:
            return None
        return cmd
    return None

def get_port_listener(port=8080):
    rc, out = run_cmd(f"ss -ltnp 'sport = :{int(port)}'")
    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', out)
    if m:
        return int(m.group(2)), m.group(1), out.strip()
    return None, None, out.strip()

def get_telemetry():
    pids = len([p for p in os.listdir("/proc") if p.isdigit()])
    pid_max = int(open("/proc/sys/kernel/pid_max").read().strip()) if os.path.exists("/proc/sys/kernel/pid_max") else 32768
    du = shutil.disk_usage("/")

    zombie_count = 0
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                if " Z " in open(f"/proc/{p}/stat").read(): zombie_count += 1
            except: pass

    rc, out = run_cmd("df -i / | tail -n 1")
    inode_pct = 0
    if rc == 0 and len(out.split()) >= 5:
        try: inode_pct = int(out.split()[4].replace('%', ''))
        except: pass

    dns_ok = True
    try:
        socket.gethostbyname("fedoraproject.org")
    except OSError:
        dns_ok = False

    _, failed_out = run_cmd("systemctl --failed --no-legend --plain")
    failed_units = [l.split()[0] for l in failed_out.strip().splitlines() if l]

    pid, _, _ = get_port_listener(8080)
    port_8080_blocked = (pid is not None)
    hosts_ok = os.access("/etc/hosts", os.R_OK)
    resolv_ok = os.access("/etc/resolv.conf", os.R_OK)
    rpm_locked = os.path.exists("/var/lib/rpm/.rpm.lock")

    broken_repos = []
    if os.path.exists("/etc/yum.repos.d"):
        for f in os.listdir("/etc/yum.repos.d"):
            if f.endswith(".repo") and not any(f.startswith(p) for p in ["fedora", "rpmfusion", "google", "vscode", "code"]):
                broken_repos.append(f)

    return {
        "pids": pids, "pid_max": pid_max, "pid_pct": round((pids / pid_max) * 100, 2),
        "disk_free_gb": round(du.free / (1024**3), 1), "disk_pct": round((du.used / du.total) * 100, 1),
        "failed_units": failed_units, "port_8080_blocked": port_8080_blocked,
        "hosts_ok": hosts_ok, "resolv_ok": resolv_ok, "rpm_locked": rpm_locked, 
        "broken_repos": broken_repos, "dns_ok": dns_ok, "zombie_count": zombie_count, "inode_pct": inode_pct
    }

def check_fork_storm():
    try:
        from forkguard import find_top_forkers, neutralize_forker
        top = find_top_forkers()
        if top and top[0][1] >= 150:
            ppid = top[0][0]
            try:
                comm = open(f"/proc/{ppid}/comm").read().strip()
            except OSError:
                comm = ""
            if ppid in (1, os.getpid(), os.getppid()) or comm in {"systemd", "init", "sshd", "bash", "ollama", "sudo"}:
                return None, 0
            neutralize_forker(ppid)
            return ppid, top[0][1]
    except Exception as e:
        print(f"[Sentinel] fork guard error: {e}")
    return None, 0

def background_checker():
    global current_incident
    print("[*] Autonomous Sentinel active: Monitoring 12+ OS health domains...")
    while True:
        time.sleep(2)
        r_pid, count = check_fork_storm()
        if r_pid:
            save_history(f"Fork storm ({count} processes under PID {r_pid})", "Tree freeze & SIGKILL", "RESOLVED")
            continue

        if current_incident and current_incident.get("status") in ("investigating", "pending_approval"):
            continue

        telem = get_telemetry()
        problems = []
        for u in telem["failed_units"]: problems.append(f"Service '{u}' crashed (status: failed)")
        for r in telem["broken_repos"]: problems.append(f"Poisoned repository file detected: /etc/yum.repos.d/{r}")
        if telem["rpm_locked"]: problems.append("Stale RPM database lock (/var/lib/rpm/.rpm.lock) blocking package manager")
        if not telem["hosts_ok"]: problems.append("Permissions on /etc/hosts are corrupted (Unreadable)")
        if not telem["resolv_ok"]: problems.append("Permissions on /etc/resolv.conf are corrupted (Unreadable)")
        if not telem["dns_ok"]: problems.append("System-wide DNS resolution failed (Cannot resolve external domains)")
        if telem["zombie_count"] > 20: problems.append(f"Zombie process accumulation detected ({telem['zombie_count']} zombies)")
        if telem["inode_pct"] > 95: problems.append("Filesystem Inode exhaustion warning (>95% used)")
        if telem["port_8080_blocked"]: problems.append("Port 8080 hijacked by foreign listener")
        if telem["disk_pct"] > 95: problems.append("Root filesystem (/) is critical (>95% full)")

        if problems and not current_incident:
            print(f"\n[Sentinel] 🚨 Problems detected: {problems}")
            with incident_lock:
                current_incident = {
                    "id": int(time.time()), "time": time.strftime("%H:%M:%S"),
                    "problems": problems, "status": "investigating",
                    "trace": [], "cause": "AI is inspecting system evidence...", "commands": []
                }
            threading.Thread(target=autonomous_investigate, args=(problems,), daemon=True).start()

def autonomous_investigate(problems):
    global current_incident
    trace, cmds, cause = [], [], ""
    print(f"[Sentinel] 🤖 SRE investigation started for: {problems}")

    for p in problems:
        m_unit = re.search(r"Service '([^']+)'", p)
        if m_unit:
            u = m_unit.group(1)
            _, cat_out = run_cmd(f"systemctl cat {u}")
            _, j_out = run_cmd(f"journalctl -u {u} -n 12 --no-pager")
            trace.append({"cmd": f"systemctl cat {u}", "out": cat_out[:250]})
            trace.append({"cmd": f"journalctl -u {u} -n 12", "out": j_out[:250]})
            m_drop = re.search(r"# (/etc/systemd/system/[^/]+\.service\.d)", cat_out)
            if m_drop:
                cmds.extend([f"sudo rm -rf {m_drop.group(1)}", "sudo systemctl daemon-reload", f"sudo systemctl restart {u}"])
                cause = f"Corrupted drop-in override in {m_drop.group(1)} crashed {u}."

        if "Poisoned repository" in p:
            m_repo = re.search(r"/etc/yum\.repos\.d/([^\s]+)", p)
            if m_repo:
                repo_file = m_repo.group(1)
                cmds.extend([f"sudo rm -f /etc/yum.repos.d/{repo_file}", "sudo dnf clean dbcache"])
                if not cause: cause = f"Corrupted repository mirror {repo_file} blocks DNF."

        if "RPM database lock" in p:
            cmds.append("sudo rm -f /var/lib/rpm/.rpm.lock")
            if not cause: cause = "Orphaned RPM database lockfile."

        if "hosts are corrupted" in p:
            cmds.append("sudo chmod 644 /etc/hosts")
            if not cause: cause = "Unreadable permissions (000) on /etc/hosts."

        if "resolv.conf are corrupted" in p:
            cmds.append("sudo chmod 644 /etc/resolv.conf")
            if not cause: cause = "Unreadable permissions (000) on /etc/resolv.conf."

        if "DNS resolution failed" in p:
            cmds.append("sudo sh -c 'echo \"nameserver 1.1.1.1\" > /etc/resolv.conf'")
            if not cause: cause = "Dead nameserver in /etc/resolv.conf breaking DNS resolution."

        if "8080 hijacked" in p:
            pid, _, _ = get_port_listener(8080)
            cmds.append(f"sudo kill -9 {pid}" if pid else "sudo fuser -k 8080/tcp")
            if not cause: cause = "Port 8080 hijacked by foreign process."

    plan = []
    for c in dict.fromkeys(cmds):
        ok, why = policy_check(c)
        if ok:
            plan.append(c)
        else:
            trace.append({"cmd": c, "out": "blocked by policy: " + why})

    print(f"[Sentinel] ✅ Fix plan: {plan}")
    with incident_lock:
        if current_incident:
            current_incident.update({
                "trace": trace,
                "cause": cause or "System infrastructure failure diagnosed.",
                "commands": plan,
                "reason": "Clear blocking artifacts and restore system integrity.",
                "status": "pending_approval" if plan else "needs_human",
            })

def save_history(prob, repairs, status):
    h = json.load(open(HISTORY_FILE)) if os.path.exists(HISTORY_FILE) else []
    h.insert(0, {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "problem": prob, "repairs": repairs, "status": status})
    json.dump(h[:50], open(HISTORY_FILE, "w"), indent=2)

threading.Thread(target=background_checker, daemon=True).start()

# -------------------------------------------------------------
# REST API (CHAT & ACTIONS)
# -------------------------------------------------------------
@app.route("/api/state")
def api_state():
    return jsonify({"telemetry": get_telemetry(), "incident": current_incident, "history": json.load(open(HISTORY_FILE)) if os.path.exists(HISTORY_FILE) else []})

@app.route("/api/approve", methods=["POST"])
def api_approve():
    global current_incident
    if not current_incident or current_incident.get("status") != "pending_approval":
        return jsonify({"error": "No incident awaiting approval"}), 400
    pwd = (request.json or {}).get("sudo_password")
    cmds = current_incident.get("commands", [])

    for c in cmds:
        ok, why = policy_check(c)
        if not ok:
            return jsonify({"error": f"Blocked by policy: {c} ({why})"}), 400

    if any(c.startswith("sudo ") for c in cmds) and not pwd and not sudo_cached():
        return jsonify({"sudo_required": True, "command": cmds[0]})

    status = "RESOLVED"
    for c in cmds:
        rc, out = run_cmd(c, sudo_pwd=pwd, timeout=60)
        if rc != 0:
            status = f"FAILED: {out[:40]}"
            break

    save_history(", ".join(current_incident["problems"]), ", ".join(cmds), status)
    with incident_lock: current_incident = None
    return jsonify({"ok": True})

@app.route("/api/chat", methods=["POST"])
def api_chat():
    msg = request.json.get("message", "").strip()
    history = request.json.get("history", [])
    pwd = request.json.get("sudo_password")

    messages = [{"role": "system", "content": COPILOT_PROMPT}] + history[-16:] + [{"role": "user", "content": msg}]
    executed = []

    for step in range(3):
        reply = ask_llm(messages)
        cmd = extract_command(reply)
        if not cmd:
            return jsonify({"reply": reply, "executed": executed})

        if any(e["cmd"] == cmd for e in executed):
            break

        rc, out = run_cmd(cmd, sudo_pwd=pwd, timeout=180)
        clean_out = (out or "(Command executed with no output)")[:1000]

        if rc == 401 and out == "SUDO_PASSWORD_REQUIRED":
            return jsonify({"sudo_required": True, "command": cmd, "message": msg})

        executed.append({"cmd": cmd, "out": clean_out})
        messages += [
            {"role": "assistant", "content": f"```bash\n{cmd}\n```"},
            {"role": "user", "content": f"Terminal Output of `{cmd}`:\n{clean_out}\n\nAnalyze this output. If complete, explain to the user. If another command is needed, output it."}
        ]

    final_reply = ask_llm(messages)
    clean_reply = re.sub(r"```(?:bash|sh)?.*?```", "", final_reply, flags=re.S).strip() or final_reply
    return jsonify({"reply": clean_reply, "executed": executed})

@app.route("/api/inject", methods=["POST"])
def api_inject():
    fault = request.json.get("fault")
    pwd = request.json.get("sudo_password")
    if fault == "crash_service":
        unit = request.json.get("unit", "chronyd")
        run_cmd(f"sudo mkdir -p /etc/systemd/system/{unit}.service.d && echo -e '[Service]\\nExecStart=\\nExecStart=/usr/bin/broken_crash_xyz' | sudo tee /etc/systemd/system/{unit}.service.d/override.conf && sudo systemctl daemon-reload && sudo systemctl restart {unit} || true", sudo_pwd=pwd)
    elif fault == "rpm_lock": run_cmd("sudo touch /var/lib/rpm/.rpm.lock", sudo_pwd=pwd)
    elif fault == "hosts_chmod": run_cmd("sudo chmod 000 /etc/hosts", sudo_pwd=pwd)
    elif fault == "port": subprocess.Popen(["python3", "-m", "http.server", "8080"])
    elif fault == "dns": run_cmd("sudo sh -c 'echo \"nameserver 192.0.2.1\" > /etc/resolv.conf'", sudo_pwd=pwd)
    elif fault == "repo":
        text = "[sysfail-poison]\nname=sysfail poison\nbaseurl=http://invalid-dead-repo.fedoraproject.invalid/\nenabled=1\ngpgcheck=0\nskip_if_unavailable=False\n"
        feed = (f"{pwd}\n" if pwd and not sudo_cached() else "") + text
        subprocess.run(["sudo", "-S", "-p", "", "tee", "/etc/yum.repos.d/sysfail-poison.repo"],
                       input=feed, text=True, stdout=subprocess.DEVNULL)
    return jsonify({"ok": True})

@app.route("/api/reset", methods=["POST"])
def api_reset():
    global current_incident
    pwd = request.json.get("sudo_password")
    run_cmd("sudo rm -rf /etc/systemd/system/*.service.d && sudo systemctl daemon-reload && sudo systemctl reset-failed && sudo chmod 644 /etc/hosts && sudo chmod 644 /etc/resolv.conf && sudo rm -f /var/lib/rpm/.rpm.lock /etc/yum.repos.d/sysfail-poison.repo", sudo_pwd=pwd)
    run_cmd("sudo sh -c 'echo \"nameserver 1.1.1.1\" > /etc/resolv.conf'", sudo_pwd=pwd)
    run_cmd("fuser -k 8080/tcp 2>/dev/null || pkill -9 -f 'http.server 8080' || true")
    run_cmd("sudo systemctl start chronyd || true", sudo_pwd=pwd)
    with incident_lock: current_incident = None
    return jsonify({"ok": True})

# -------------------------------------------------------------
# FRONTEND
# -------------------------------------------------------------
@app.route("/")
def index():
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SelfHeal OS Guardian - B&W Minimalist</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: dark;
    --bg: #000000;
    --card: #0a0a0a;
    --border: #ffffff;
    --text: #ffffff;
    --muted: #a3a3a3;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { min-height: 100vh; background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; padding: 24px; }
  .mono { font-family: 'JetBrains Mono', monospace; }
  h2, h3, strong, th { color: #fff; }
  h2 { font-size: clamp(1.15rem, 2vw, 1.5rem); }
  h3 { font-size: 1rem; line-height: 1.4; }
  p, label, td { color: var(--text); }
  .header { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:14px; padding-bottom:18px; border-bottom:2px solid var(--border); margin-bottom:22px; }
  .grid-6 { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .grid-2 { display: grid; grid-template-columns: 1.25fr 0.75fr; gap: 24px; margin-bottom: 24px; }
  @media(max-width: 1000px) { .grid-2 { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 2px solid var(--border); border-radius: 6px; padding: 18px; }
  .card h3 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 8px; display: flex; justify-content: space-between; }
  .stat-val { font-size: 1.6rem; font-weight: 700; font-family: 'JetBrains Mono'; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; border: 1px solid var(--border); }
  .badge-healthy { background: #fff; color: #000; }
  .badge-danger { background: #000; color: #fff; border-color: #fff; text-decoration: underline; }
  .btn { padding: 8px 16px; border-radius: 4px; border: 2px solid var(--border); font-weight: 700; cursor: pointer; font-size: 0.85rem; background: #000; color: #fff; transition: background 0.1s, color 0.1s; }
  .btn:hover { background: #fff; color: #000; }
  .btn-primary { background: #fff; color: #000; }
  .btn-primary:hover { background: #000; color: #fff; border-color: #fff; }
  .btn-danger-sim { background: #000; color: #fff; border: 1px solid #737373; }
  .btn-danger-sim:hover { background: #262626; }
  .incident-box { border: 2px dashed #fff; background: #000; border-radius: 6px; padding: 20px; margin-bottom: 24px; }
  .chat-box { height: 320px; overflow-y: auto; border: 2px solid var(--border); border-radius: 6px; background: #000; padding: 14px; display: flex; flex-direction: column; gap: 12px; }
  .chat-msg { max-width: 85%; padding: 10px 14px; border-radius: 6px; font-size: 0.88rem; line-height: 1.5; }
  .chat-msg.user { background: #262626; color: #fff; align-self: flex-end; border: 1px solid #737373; }
  .chat-msg.bot { background: #0a0a0a; color: #fff; align-self: flex-start; border: 1px solid var(--border); border-left: 4px solid #fff; }
  .chat-exec { background: #000; border: 1px solid #525252; border-radius: 4px; padding: 6px 10px; margin: 6px 0; font-size: 0.78rem; color: #7dd3fc; }
  .chat-input-row { display: flex; gap: 10px; margin-top: 12px; }
  .chat-input { flex: 1; background: #000; border: 2px solid var(--border); border-radius: 4px; color: #fff; padding: 10px 14px; font: inherit; }
  .chat-input:focus { outline: none; border-color: #fff; background: #0a0a0a; }
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.9); display: none; place-items: center; z-index: 1000; padding: 16px; }
  .modal-card { background: #000; border: 2px solid #fff; border-radius: 8px; padding: 24px; width: min(420px, 100%); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 8px; }
  th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid #333; }
  th { color: #fff; background: #111; border-top: 1px solid #fff; border-bottom: 1px solid #fff; }
  td { color: #f8fafc; overflow-wrap:anywhere; }
</style>
</head>
<body>

<div class="header">
  <div style="display:flex; align-items:center; gap:12px;">
    <div style="border: 2px solid #fff; width: 38px; height: 38px; border-radius: 6px; display:grid; place-items:center; font-size:18px; background:#000;">🛡️</div>
    <div><h2>SelfHeal Sentinel</h2><p>High-Contrast Monochromatic SRE Console</p></div>
  </div>
  <button class="btn" onclick="resetAll()">RESET SYSTEM STATE</button>
</div>

<!-- 6-CARD GRID -->
<div class="grid-6">
  <div class="card">
    <h3>Services <span id="badge-svc" class="badge"></span></h3>
    <div class="stat-val" id="val-svc">0</div>
  </div>
  <div class="card">
    <h3>PIDs / Fork <span id="badge-pids" class="badge badge-healthy">NORMAL</span></h3>
    <div class="stat-val" id="val-pids">--</div>
  </div>
  <div class="card">
    <h3>DNF/RPM <span id="badge-pkg" class="badge"></span></h3>
    <div class="stat-val" id="val-pkg">HEALTHY</div>
  </div>
  <div class="card">
    <h3>DNS Resolution <span id="badge-dns" class="badge"></span></h3>
    <div class="stat-val" id="val-dns">ONLINE</div>
  </div>
  <div class="card">
    <h3>Zombie Procs <span id="badge-zomb" class="badge"></span></h3>
    <div class="stat-val" id="val-zomb">0</div>
  </div>
  <div class="card">
    <h3>Disk Free (/) <span class="badge badge-healthy">STORAGE</span></h3>
    <div class="stat-val" id="val-disk">--</div>
  </div>
</div>

<!-- LIVE INCIDENT BOX -->
<div id="incident-box" class="incident-box" style="display:none;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
    <strong style="font-size:1.05rem; letter-spacing:0.05em;">[!] SYSTEM INCIDENT DETECTED</strong>
    <span id="inc-status" class="badge badge-danger">PENDING</span>
  </div>
  <div id="inc-desc" style="font-size:0.9rem; margin-bottom:12px;"></div>

  <div style="margin-bottom:12px;">
    <div style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:4px;">Diagnostic Evidence:</div>
    <div id="inc-trace" class="mono" style="background:#000; border:1px solid #444; padding:8px; border-radius:4px; font-size:0.75rem; max-height:120px; overflow-y:auto;"></div>
  </div>

  <div id="inc-plan-container" style="display:none; margin-bottom:14px;">
    <div style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:4px;">Synthesized Fix Plan:</div>
    <div id="inc-cmds" class="mono" style="background:#000; border:1px solid #fff; padding:8px; border-radius:4px; font-size:0.8rem; color:#fff;"></div>
  </div>

  <button class="btn btn-primary" id="inc-btn" style="display:none;" onclick="approve()">⚡ EXECUTE FIX PLAN</button>
</div>

<div class="grid-2">
  <div class="card">
    <h3 style="margin-bottom:10px;">💬 AI Copilot Terminal</h3>
    <div class="chat-box" id="chat-messages">
      <div class="chat-msg bot">👋 Ask any question or request maintenance. Commands run live.</div>
    </div>
    <div class="chat-input-row">
      <input type="text" id="chat-input" class="chat-input" placeholder="Type prompt here..." onkeydown="if(event.key==='Enter') sendChat()">
      <button class="btn btn-primary" id="chat-btn" onclick="sendChat()">SEND</button>
    </div>
  </div>

  <div class="card">
    <h3 style="margin-bottom:10px;">Fault Playground</h3>
    <p style="font-size:0.8rem; color:var(--muted); margin-bottom:12px;">Simulate real OS failures to test autonomous healing:</p>
    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:20px;">
      <button class="btn btn-danger-sim" onclick="inject('crash_service', 'chronyd')">💥 Crash Chrony</button>
      <button class="btn btn-secondary" onclick="inject('repo')">🗄️ Poison Repo</button>
      <button class="btn btn-secondary" onclick="inject('rpm_lock')">📦 Stale RPM Lock</button>
      <button class="btn btn-secondary" onclick="inject('dns')">🌐 Break DNS</button>
      <button class="btn btn-secondary" onclick="inject('port')">🔌 Hijack Port 8080</button>
    </div>
    <h3 style="margin-bottom:8px;">Incident Audit Log</h3>
    <table>
      <thead><tr><th>Time</th><th>Problem</th><th>Fix</th><th>Status</th></tr></thead>
      <tbody id="hist-tbody"><tr><td colspan="4" style="text-align:center; color:var(--muted);">No history recorded.</td></tr></tbody>
    </table>
  </div>
</div>

<div class="modal-overlay" id="sudo-modal">
  <div class="modal-card">
    <h3 style="color:#fff; margin-bottom:8px;">🔒 SUDO AUTHORIZATION</h3>
    <p style="font-size:0.85rem; color:var(--muted); margin-bottom:12px;">Privileged command required: <div id="modal-cmd" class="mono" style="color:#fff; font-size:0.8rem; margin:8px 0; background:#111; padding:6px; border:1px solid #444;"></div></p>
    <input type="password" id="modal-pwd" class="chat-input" style="width:100%; margin-bottom:14px;" placeholder="Enter Sudo Password" onkeydown="if(event.key==='Enter') submitSudo()">
    <div style="display:flex; justify-content:flex-end; gap:10px;">
      <button class="btn btn-secondary" onclick="document.getElementById('sudo-modal').style.display='none'">CANCEL</button>
      <button class="btn btn-primary" onclick="submitSudo()">AUTHORIZE</button>
    </div>
  </div>
</div>

<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let chatHistory = [], sudoPwd = null, pendingAction = null;

async function sendChat(forcePwd = null) {
  const inp = document.getElementById('chat-input'), msg = forcePwd ? pendingAction.msg : inp.value.trim();
  if (!msg) return;
  if (!forcePwd) { inp.value = ''; appendMsg('user', msg); chatHistory.push({role:'user', content:msg}); }
  document.getElementById('chat-btn').textContent = '...';

  const res = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({message:msg, history:chatHistory, sudo_password:forcePwd||sudoPwd})});
  const data = await res.json();
  if (data.sudo_required) {
    pendingAction = {type:'chat', msg:msg, cmd:data.command};
    openSudo(data.command);
    document.getElementById('chat-btn').textContent = 'SEND';
    return;
  }
  appendMsg('bot', data.reply, data.executed);
  chatHistory.push({role:'assistant', content:data.reply});
  document.getElementById('chat-btn').textContent = 'SEND';
}

async function approve(forcePwd = null) {
  const res = await fetch('/api/approve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({sudo_password:forcePwd||sudoPwd})});
  const data = await res.json();
  if (data.sudo_required) { pendingAction = {type:'approve', cmd:data.command}; openSudo(data.command); return; }
  if (data.error) { alert(data.error); }
  refresh();
}

function openSudo(cmd) {
  document.getElementById('modal-cmd').textContent = cmd;
  document.getElementById('modal-pwd').value = '';
  document.getElementById('sudo-modal').style.display = 'grid';
  document.getElementById('modal-pwd').focus();
}

function submitSudo() {
  const p = document.getElementById('modal-pwd').value;
  if (!p) return;
  sudoPwd = p;
  document.getElementById('sudo-modal').style.display = 'none';
  if (pendingAction.type === 'approve') approve(p);
  else sendChat(p);
}

function appendMsg(role, txt, executed) {
  const b = document.getElementById('chat-messages'), d = document.createElement('div');
  d.className = 'chat-msg ' + role;
  let cmdHtml = '';
  if (executed && executed.length > 0) {
    cmdHtml = executed.map(e => `
      <div class="chat-exec mono">
        <div style="font-weight:700; color:#fff;">$ ${esc(e.cmd)}</div>
        <div style="color:#a3a3a3; font-size:0.7rem; white-space:pre-wrap; margin-top:2px;">${esc(e.out.slice(0, 250))}</div>
      </div>
    `).join('');
  }
  d.innerHTML = cmdHtml + esc(txt).replace(/\n/g, '<br>');
  b.appendChild(d); b.scrollTop = b.scrollHeight;
}

async function refresh() {
  const res = await fetch('/api/state'), data = await res.json(), t = data.telemetry, inc = data.incident;
  
  document.getElementById('val-svc').textContent = t.failed_units.length;
  document.getElementById('badge-svc').className = 'badge ' + (t.failed_units.length === 0 ? 'badge-healthy' : 'badge-danger');
  document.getElementById('badge-svc').textContent = t.failed_units.length === 0 ? 'CLEAN' : t.failed_units.length + ' FAILED';

  document.getElementById('val-pids').textContent = t.pids;
  document.getElementById('badge-pids').textContent = t.pid_pct + '%';

  const pkgEl = document.getElementById('val-pkg');
  const badgePkg = document.getElementById('badge-pkg');
  if (t.broken_repos && t.broken_repos.length > 0) {
    pkgEl.textContent = 'POISONED';
    badgePkg.className = 'badge badge-danger';
    badgePkg.textContent = 'REPO';
  } else if (t.rpm_locked) {
    pkgEl.textContent = 'LOCKED';
    badgePkg.className = 'badge badge-danger';
    badgePkg.textContent = 'RPM LOCK';
  } else {
    pkgEl.textContent = 'HEALTHY';
    badgePkg.className = 'badge badge-healthy';
    badgePkg.textContent = 'OK';
  }

  const dnsEl = document.getElementById('val-dns');
  const badgeDns = document.getElementById('badge-dns');
  if (t.dns_ok) {
    dnsEl.textContent = 'ONLINE';
    badgeDns.className = 'badge badge-healthy';
    badgeDns.textContent = 'OK';
  } else {
    dnsEl.textContent = 'DEAD';
    badgeDns.className = 'badge badge-danger';
    badgeDns.textContent = 'FAIL';
  }

  const zombEl = document.getElementById('val-zomb');
  const badgeZomb = document.getElementById('badge-zomb');
  zombEl.textContent = t.zombie_count;
  if (t.zombie_count > 20) {
    badgeZomb.className = 'badge badge-danger';
    badgeZomb.textContent = 'CRITICAL';
  } else {
    badgeZomb.className = 'badge badge-healthy';
    badgeZomb.textContent = 'CLEAN';
  }

  document.getElementById('val-disk').textContent = t.disk_free_gb + ' GB';

  const ibox = document.getElementById('incident-box');
  if (inc) {
    ibox.style.display = 'block';
    document.getElementById('inc-status').textContent =
      inc.status === 'investigating' ? 'ANALYZING...' :
      inc.status === 'needs_human' ? 'NEEDS HUMAN' : 'READY';

    document.getElementById('inc-desc').innerHTML = `
      <strong>Symptoms:</strong> ${esc(inc.problems.join(', '))}<br>
      <strong>Root Cause:</strong> <span style="color:#fff;">${esc(inc.cause)}</span>
    `;

    const traceEl = document.getElementById('inc-trace');
    if (inc.trace && inc.trace.length > 0) {
      traceEl.innerHTML = inc.trace.map(s => `<div>$ ${esc(s.cmd)}<br><span style="color:#a3a3a3; white-space:pre-wrap;">${esc(s.out)}</span></div>`).join('<hr style="border:0; border-top:1px solid #333; margin:4px 0;">');
    } else {
      traceEl.innerHTML = `<em>Inspecting system evidence...</em>`;
    }

    if (inc.status === 'pending_approval') {
      document.getElementById('inc-plan-container').style.display = 'block';
      document.getElementById('inc-cmds').innerHTML = inc.commands.map(esc).join('<br>');
      document.getElementById('inc-btn').style.display = 'inline-block';
    } else {
      document.getElementById('inc-plan-container').style.display = 'none';
      document.getElementById('inc-btn').style.display = 'none';
    }
  } else {
    ibox.style.display = 'none';
  }

  document.getElementById('hist-tbody').innerHTML = (data.history||[]).slice(0, 5).map(h => `<tr><td>${esc(h.time.slice(11))}</td><td style="color:#fff">${esc(h.problem.slice(0,25))}</td><td class="mono">${esc(h.repairs.slice(0,25))}</td><td>${esc(h.status)}</td></tr>`).join('');
}

async function inject(f, unit) { await fetch('/api/inject', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({fault:f, unit:unit, sudo_password:sudoPwd})}); refresh(); }
async function resetAll() { await fetch('/api/reset', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({sudo_password:sudoPwd})}); refresh(); }
setInterval(refresh, 2000); refresh();
</script>
</body>
</html>
"""
if __name__ == "__main__":
    print("Serving B&W Sentinel on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
