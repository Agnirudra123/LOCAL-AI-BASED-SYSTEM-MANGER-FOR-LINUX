import json
import os
import shutil
import subprocess
import time

import psutil
import requests


def check_http(url, timeout=5, slow_ms=1500):
    start = time.monotonic()
    try:
        r = requests.get(url, timeout=timeout)
        ms = round((time.monotonic() - start) * 1000)
        if r.status_code >= 400:
            return dict(healthy=False, status=r.status_code, latency_ms=ms,
                        problem=f"HTTP {r.status_code}")
        if ms > slow_ms:
            return dict(healthy=False, status=r.status_code, latency_ms=ms,
                        problem=f"slow response ({ms} ms)")
        return dict(healthy=True, status=r.status_code, latency_ms=ms, problem=None)
    except requests.RequestException as e:
        return dict(healthy=False, status=None, latency_ms=None,
                    problem=f"no response ({type(e).__name__})")


def unit_state(unit):
    out = subprocess.run(
        ["systemctl", "--user", "show", unit,
         "-p", "ActiveState,SubState,Result,ExecMainStatus,MainPID"],
        capture_output=True, text=True).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def _collapse(lines):
    out = []
    for line in lines:
        if out and out[-1][0] == line:
            out[-1][1] += 1
        else:
            out.append([line, 1])
    return [f"{l} (x{c})" if c > 1 else l for l, c in out]


def recent_logs(unit, since=None, n=25):
    cmd = ["journalctl", "--user", "-u", unit, "-n", str(n), "--no-pager", "-o", "cat"]
    if since:
        cmd += ["--since", f"@{int(since)}"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    if not out and since:
        return recent_logs(unit, None, 15)
    return "\n".join(_collapse(out.splitlines()))[-1800:]


def port_listeners(port):
    pids = set()
    for c in psutil.net_connections(kind="inet"):
        if c.status == psutil.CONN_LISTEN and c.laddr.port == port and c.pid:
            pids.add(c.pid)
    return sorted(pids)


def _config_state(path):
    try:
        mode = oct(os.stat(path).st_mode & 0o777)
    except FileNotFoundError:
        return "missing"
    try:
        with open(path) as f:
            json.load(f)
        return f"valid JSON, mode {mode}"
    except PermissionError:
        return f"permission denied, mode {mode}"
    except ValueError:
        return f"invalid JSON, mode {mode}"


def probes(cfg, unit):
    """Measurements taken by plain code and handed to the model as evidence."""
    main = int(unit.get("MainPID", "0") or 0)
    owners = []
    for pid in port_listeners(cfg["port"]):
        try:
            name = psutil.Process(pid).name()
        except psutil.Error:
            name = "?"
        owners.append(f"{name} (pid {pid}, {'the service' if pid == main else 'NOT the service'})")
    try:
        du = shutil.disk_usage(cfg["data_dir"])
        disk = f"{du.free / 1e6:.1f} MB free of {du.total / 1e6:.1f} MB"
    except OSError as e:
        disk = f"unavailable ({e})"
    return {
        f"listeners on port {cfg['port']}": ", ".join(owners) or "none",
        "data disk": disk,
        "config file": _config_state(cfg["config"]),
    }
