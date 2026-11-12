"""Fork bomb detector and active killer.
Monitors system PID consumption and identifies fast-spawning process trees."""
import os
import signal
import subprocess
import time

PID_MAX_PATH = "/proc/sys/kernel/pid_max"


def get_pid_max():
    try:
        with open(PID_MAX_PATH, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 32768


def count_system_pids():
    """Count running processes via /proc."""
    return len([p for p in os.listdir("/proc") if p.isdigit()])


def find_top_forkers():
    """Identifies users/PPIDs holding an abnormally high number of child processes."""
    counts = {}
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        try:
            with open(f"/proc/{pid_str}/status", "r") as f:
                ppid = None
                uid = None
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
                if ppid is not None and uid is not None and uid != 0:  # ignore kernel/root
                    counts[ppid] = counts.get(ppid, 0) + 1
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


def neutralize_forker(ppid):
    """Halts process tree with SIGSTOP first to prevent further forking, then kills with SIGKILL."""
    print(f"[!] NEUTRALIZING FORK STORM AT ROOT PID {ppid}...")
    try:
        # Step 1: Freeze parent to stop fork loop
        os.kill(ppid, signal.SIGSTOP)

        # Step 2: Kill all children
        subprocess.run(["pkill", "-STOP", "-P", str(ppid)], check=False)
        time.sleep(0.1)
        subprocess.run(["pkill", "-KILL", "-P", str(ppid)], check=False)

        # Step 3: Kill parent
        os.kill(ppid, signal.SIGKILL)
        print(f"[+] Root PID {ppid} and children neutralized.")
        return True
    except ProcessLookupError:
        return False
    except Exception as e:
        print(f"[-] Error neutralizing PID {ppid}: {e}")
        return False


def check_fork_bomb():
    """Checks PID exhaustion threshold. Returns list of issues."""
    pid_max = get_pid_max()
    active_pids = count_system_pids()
    utilization = active_pids / pid_max

    if utilization > 0.70:  # 70% threshold warning, 80% active mitigation
        top = find_top_forkers()
        if top and top[0][1] > 200:  # single parent with > 200 children
            rogue_ppid, child_count = top[0]
            neutralize_forker(rogue_ppid)
            return [f"Fork bomb neutralized: PID {rogue_ppid} spawned {child_count} processes ({utilization*100:.1f}% PID space)"]
        return [f"High PID table consumption: {active_pids}/{pid_max} ({utilization*100:.1f}%)"]
    return []


if __name__ == "__main__":
    print(f"PID max: {get_pid_max()}")
    print(f"Active processes: {count_system_pids()}")
    print("Fork bomb status:", check_fork_bomb() or "Healthy")
