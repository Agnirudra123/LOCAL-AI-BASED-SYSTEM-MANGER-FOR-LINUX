"""Real fault injection against the demo service only."""
import errno
import os
import shutil
import subprocess
import sys
import time

import psutil

from config import SERVICES
from health import check_http, port_listeners

CFG = SERVICES["demo-app"]
UNIT = CFG["unit"]
SQUATTER = ("import socket,time;s=socket.socket();"
            "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
            f"s.bind(('127.0.0.1',{CFG['port']}));s.listen();time.sleep(3600)")


def sc(*args):
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True)


def kill():
    sc("kill", "-s", "SIGKILL", UNIT)


def bad_config():
    with open(CFG["config"], "w") as f:
        f.write('{"db_host": "127.0.0.1", "pool_size": ')
    sc("restart", UNIT)


def permission():
    os.chmod(CFG["config"], 0o000)
    sc("restart", UNIT)


def port_conflict():
    sc("stop", UNIT)
    subprocess.Popen([sys.executable, "-c", SQUATTER], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(1)
    sc("start", UNIT)


def disk_full():
    d = CFG["data_dir"]
    if not os.path.ismount(d) or shutil.disk_usage(d).total > 64 * 1024 * 1024:
        raise RuntimeError("refusing: data dir is not the small RAM disk")
    os.makedirs(CFG["cache_dir"], exist_ok=True)
    fd = os.open(os.path.join(CFG["cache_dir"], "filler.bin"),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        for size in (1 << 16, 4096):
            buf = b"\0" * size
            while True:
                try:
                    os.write(fd, buf)
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        break
                    raise
    finally:
        os.close(fd)


FAULTS = {"kill": kill, "bad_config": bad_config, "permission": permission,
          "port_conflict": port_conflict, "disk_full": disk_full}


def inject(name):
    FAULTS[name]()


def reset():
    sc("stop", UNIT)
    for pid in port_listeners(CFG["port"]):
        try:
            p = psutil.Process(pid)
            if p.uids().real == os.getuid():
                p.kill()
        except psutil.Error:
            pass
    if os.path.exists(CFG["config"]):
        os.chmod(CFG["config"], 0o600)
    shutil.copyfile(CFG["good_config"], CFG["config"])
    os.makedirs(CFG["cache_dir"], exist_ok=True)
    for e in os.scandir(CFG["cache_dir"]):
        if e.is_file(follow_symlinks=False):
            os.unlink(e.path)
    sc("reset-failed", UNIT)
    sc("start", UNIT)
    for _ in range(15):
        if check_http(CFG["url"], slow_ms=CFG["slow_ms"])["healthy"]:
            return True
        time.sleep(1)
    return False
