"""Test branch only: install and use warpgate.exe on a fresh Windows machine. Each check prints PASS or FAIL."""
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import paramiko
import requests
import urllib3

urllib3.disable_warnings()

EXE = str(Path(sys.argv[1]).resolve())
EVIDENCE = Path(sys.argv[2]).resolve()
ROOT = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
PASSWORD = secrets.token_urlsafe(24)
TARGET_PASSWORD = "Aa1-" + secrets.token_urlsafe(18)
ENV = {**os.environ, "WARPGATE_ADMIN_PASSWORD": PASSWORD, "RUST_BACKTRACE": "1"}
results = []


def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:600]})
    print(("PASS " if ok else "FAIL ") + name + (f": {str(detail)[:600]}" if detail and not ok else ""), flush=True)
    return ok


def wait_port(port, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.5)
    return False


def wg(config, *args, skip=True, timeout=180):
    flags = ["--skip-securing-files"] if skip else []
    return subprocess.run([EXE, *flags, "--config", str(config), *args], env=ENV, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


class Server:
    def __init__(self, config, http_port, log):
        self.http = http_port
        self.log = open(log, "ab")
        self.p = subprocess.Popen([EXE, "--skip-securing-files", "--config", str(config), "run"], env=ENV,
                                  stdout=self.log, stderr=subprocess.STDOUT,
                                  creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)

    def stop(self):
        self.p.send_signal(signal.CTRL_BREAK_EVENT)
        try:
            return self.p.wait(30)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None
        finally:
            self.log.close()


def session(http, password=PASSWORD):
    s = requests.Session()
    s.verify = False
    r = s.post(f"https://127.0.0.1:{http}/@warpgate/api/auth/login",
               json={"username": "admin", "password": password}, timeout=20)
    return s, r.status_code


def install_case(label, data, http, ssh):
    cfg = data.parent / f"{label}.yaml"
    args = ["unattended-setup", "--data-path", str(data), "--http-port", str(http), "--ssh-port", str(ssh),
            "--host-key-verification", "auto-accept"]
    r = wg(cfg, *args, skip=False)
    text = r.stdout + r.stderr
    check(f"{label}: setup without --skip-securing-files refuses", r.returncode != 0 and "skip-securing-files" in text,
          f"rc={r.returncode} {text[-300:]}")
    cfg.unlink(missing_ok=True)
    r = wg(cfg, *args)
    if not check(f"{label}: setup with --skip-securing-files", r.returncode == 0, r.stdout[-300:] + r.stderr[-300:]):
        return None
    (EVIDENCE / f"{label}-config.txt").write_text(
        "\n".join(x for x in cfg.read_text(encoding="utf-8").splitlines() if "database_url" in x), encoding="utf-8")
    check(f"{label}: no verbatim prefix in the config", "\\\\?\\" not in cfg.read_text(encoding="utf-8"))
    r = wg(cfg, "run", skip=False, timeout=60)
    check(f"{label}: run without --skip-securing-files refuses", r.returncode != 0, f"rc={r.returncode}")

    log = EVIDENCE / f"{label}-server.log"
    srv = Server(cfg, http, log)
    if not check(f"{label}: run binds its listeners", wait_port(http) and wait_port(ssh)):
        srv.stop()
        return None
    s, code = session(http)
    check(f"{label}: login with the right password", code == 201, code)
    check(f"{label}: admin API reads users", s.get(f"https://127.0.0.1:{http}/@warpgate/admin/api/users",
                                                   timeout=20).status_code == 200)
    check(f"{label}: wrong password refused", session(http, "wrong-" + PASSWORD)[1] == 401)
    check(f"{label}: Ctrl+Break ends the process cleanly", srv.stop() == 0)
    db = list(data.rglob("db.sqlite3"))
    check(f"{label}: the database is in the data path", len(db) == 1, [str(x) for x in db])

    srv = Server(cfg, http, log)
    check(f"{label}: restart on the same database", wait_port(http))
    check(f"{label}: login after the restart", session(http)[1] == 201)
    return srv


def sshd_up():
    script = ("if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) "
              "{ Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }; Start-Service sshd")
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=600)
    if r.returncode:
        return r.stderr[-300:]
    r = subprocess.run(["net", "user", "wge2e", TARGET_PASSWORD, "/add"], capture_output=True, text=True)
    return None if r.returncode == 0 else r.stderr[-300:]


def ssh_client(port, user, password):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", port=port, username=user, password=password, look_for_keys=False, allow_agent=False,
              timeout=30, auth_timeout=30, banner_timeout=30)
    return c


def run_output(c, command, timeout=60):
    _, out, err = c.exec_command(command, timeout=timeout)
    return out.read().decode(errors="replace") + err.read().decode(errors="replace")


def ssh_through(http, ssh):
    problem = sshd_up()
    if not check("the machine's own sshd is up", problem is None, problem):
        return
    direct = ssh_client(22, "wge2e", TARGET_PASSWORD)
    check("the target works directly", "wge2e" in run_output(direct, "whoami"))
    direct.close()

    api = f"https://127.0.0.1:{http}/@warpgate/admin/api"
    s, _ = session(http)
    r = s.post(f"{api}/targets", timeout=20, json={"name": "win", "options": {
        "kind": "Ssh", "host": "127.0.0.1", "port": 22, "username": "wge2e", "allow_insecure_algos": False,
        "auth": {"kind": "Password", "password": TARGET_PASSWORD}}})
    if not check("create the SSH target", r.status_code == 201, f"{r.status_code} {r.text[:300]}"):
        return
    target = r.json()["id"]
    role = next(x["id"] for x in s.get(f"{api}/roles", timeout=20).json() if x["name"] == "warpgate:admin")
    r = s.post(f"{api}/targets/{target}/roles/{role}", timeout=20)
    if not check("give the admin role the target", r.status_code in (200, 201), r.status_code):
        return

    c = ssh_client(ssh, "admin:win", PASSWORD)
    check("an SSH session through Warpgate runs a command", "wge2e" in run_output(c, "whoami"))
    payload = run_output(c, 'powershell -NoProfile -Command "\'x\' * 2000000"', timeout=120)
    check("2 MB comes back through the session", payload.count("x") == 2000000, payload.count("x"))
    c.close()

    # paramiko stops reading once the channel window is full; the server's write then stalls on flow control. The
    # parked socket write itself is covered by the unit test close_releases_parked_write.
    c = ssh_client(ssh, "admin:win", PASSWORD)
    transport = c.get_transport()
    c.exec_command('powershell -NoProfile -Command "while ($true) { \'x\' * 60000 }"')
    time.sleep(8)
    items = s.get(f"{api}/sessions", params={"active_only": "true"}, timeout=20).json()
    items = items["items"] if isinstance(items, dict) else items
    live = [x for x in items if not x.get("ended")]
    if not check("the stalled session is listed as live", len(live) >= 1, items):
        return
    for x in live:
        s.post(f"{api}/sessions/{x['id']}/close", timeout=20)
    end = time.time() + 30
    while transport.is_active() and time.time() < end:
        time.sleep(0.5)
    check("closing a stalled session ends the client's connection", not transport.is_active())
    ended = s.get(f"{api}/sessions/{live[0]['id']}", timeout=20).json().get("ended")
    check("the session is recorded as ended", bool(ended), ended)
    c.close()


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    icacls = subprocess.run(["icacls", "C:\\ProgramData"], capture_output=True, text=True)
    (EVIDENCE / "icacls-programdata.txt").write_text(icacls.stdout, encoding="utf-8")
    cases = [("plain", ROOT / "wg1" / "data", 18881, 12221),
             ("space", ROOT / "wg 2 with space" / "my data", 18882, 12222),
             ("nonascii", ROOT / "wg3-caf\u00e9-\u65e5\u672c" / "data", 18883, 12223)]
    for label, data, http, ssh in cases:
        data.parent.mkdir(parents=True, exist_ok=True)
        srv = install_case(label, data, http, ssh)
        if srv and label == "plain":
            try:
                ssh_through(http, ssh)
            except Exception as e:
                check("SSH through Warpgate finished", False, repr(e))
        if srv:
            check(f"{label}: Ctrl+Break after the restart", srv.stop() == 0)
    (EVIDENCE / "e2e-results.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    failed = [r["check"] for r in results if not r["ok"]]
    print(f"{len(results) - len(failed)} of {len(results)} passed")
    sys.exit(1 if failed else 0)


main()
