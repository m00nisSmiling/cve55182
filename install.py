#!/usr/bin/python3
import time
import os
import requests
from pathlib import Path


# ---------------- USER INPUT ----------------
websvr = input("| Webserver name [nginx/apache2]: ").strip()
botkey = input("| Telegram bot api key: ").strip()
chatid = input("| Telegram chat id: ").strip()
note = input("| Note: ").strip()

if websvr not in ("nginx", "apache2"):
    raise SystemExit("Invalid webserver")

os.system("mkdir /root/log2block 2> /dev/null")
home = "/root/log2block"

# ---------------- SECURE moni.py ----------------
moni_install = f"""#!/usr/bin/python3
import time
import subprocess
import requests
import ipaddress
from pathlib import Path

ACCESS_LOG = "/var/log/{websvr}/access.log"
BANNED_LOG = "/var/log/moni.log"

BOT_TOKEN = "{botkey}"
CHAT_ID = "{chatid}"

PAYLOADS = [".php", ".git", "../", ".env","alert("]
WHITELIST_IPS = []

banned_ips = set()

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ban_ip(ip):
    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "-j", "DROP"],
        check=True
    )

def notify(ip, url, timestamp, hostname):
    msg = (
        f"BANNED -> {{ip}}\\n"
        f"{{url}}\\n"
        f" "
        f"[ {{hostname}} ]\\n"
        f"[{{timestamp}}]"
    )
    requests.post(
        f"https://api.telegram.org/bot{{BOT_TOKEN}}/sendMessage",
        json={{"chat_id": CHAT_ID, "text": msg}},
        timeout=5
    )

def monitor():
    hostname = subprocess.check_output(["hostname"], text=True).strip()
    log_file = Path(ACCESS_LOG)

    if not log_file.exists():
        raise RuntimeError("Access log not found")

    with log_file.open() as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            if not any(p in line for p in PAYLOADS):
                continue

            parts = line.split()
            if not parts:
                continue

            ip = parts[0]
            if not valid_ip(ip) or ip in banned_ips:
                continue
            if ip in WHITELIST_IPS:
                continue
                
            try:
                url = line.split('"')[1]
                timestamp = line.split("[", 1)[1].split("]")[0]
            except Exception:
                continue

            ban_ip(ip)
            with open(BANNED_LOG, "a") as lf:
                lf.write(f"[{{timestamp}}] banned {{ip}}\\n")

            notify(ip, url, timestamp, hostname)
            banned_ips.add(ip)

if __name__ == "__main__":
    monitor()
"""

# ---------------- SECURE systemd service ----------------
service_install = f"""[Unit]
Description=Monitoring And Banning Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 {home}/moni.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
"""

# ---------------- SECURE unban.py ----------------
unban_install = """#!/usr/bin/python3
import sys
import os

while True:
 #inp1 = input("Ip -> ")
 #os.system(f"ufw delete deny from {inp1}")
 os.system(f"iptables -L INPUT --line-numbers -n")
 inp1 = input("| Line No. To unban -> ")
 if inp1 == 'exit':
  sys.exit()
 elif inp1 == 'total':
  inp2 = input("| Line-10 To Line-? to unban -> ")
  for i in range(10,int(inp2)):
   os.system(f"iptables -D INPUT 11")
 else:
  os.system(f"iptables -D INPUT {inp1}")

"""

# ---------------- INSTALLER ----------------
def install():
    moni_path = Path(home) / "moni.py"
    unban_path = Path(home) / "unban.py"
    service_path = Path("/etc/systemd/system/moni.service")
    banned_log_path = Path("/var/log/moni.log")

    moni_path.write_text(moni_install)
    moni_path.chmod(0o700)
    print(f"[+] Installed moni.py -> {moni_path}")

    unban_path.write_text(unban_install)
    unban_path.chmod(0o700)
    print(f"[+] Installed unban.py -> {unban_path}")

    service_path.write_text(service_install)
    print(f"[+] Installed moni.service -> {service_path}")

    banned_log_path.touch(exist_ok=True)
    print(f"[+] Created log -> {banned_log_path}")
    print("[+] Installed uninstall script -> /root/log2block/delete-moni.py")
    print("\n-- Run these commands --")
    print("systemctl daemon-reload")
    print("systemctl enable moni")
    print("systemctl start moni")

install()

requests.post(f"https://api.telegram.org/bot{botkey}/sendMessage",json={"chat_id": chatid, "text": f"[ Log2block setup done. ({note}) ]"},timeout=5)
os.system("rm -rf ./install.py ./README.md")
os.system("mv ./uninstall.py /root/log2block/delete-moni.py")
