import os
import time

unban = f"/root/unban.py"
moni = f"/root/moni.py"
service = f"/etc/systemd/system/moni.service"
log = f"/var/log/moni.log"

os.system(f"rm -rf {unban} {moni} {service} {log}")
time.sleep(1)
os.system("rm -rf ./remove-moni.py")
print("[!] Uninstalled moni service... ")
