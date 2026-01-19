import os

dir = f"/root/log2block"
service = f"/etc/systemd/system/moni.service"
log = f"/var/log/moni.log"

os.system(f"rm -rf {dir} {service} {log}")
print("[!] Uninstalled moni service... ")
