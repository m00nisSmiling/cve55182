#!/usr/bin/python3
import os
import time

usrname = input("| Username to install :> ")
websvr = input("| Webserver name :> ")
botkey = input("| Telegram bot api key [ 123432988:xyzabcdefjklmnopqrs ] :> ")
chatid = input("| Telegram chat id :> ")

if usrname == "root":
 home = "/root"
else:
 home = f"/home/{usrname}"

moni_install = f"""#!/usr/bin/python3
#from datetime import datetime
import time
import subprocess
import requests
import os

ACCESS_LOG = "/var/log/{websvr}/access.log"
#IP_FILE = "/root/ip"
#Log_file = "/var/log/moni.log"

#fileo = open(Log_file,"a")

#print("Monitoring Nginx Server.....")

turl = f"https://api.telegram.org/bot{botkey}/sendMessage"
chat_id = '{chatid}'
"""+"""

#c_time = datetime.now()
#year = c_time.year
#month = c_time.month
#day = c_time.day
#hour = c_time.hour
#minute = c_time.minute
#second = c_time.second
hostname = subprocess.getoutput("hostname")
list1 = []
payloads = [".php","../","/etc",".env"]

while True:
    last_line = subprocess.getoutput(f"tail -n 1 {ACCESS_LOG}")
    for i in payloads:
        if i in last_line:
            ip = last_line.split(" ")[0]
            urlr = last_line.split('"')[1]
            time = last_line.split(' ')[3]
            if ip == "18.138.119.71":
                pass
            else:
                if ip in list1:
                    pass
                else:

                    os.system(f"echo '[{time}] malicious ip -> {ip}' >> /var/log/moni.log")
                    os.system(f"iptables -A INPUT -s {ip} -p tcp -j DROP -w")
                    #os.system(f"ufw deny from {ip} to any")
                    list1.append(ip)
                    msg = f"Banned_ip -> {ip}\\n{urlr}\\n---------------------\\n[ {hostname} ]\\n{time}] " #change this 
                    data = f"chat_id={chat_id}&text={msg}"
                    resp = requests.post(turl,params=data).text
     
            #with open(IP_FILE, "a") as f:
            #    f.write(ip + "")

"""
service_install = f"""[Unit]
Description=Monitoring And Banning Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 {home}/moni.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target"""

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
   os.system(f"iptables -D INPUT {i}")
 else:
  os.system(f"iptables -D INPUT {inp1}")
"""

def install():
 moni_path = f"{home}/moni.py"
 service_path = "/etc/systemd/system/moni.service"
 banned_log_path = "/var/log/moni.log"
 unban_path = f"{home}/unban.py"

 os.system(f"touch {moni_path}")
 print(f"[+] created moni file in -> {moni_path}")
 time.sleep(1)
 filew1 = open(moni_path,'w')
 filew1.write(moni_install)
 print(f"[+] installed moni in -> {moni_path}")
 time.sleep(1)
 
 os.system(f"touch {service_path}")
 print(f"[+] created moni service file in -> {service_path}")
 time.sleep(1)
 filew2 = open(service_path,'w')
 filew2.write(service_install)
 print(f"[+] installed moni service configuration in -> {service_path}")
 time.sleep(1)
 
 os.system(f"touch {banned_log_path}")
 print(f"[+] created banned log file in -> {banned_log_path}")
 time.sleep(1)

 os.system(f"touch {unban_path}")
 print(f"[+] created unban file in -> {unban_path}")
 time.sleep(1)
 filew3 = open(unban_path,'w')
 filew3.write(unban_install)
 print(f"[+] installed unban script in -> {unban_path}")
 time.sleep(1)

 #os.system("systemctl daemon-reload")
 print("\n-- Run following command to start moni service --")

 #time.sleep(3)
 #os.system("systemctl start moni")
 print("$ systemctl daemon-reload\n$ systemctl start moni\n$ systemctl enable moni\n$ systemctl restart moni")

 #time.sleep(3)
 #os.system("systemctl enable moni")
 #print("[*] moni service enabled !")
 
install()
os.system("rm -rf ../log2block")                                  
