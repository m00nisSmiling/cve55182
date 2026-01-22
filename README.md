<div align="center">

# Log2block 

</div>

- Service Description:   Firewall service to 'block' malicious HTTP traffic & 'upgrade' web server security
- Supported Web Server:   Nginx & Apache
- Privilege Requirement:   root
- Supported Os:   Linux
- Package Requirement:   [Python3.0](https://www.python.org/)
- Whoami:   [m00nissmiling](https://www.facebook.com/moonissmiling1)

<br>

### Installation Steps

<br>

- pip install requests :
```
pip install requests --break-system-packages
```

<br>

- Clone my repo :
```
git clone https://github.com/m00nisSmiling/log2block.git
```

<br>

- Change directory to log2block :
```
cd log2block
```

<br>

- Change to root user :
```
sudo su
```

<br>

- Run installation script : 

```
python3 install.py
```
```1. Fill your web server name (apache2 or nginx ...etc)```

```2. Fill telegram bot api key (to report malicious activities using telegram bot)```

```3. Fill telegram chatid to send banned ip address and malicious informations (report to this chat id)```

```4. Fill custom note to send notification from bot```

<br>


- Start & enable firewall service :
```
systemctl daemon-reload
```
```
systemctl start moni
```
```
systemctl enable moni
```
------------------------

- To remove an ip address from banlist :
```
python3 /root/log2block/unban.py
```

-------------------------

- To check the total list of banned ip and malicious information :
```
cat /var/log/moni.log
```

- To delete Logtoblock :
```
python3 /root/log2block/delete-moni.py
```
--------------------------

- You can edit malicious payload list in /root/log2block/moni.py to block malicious http traffic.


