# Log2block
- Description : Firewall service to 'block' malicious HTTP traffic & 'upgrade' web server security
- Webserver : Nginx & Apache
- Privilege : root
- Operating system : linux
- Language : [Python](https://www.python.org/)
- Whoami : [m00nissmiling](https://www.facebook.com/moonissmiling1)

### *** Firewall Installation Steps ***
#### 1. Clone my repo :
```
git clone https://github.com/m00nisSmiling/log2block.git
```
#### 2. Change directory to log2block
```
cd log2block
```
#### 3. Change to root user
```
sudo su
```
#### 4. Run installation script
```
python3 install.py
```
``` > Fill your web server name (apache2 or nginx ...etc)```

``` > Fill telegram bot api key (to report malicious activities using telegram bot)```

``` > Fill telegram chatid to send banned ip address and malicious informations (report to this chat id) ```

#### 9. Start & enable firewall service

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

## *** To remove an ip address from banlist ***
```
python3 /root/unban.py
```

-------------------------

## *** To check the total list of banned ip and malicious information ***
```
cat /var/log/moni.log
```

## *** You can edit malicious payload list in /root/moni.py to block malicious http traffic ***
