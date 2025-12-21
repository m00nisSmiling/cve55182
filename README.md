# Log2block

### Firewall Installation Steps
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
#### 5.  Fill your web server
#### 6.  Fill username of home directory to install the script files
#### 7.  Fill telegram bot api key
#### 8. Fill telegram chatid to send banned ip address and malicious informations

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
### To remove an ip address from banlist
#### Use unban.py in your home directory of user
