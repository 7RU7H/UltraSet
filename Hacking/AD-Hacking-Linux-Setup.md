# Active Directory Hacking Linux Setup


https://notes.vulndev.io/wiki/misc/labs/misc
```bash
# Increase kerberos ticket duration on linux machines
# edit /etc/sssd/sssd.conf

krb5_lifetime = 365d
krb5_renewable_lifetime = 365d
krb5_renew_interval = 1m
```

```bash
# Find Default Password Policy Compliant Passwords in Wordlists
grep -n -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])' rockyou.txt | less
```