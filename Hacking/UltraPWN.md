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