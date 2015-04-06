# roputils

A Return-oriented Programming toolkit


## Usage

[examples/ropasaurusrex.py](examples/ropasaurusrex.py) is a write up of [ropasaurusrex](http://repo.shell-storm.org/CTF/PlaidCTF-2013/Pwnable/ropasaurusrex-200/) in PlaidCTF 2013.

roputils.py is the single-file module, so your script can use it by creating a symlink named `roputils.py` in the same directory.


## Overview

Currently roputils.py has the below classes:

* ELF: ELF parser (by readelf)
* ROP: ELF with additional methods for creating ROP chains
* Shellcode: i386/x86-64/ARM shellcode builder
* FormatStr: format string for exploitation
* Proc: non-blocking IO for local process and remote service
* Pattern: Metasploit pattern generator/calculator
* Asm: implementation of asm subcommand

roputils.py also can be used as CLI tool, the subcommands are:

* checksec: a clone of [checksec.sh](http://www.trapkit.de/tools/checksec.html)
* create: call Pattern.create()
* offset: call Pattern.offset()
* gadget: availability check of tiny gadgets
* scan: grep the binary and disassemble from there
* sc: output shellcode as hexstring
* asm: i386/x86-64/ARM/Thumb2 assembler and disassembler
* objdump: disassemble with IDA-like annotations

To list up the methods of each class, hit the below command in the same directory as roputils.py:

```
$ python -c 'import roputils as me; help(me)'
```

For more details, just read [the code](roputils.py).
