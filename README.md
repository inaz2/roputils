# roputils

A Return-oriented Programming toolkit

## Usage

[examples/ropasaurusrex.py](examples/ropasaurusrex.py) is a write-up of [ropasaurusrex](http://repo.shell-storm.org/CTF/PlaidCTF-2013/Pwnable/ropasaurusrex-200/) in PlaidCTF 2013.

## Overview

Currently roputils.py has 5 classes: ELF, ROP, Shellcode, FormatStr, Proc, Pattern.

* ELF: information about ELF object retrieved by readelf
* ROP: subclass of ELF, with additional methods for creating ROP stack
* Shellcode: x86 and x64 shellcode builder
* FormatStr: create format string for exploitation
* Proc: gateway interface of subprocess and socket
* Pattern: create Metasploit pattern and calculate its offset

roputils.py also can be used as CLI tool, has 6 subcommands: checksec, create, offset, gadget, scan, asm.

* checksec: a clone of [checksec.sh](http://www.trapkit.de/tools/checksec.html)
* create: call Pattern.create()
* offset: call Pattern.offset()
* gadget: availability check for tiny gadgets
* scan: search the binary chunk and disassemble from there
* asm: x86 and x64 assembler/disassembler

For more details, just read the codes.
