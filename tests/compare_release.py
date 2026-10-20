"""Compare the supplied release with unstripped, rebuilt ARM64 ELFs in Unicorn.

Usage: python tests/compare_release.py ORIGINAL_HOOK REBUILT_HOOK ORIGINAL_DAEMON REBUILT_DAEMON
Use module/build/intermediates/cxx/RelWithDebInfo/<id>/obj/arm64-v8a for rebuilt ELFs.
All libc, filesystem and perf operations are simulated; no Android device is needed.
The reference addresses below are specific to the SHA-256-checked 4d8d26d release.
"""

import hashlib
import io
import re
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

BASE = 0x100000
REGS = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29, UC_ARM64_REG_X30]


class Machine:
    def __init__(self, path):
        self.elf = ELFFile(io.BytesIO(Path(path).read_bytes()))
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(BASE, 0x1000000)
        self.uc.mem_map(0x10000000, 0x1000000)
        self.uc.mem_map(0x20000000, 0x4000000)
        self.uc.mem_map(0x30000000, 0x100000)
        self.uc.mem_map(0x40000000, 0x10000)
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, 0x40000000)
        self.next_alloc = 0x20000000
        self.hooks = {}
        self.handlers = {}
        self.symbols = {}
        self.trace = []
        self.errno = self.alloc(4)
        self.next_hook = 0x30000000
        for seg in self.elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                self.write(BASE + seg['p_vaddr'], seg.data())
        for section in self.elf.iter_sections():
            if section['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                for sym in section.iter_symbols():
                    if sym['st_shndx'] != 'SHN_UNDEF':
                        self.symbols[sym.name] = BASE + sym['st_value']
            if section['sh_type'] == 'SHT_RELA':
                symbols = self.elf.get_section(section['sh_link'])
                for rel in section.iter_relocations():
                    kind = rel['r_info_type']
                    addr = BASE + rel['r_offset']
                    if kind == 1027:
                        value = BASE + rel['r_addend']
                    else:
                        sym = symbols.get_symbol(rel['r_info_sym'])
                        if sym['st_shndx'] == 'SHN_UNDEF':
                            value = self.hook(sym.name)
                        else:
                            value = BASE + sym['st_value'] + rel['r_addend']
                    self.write(addr, struct.pack('<Q', value))
        self.uc.hook_add(UC_HOOK_CODE, self.intercept, begin=0x30000000, end=0x30100000)

    def alloc(self, n, content=None):
        addr = self.next_alloc
        self.next_alloc += (n + 31) & ~15
        if content is not None:
            self.write(addr, content)
        return addr

    def write(self, addr, value):
        self.uc.mem_write(addr, bytes(value))

    def read(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def string(self, addr):
        result = bytearray()
        while True:
            chunk = self.read(addr + len(result), 1)
            if chunk == b'\0':
                return bytes(result)
            result.extend(chunk)

    def text(self, addr):
        return self.string(addr).decode()

    def hook(self, name):
        addr = self.next_hook
        self.next_hook += 4
        self.hooks[addr] = name
        self.write(addr, bytes.fromhex('c0035fd6'))
        return addr

    def find(self, name):
        matches = [(n, v) for n, v in self.symbols.items() if name in n]
        exact = [v for n, v in matches if n == name]
        if exact:
            return exact[0]
        assert len(matches) == 1, (name, matches)
        return matches[0][1]

    def call(self, addr, *args):
        for i in range(29):
            self.uc.reg_write(REGS[i], 0)
        for i, arg in enumerate(args):
            self.uc.reg_write(REGS[i], arg & ((1 << 64) - 1))
        self.uc.reg_write(UC_ARM64_REG_SP, 0x10fff000)
        self.uc.reg_write(UC_ARM64_REG_X30, 0x300ff000)
        try:
            self.uc.emu_start(addr, 0x300ff000, count=2000000)
        except Exception:
            print('Failure PC:', hex(self.uc.reg_read(UC_ARM64_REG_PC)), 'trace:', self.trace[-12:])
            raise
        assert self.uc.reg_read(UC_ARM64_REG_PC) == 0x300ff000, 'instruction limit'
        return self.uc.reg_read(UC_ARM64_REG_X0)

    def intercept(self, uc, addr, size, unused):
        name = self.hooks[addr]
        a = [uc.reg_read(REGS[i]) for i in range(8)]
        if name in self.handlers:
            result = self.handlers[name](*a)
        else:
            result = self.libc(name, a)
        uc.reg_write(UC_ARM64_REG_X0, (result or 0) & ((1 << 64) - 1))
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def va_args(self, ptr, n):
        stack, grtop, vrtop, groff, vroff = struct.unpack('<QQQii', self.read(ptr, 32))
        values = []
        for _ in range(n):
            if groff < 0:
                addr = grtop + groff
                groff += 8
            else:
                addr = stack
                stack += 8
            values.append(struct.unpack('<Q', self.read(addr, 8))[0])
        return values

    def formatted(self, fmt, args):
        out = []
        for kind, value in zip(re.findall(r'%([sd])', fmt), args):
            out.append(self.text(value) if kind == 's' else struct.unpack('<i', struct.pack('<I', value & 0xffffffff))[0])
        return (fmt % tuple(out)).encode()

    def libc(self, name, a):
        if name in ('malloc', 'realloc'):
            if name == 'malloc':
                return self.alloc(a[0])
            new = self.alloc(a[1])
            if a[0]:
                self.write(new, self.read(a[0], a[1]))
            return new
        if name in ('free', '__cxa_atexit', '__register_atfork', '__cxa_finalize', '__android_log_print'):
            return 0
        if name in ('memcpy', 'memmove', '__memcpy_chk'):
            if name == '__memcpy_chk':
                assert a[2] <= a[3]
            self.write(a[0], self.read(a[1], a[2]))
            return a[0]
        if name == 'memset':
            self.write(a[0], bytes([a[1] & 255]) * a[2])
            return a[0]
        if name == 'strlen':
            return len(self.string(a[0]))
        if name == 'strcpy':
            self.write(a[0], self.string(a[1]) + b'\0')
            return a[0]
        if name in ('strcmp', 'strncmp', 'memcmp'):
            if name == 'memcmp':
                x, y = self.read(a[0], a[2]), self.read(a[1], a[2])
            else:
                x, y = self.string(a[0]), self.string(a[1])
                if name == 'strncmp':
                    x, y = x[:a[2]], y[:a[2]]
            return (x > y) - (x < y)
        if name == 'strstr':
            index = self.string(a[0]).find(self.string(a[1]))
            return a[0] + index if index >= 0 else 0
        if name == 'memchr':
            index = self.read(a[0], a[2]).find(bytes([a[1] & 255]))
            return a[0] + index if index >= 0 else 0
        if name in ('snprintf', 'vsnprintf'):
            fmt = self.text(a[2])
            args = self.va_args(a[3], len(re.findall(r'%[sd]', fmt))) if name == 'vsnprintf' else a[3:]
            value = self.formatted(fmt, args)
            self.write(a[0], value[:max(0, a[1] - 1)] + b'\0')
            return len(value)
        if name == '__errno':
            return self.errno
        raise AssertionError(('unimplemented import', name, [hex(v) for v in a]))


def compare_hook(original, rebuilt):
    cases = [b'', b'ordinary audit message', b'tcontext=u:r:other:s0',
             b'tcontext=u:r:su:s0 rest', b'tcontext=u:r:ksu:s0 rest',
             b'tcontext=u:r:magisk:s0 rest', b'prefix tcontext=u:r:su:s0 rest',
             b'"tcontext=u:r:su:s0" rest', b'"tcontext=u:r:su:s0 rest"',
             b'tcontext=u:r:su:s0"', b'tcontext=u:r:su:s0',
             b'tcontext=u:r:magisk:s0 tcontext=u:r:ksu:s0 tcontext=u:r:su:s0',
             b'"tcontext=u:r:su:s0 hidden" tcontext=u:r:ksu:s0 rest']
    results = []
    for path, reference in ((original, True), (rebuilt, False)):
        machine = Machine(path)
        entry = BASE + 0xac4 if reference else machine.find('my_vasprintf')
        old = BASE + 0x9040 if reference else machine.find('old_vasprintf')
        state = {}
        def original_vasprintf(out, *_):
            buf = machine.alloc(len(state['input']) + 64, state['input'] + b'\0')
            machine.write(out, struct.pack('<Q', buf))
            return len(state['input'])
        machine.handlers['old_format'] = original_vasprintf
        machine.write(old, struct.pack('<Q', machine.hook('old_format')))
        va = machine.alloc(32)
        strp = machine.alloc(8)
        outputs = []
        for value in cases:
            state['input'] = value
            n = machine.call(entry, strp, 0, va)
            ptr = struct.unpack('<Q', machine.read(strp, 8))[0]
            outputs.append((n, machine.string(ptr)))
        results.append(outputs)
    assert results[0] == results[1], list(zip(cases, results[0], results[1]))
    print('Hook: %d original/rebuilt cases match' % len(cases))


class SystemFixture:
    def __init__(self, m):
        self.m = m
        self.events = []
        self.paths = {'/proc/41', '/proc/42', '/proc/43', '/proc/44'}
        self.contexts = {41: [b'u:r:su:s0'], 42: [b'u:r:ksu:s0'],
                         44: [b'u:r:untrusted_app:s0', b'u:r:untrusted_app:s0', b'u:r:magisk:s0']}
        self.files = {'/proc/42/status': b'Name:\tchild\nTgid:\t42\n',
                      '/proc/43/status': b'Name:\tthread\nTgid:\t42\n'}
        self.streams = {}
        self.dirs = {}
        self.failed_remove = set()
        self.entries = {}
        self.missing_dirs = set()
        self.random = 0
        for name in ['access', 'getxattr', 'usleep', 'mkdir', 'opendir', 'readdir', 'closedir',
                     'clock_gettime', 'chown', 'chmod', 'rand', 'utimensat', 'rmdir',
                     'fopen', 'fclose', 'fgets', 'sscanf', 'fscanf', 'strtol']:
            m.handlers[name] = lambda *a, name=name: self.handle(name, a)

    def fail(self, errno):
        self.m.write(self.m.errno, struct.pack('<i', errno))
        return -1

    def handle(self, name, a):
        m = self.m
        if name == 'access':
            return 0 if m.text(a[0]) in self.paths else self.fail(2)
        if name == 'getxattr':
            pid = int(m.text(a[0]).rsplit('/', 1)[1])
            contexts = self.contexts.get(pid, [])
            context = contexts.pop(0) if len(contexts) > 1 else contexts[0] if contexts else None
            self.events.append(('context', pid, context))
            if context is None:
                return self.fail(2)
            m.write(a[2], context)
            return len(context)
        if name == 'usleep':
            self.events.append(('sleep', a[0]))
            return 0
        if name == 'mkdir':
            path = m.text(a[0])
            self.events.append(('mkdir', path, a[1]))
            if path in self.paths:
                return self.fail(17)
            self.paths.add(path)
            return 0
        if name == 'opendir':
            path = m.text(a[0])
            if path in self.missing_dirs:
                return 0
            handle = m.alloc(8)
            self.dirs[handle] = iter(self.entries.get(path, ['.', '..', 'cgroup.procs', 'cgroup.threads']))
            return handle
        if name == 'readdir':
            item = next(self.dirs[a[0]], None)
            if item is None:
                return 0
            return m.alloc(280, b'\0' * 18 + b'\x04' + item.encode() + b'\0')
        if name == 'closedir':
            return 0
        if name == 'clock_gettime':
            m.write(a[1], struct.pack('<qq', 12345, 999000000))
            return 0
        if name in ('chmod', 'chown'):
            self.events.append((name, m.text(a[0]), *a[1:3 if name == 'chown' else 2]))
            return 0
        if name == 'rand':
            self.random += 1000000
            return self.random
        if name == 'utimensat':
            self.events.append((name, m.text(a[1]), struct.unpack('<qqqq', m.read(a[2], 32))))
            return 0
        if name == 'rmdir':
            path = m.text(a[0])
            self.events.append(('rmdir', path))
            if path in self.failed_remove:
                return self.fail(16)
            if path not in self.paths:
                return self.fail(2)
            self.paths.remove(path)
            return 0
        if name == 'fopen':
            path = m.text(a[0])
            if path not in self.files:
                return 0
            handle = m.alloc(8)
            self.streams[handle] = io.BytesIO(self.files[path])
            return handle
        if name == 'fclose':
            return 0
        if name == 'fgets':
            line = self.streams[a[2]].readline(a[1] - 1)
            if not line:
                return 0
            m.write(a[0], line + b'\0')
            return a[0]
        if name in ('sscanf', 'fscanf'):
            value = m.text(a[0]) if name == 'sscanf' else self.streams[a[0]].read().decode()
            fmt = m.text(a[1])
            pattern = re.escape(fmt).replace('%d', r'\s*([+-]?\d+)')
            match = re.match(pattern, value)
            if not match:
                return 0
            m.write(a[2], struct.pack('<i', int(match.group(1))))
            return 1
        if name == 'strtol':
            text = m.text(a[0])
            match = re.match(r'[+-]?\d+', text)
            m.write(a[1], struct.pack('<Q', a[0] + (len(match.group()) if match else 0)))
            return int(match.group()) if match else 0
        raise AssertionError(name)


def compare_daemon(original, rebuilt):
    results = []
    for path, reference in ((original, True), (rebuilt, False)):
        m = Machine(path)
        fixture = SystemFixture(m)
        root = BASE + 0x42e48 if reference else m.find('cgroup_root')
        tracked = BASE + 0x42e60 if reference else m.find('created_pids')
        value = b'/sys/fs/cgroup'
        m.write(root, bytes([len(value) * 2]) + value + b'\0')
        m.write(tracked + 32, struct.pack('<f', 1.0))
        onexec = BASE + 0x14218 if reference else m.find('on_exec')
        onfork = BASE + 0x144ec if reference else m.find('on_fork')
        onexit = BASE + 0x146e8 if reference else m.find('on_exit')
        for pid in (0, -1, 41, 41, 44, 45):
            m.call(onexec, pid)
        m.call(onfork, 41, 42)
        m.call(onfork, 41, 43)
        m.call(onfork, 0, 42)
        m.call(onexit, 41, 43)
        m.call(onexit, 41, 41)
        m.call(onexit, 41, 41)
        fixture.failed_remove.add('/sys/fs/cgroup/uid_1000/pid_42')
        m.call(onexit, 42, 42)
        fixture.failed_remove.clear()
        m.call(onexit, 42, 42)
        results.append((fixture.events, sorted(fixture.paths)))
    if results[0] != results[1]:
        for i, (a, b) in enumerate(zip(results[0][0], results[1][0])):
            if a != b:
                print('first mismatch', i, a, b)
                break
        raise AssertionError(results)
    print('Daemon: exec/fork/exit, three contexts, retries, thread filter, ownership, timestamps and cleanup match (%d effects)' % len(results[0][0]))


def compare_monitor(original, rebuilt):
    for scenario in ('wrapped', 'missing_ids', 'fallback', 'malformed', 'no_cpus', 'open_fail', 'mmap_fail', 'ioctl_fail', 'eintr'):
        outputs = []
        for path, reference in ((original, True), (rebuilt, False)):
            m = Machine(path)
            fixture = SystemFixture(m)
            root = '/sys/kernel/debug/tracing' if scenario == 'fallback' else '/sys/kernel/tracing'
            if scenario != 'missing_ids':
                for i, event in enumerate(('exec', 'fork', 'exit')):
                    fixture.files[f'{root}/events/sched/sched_process_{event}/id'] = str(101 + i).encode()
                fixture.files[f'{root}/events/sched/sched_process_fork/format'] = b'field:pid_t child_pid; offset:4; size:4; signed:1;\n'
            state = {'polls': 0, 'fds': {}, 'callbacks': [], 'attrs': [], 'closed': [], 'unmapped': []}

            def callback(name):
                def invoke(*a):
                    count = {'ready': 0, 'exec': 1, 'fork': 2, 'exit': 2}[name]
                    state['callbacks'].append((name, *a[:count]))
                return invoke

            callbacks = []
            for name in ('ready', 'exec', 'fork', 'exit'):
                m.handlers[name] = callback(name)
                callbacks.append(m.hook(name))
            cb = m.alloc(32, struct.pack('<4Q', *callbacks))

            def syscall(number, attr, pid, cpu, group, flags, *_):
                assert number == 241
                fields = struct.unpack('<IIQQQQQI', m.read(attr, 52))
                state['attrs'].append((fields, pid & 0xffffffff, cpu, group & 0xffffffff, flags))
                if scenario == 'open_fail':
                    return fixture.fail(1)
                fd = 20 + len(state['fds'])
                state['fds'][fd] = {'kind': fields[2] - 101, 'cpu': cpu}
                return fd

            def mmap(addr, size, prot, flags, fd, offset, *_):
                assert (size, prot, flags, offset) == (4096 * 129, 3, 1, 0)
                if scenario == 'mmap_fail':
                    return -1
                ptr = m.alloc(size)
                state['fds'][fd]['mapping'] = ptr
                return ptr

            def ioctl(fd, request, value, *_):
                assert request in (0x2403, 0x2400) and value == 0
                return -1 if scenario == 'ioctl_fail' else 0

            def poll(fds, count, timeout, *_):
                state['polls'] += 1
                if scenario == 'eintr' and state['polls'] == 1:
                    return fixture.fail(4)
                limit = 2 if scenario == 'eintr' else 1
                if state['polls'] > limit:
                    return fixture.fail(22)
                for i in range(count):
                    fd = struct.unpack('<i', m.read(fds + i * 8, 4))[0]
                    info = state['fds'][fd]
                    raw = struct.pack('<ii', 0, 99)
                    record = struct.pack('<IHHIII', 9, 0, 28, 41, 42, len(raw)) + raw
                    if scenario == 'malformed':
                        record = struct.pack('<IHH', 9, 0, 4)
                    tail = 4096 * 128 - 4
                    mapping = info['mapping']
                    m.write(mapping + 1024, struct.pack('<QQ', tail + len(record), tail))
                    m.write(mapping + 4096 + tail, record[:4])
                    m.write(mapping + 4096, record[4:])
                    m.write(fds + i * 8 + 6, struct.pack('<h', 1))
                return count

            def unmap(ptr, size, *_):
                info = next(v for v in state['fds'].values() if v.get('mapping') == ptr)
                tail = struct.unpack('<Q', m.read(ptr + 1032, 8))[0]
                state['unmapped'].append((info['kind'], info['cpu'], size, tail))
                return 0

            m.handlers.update({'getpagesize': lambda *_: 4096,
                               'sysconf': lambda *a: 0 if scenario == 'no_cpus' else 2,
                               'syscall': syscall, 'mmap': mmap, 'ioctl': ioctl, 'poll': poll,
                               'munmap': unmap, 'close': lambda fd, *_: state['closed'].append(fd)})
            entry = BASE + 0x157e0 if reference else m.find('_Z17monitor_processesRK16ProcessCallbacks')
            m.call(entry, cb)
            outputs.append((state['callbacks'], state['attrs'], sorted(state['closed']), sorted(state['unmapped'])))
        assert outputs[0] == outputs[1], (scenario, outputs)
        print('Monitor:', scenario, 'matches (%d callbacks)' % len(outputs[0][0]))


def compare_startup(original, rebuilt):
    for scenario in ('system_root', 'base_root', 'no_root', 'no_uid_dir', 'empty_uid', 'prefer_system'):
        results = []
        for path, reference in ((original, True), (rebuilt, False)):
            m = Machine(path)
            fixture = SystemFixture(m)
            root = '/sys/fs/cgroup/system' if scenario in ('system_root', 'prefer_system') else '/sys/fs/cgroup'
            if scenario != 'no_root':
                fixture.paths.add(root)
            if scenario == 'prefer_system':
                fixture.paths.add('/sys/fs/cgroup')
                fixture.entries['/sys/fs/cgroup/uid_0'] = ['pid_1']
            fixture.entries[root + '/uid_0'] = ['.', '..', 'pid_1']
            if scenario in ('empty_uid', 'prefer_system'):
                fixture.entries[root + '/uid_0'] = ['.', '..']
            if scenario == 'no_uid_dir':
                fixture.missing_dirs.add(root + '/uid_0')
            monitor = BASE + 0x157e0 if reference else m.find('_Z17monitor_processesRK16ProcessCallbacks')
            m.hooks[monitor] = 'monitor'
            m.uc.hook_add(UC_HOOK_CODE, m.intercept, begin=monitor, end=monitor)
            m.handlers['monitor'] = lambda *_: fixture.events.append(('monitor',))
            m.handlers['time'] = lambda *_: 12345
            m.handlers['srand'] = lambda *a: fixture.events.append(('seed', a[0]))
            status = m.call(BASE + 0x14864 if reference else m.find('main'))
            results.append((status, fixture.events))
        assert results[0] == results[1], (scenario, results)
        print('Startup:', scenario, 'matches', results[0])

    results = []
    for path, reference in ((original, True), (rebuilt, False)):
        m = Machine(path)
        fixture = SystemFixture(m)
        fixture.entries['/proc'] = ['.', '..', '41', '42', '43', '44', '0', '-1', '41x', 'self']
        root = BASE + 0x42e48 if reference else m.find('cgroup_root')
        tracked = BASE + 0x42e60 if reference else m.find('created_pids')
        value = b'/sys/fs/cgroup'
        m.write(root, bytes([len(value) * 2]) + value + b'\0')
        m.write(tracked + 32, struct.pack('<f', 1.0))
        m.call(BASE + 0x14144 if reference else m.find('scan_processes'))
        results.append(fixture.events)
    assert results[0] == results[1], results
    print('Startup: initial /proc scan matches (%d effects)' % len(results[0]))


if __name__ == '__main__':
    assert len(sys.argv) == 5, __doc__
    for path, expected in ((sys.argv[1], 'b0221b5ebbf42d8ed56b26d179bc276d1d3ddd52b31bb1f345f56cb82eb7197c'),
                           (sys.argv[3], '1229cb33a925a4dc49494da30b784cccb676c1217796784f615d4031876bbed5')):
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, 'Wrong reference binary: ' + path
    compare_hook(sys.argv[1], sys.argv[2])
    compare_daemon(sys.argv[3], sys.argv[4])
    compare_monitor(sys.argv[3], sys.argv[4])
    compare_startup(sys.argv[3], sys.argv[4])
