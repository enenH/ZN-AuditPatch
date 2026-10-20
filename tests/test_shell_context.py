"""Exercise rebuilt ARM64 code with simulated libc, filesystem and process events."""

import os
from pathlib import Path
import struct
import unittest

from unicorn import UC_HOOK_CODE

from compare_release import Machine, SystemFixture


ROOT = Path(__file__).resolve().parents[1]


def native_directory():
    configured = os.environ.get("AUDITPATCH_NATIVE_DIR")
    if configured:
        return Path(configured)
    directories = list((ROOT / "module/build/intermediates/cxx/RelWithDebInfo").glob("*/obj/arm64-v8a"))
    directories = [p for p in directories if all((p / lib).is_file() for lib in ("libauditpatch.so", "libdaemon.so"))]
    if not directories:
        raise RuntimeError("Build :module:zipRelease first, or set AUDITPATCH_NATIVE_DIR to the unstripped ARM64 output directory.")
    return max(directories, key=lambda p: (p / "libauditpatch.so").stat().st_mtime_ns)


class ShellContextTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = native_directory()

    def rewrite(self, value):
        machine = Machine(self.native / "libauditpatch.so")

        def original_vasprintf(out, *_):
            buf = machine.alloc(len(value) + 64, value + b"\0")
            machine.write(out, struct.pack("<Q", buf))
            return len(value)

        machine.handlers["old_format"] = original_vasprintf
        machine.write(machine.find("old_vasprintf"), struct.pack("<Q", machine.hook("old_format")))
        va = machine.alloc(32)
        strp = machine.alloc(8)
        size = machine.call(machine.find("my_vasprintf"), strp, 0, va)
        ptr = struct.unpack("<Q", machine.read(strp, 8))[0]
        result = machine.string(ptr)
        self.assertEqual(size, len(result))
        return result

    def daemon(self):
        machine = Machine(self.native / "libdaemon.so")
        fixture = SystemFixture(machine)
        fixture.contexts[41] = [b"u:r:shell:s0"]
        fixture.contexts[42] = [b"u:r:shell:s0"]
        root = b"/sys/fs/cgroup"
        machine.write(machine.find("cgroup_root"), bytes([len(root) * 2]) + root + b"\0")
        machine.write(machine.find("created_pids") + 32, struct.pack("<f", 1.0))
        return machine, fixture

    def test_shell_and_existing_domains_preserve_log_suffix(self):
        for domain in (b"shell", b"su", b"ksu", b"magisk"):
            with self.subTest(domain=domain):
                line = b"avc: denied tcontext=u:r:" + domain + b":s0 tclass=dir permissive=0"
                expected = b"avc: denied tcontext=u:r:system_server:s0 tclass=dir permissive=0"
                self.assertEqual(self.rewrite(line), expected)

    def test_quoted_context_source_context_and_other_domains_are_unchanged(self):
        for line in (b'comm="tcontext=u:r:shell:s0" tclass=dir',
                     b"scontext=u:r:shell:s0 tcontext=u:r:untrusted_app:s0",
                     b"tcontext=u:r:adbd:s0", b"tcontext=u:r:shell_exec:s0"):
            with self.subTest(line=line):
                self.assertEqual(self.rewrite(line), line)

    def test_shell_exec_creates_once_and_process_exit_removes(self):
        machine, fixture = self.daemon()
        path = "/sys/fs/cgroup/uid_1000/pid_41"
        machine.call(machine.find("on_exec"), 41)
        machine.call(machine.find("on_exec"), 41)
        self.assertIn(path, fixture.paths)
        self.assertEqual(sum(e[0] == "mkdir" for e in fixture.events), 1)
        machine.call(machine.find("on_exit"), 41, 43)
        self.assertIn(path, fixture.paths)
        machine.call(machine.find("on_exit"), 41, 41)
        self.assertNotIn(path, fixture.paths)

    def test_shell_fork_creates_child_group_but_ignores_threads(self):
        machine, fixture = self.daemon()
        machine.call(machine.find("on_fork"), 41, 42)
        machine.call(machine.find("on_fork"), 41, 43)
        self.assertIn("/sys/fs/cgroup/uid_1000/pid_42", fixture.paths)
        self.assertNotIn("/sys/fs/cgroup/uid_1000/pid_43", fixture.paths)

    def test_existing_shell_is_found_by_initial_scan(self):
        machine, fixture = self.daemon()
        fixture.entries["/proc"] = [".", "..", "41", "self", "41x"]
        machine.call(machine.find("scan_processes"))
        self.assertIn("/sys/fs/cgroup/uid_1000/pid_41", fixture.paths)
        self.assertEqual(sum(e[0] == "mkdir" for e in fixture.events), 1)

    def test_other_domains_do_not_create_groups(self):
        for context in (b"u:r:untrusted_app:s0", b"u:r:adbd:s0", b"u:r:system_server:s0"):
            with self.subTest(context=context):
                machine, fixture = self.daemon()
                fixture.contexts[41] = [context]
                machine.call(machine.find("on_exec"), 41)
                self.assertFalse(any(e[0] == "mkdir" for e in fixture.events))

    def test_startup_accepts_shell_groups_when_root_groups_are_missing_or_empty(self):
        for root_missing in (True, False):
            with self.subTest(root_missing=root_missing):
                machine = Machine(self.native / "libdaemon.so")
                fixture = SystemFixture(machine)
                fixture.paths.add("/sys/fs/cgroup")
                fixture.entries["/sys/fs/cgroup/uid_0"] = [".", ".."]
                if root_missing:
                    fixture.missing_dirs.add("/sys/fs/cgroup/uid_0")
                fixture.entries["/sys/fs/cgroup/uid_2000"] = [".", "..", "pid_41"]
                monitor = machine.find("_Z17monitor_processesRK16ProcessCallbacks")
                machine.hooks[monitor] = "monitor"
                machine.uc.hook_add(UC_HOOK_CODE, machine.intercept, begin=monitor, end=monitor)
                machine.handlers["monitor"] = lambda *_: fixture.events.append(("monitor",))
                machine.handlers["time"] = lambda *_: 12345
                machine.handlers["srand"] = lambda *_: None
                self.assertEqual(machine.call(machine.find("main")), 0)
                self.assertIn(("monitor",), fixture.events)


if __name__ == "__main__":
    unittest.main()
