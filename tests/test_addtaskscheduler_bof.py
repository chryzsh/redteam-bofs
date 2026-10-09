import argparse
import importlib.util
import pathlib
import sys
import types
import unittest
from enum import Enum


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "oc2-python-scripts-bof" / "OperatorsKit" / "addtaskscheduler_bof.s1.py"


def load_module():
    class StubBaseBOFTask:
        def __init__(self, command_name, base_binary_name=None, base_binary_path=None,
                     supported_architectures=None):
            self.command_name = command_name
            self.base_binary_name = base_binary_name
            self.base_binary_path = base_binary_path
            self.supported_architectures = supported_architectures
            self.parser = argparse.ArgumentParser(prog=command_name, add_help=False)
            self.responses = []

        def set_base_path(self, base_path):
            self.base_path = base_path

        def append_response(self, message):
            self.responses.append(message)

        def run(self, arguments):
            return arguments

        def validate_arguments(self, arguments):
            return arguments

    class StubImplantArch(Enum):
        INTEL_X86 = "INTEL_X86"
        INTEL_X64 = "INTEL_X64"

    class StubBOFArgumentEncoding(Enum):
        INT = "INT"
        STR = "STR"
        WSTR = "WSTR"
        BUFFER = "BUFFER"

    class StubTaskInvalidArgumentsException(Exception):
        pass

    outflank_stage1 = types.ModuleType("outflank_stage1")
    implant_pkg = types.ModuleType("outflank_stage1.implant")
    implant_enums_mod = types.ModuleType("outflank_stage1.implant.enums")
    task_pkg = types.ModuleType("outflank_stage1.task")
    base_bof_task_mod = types.ModuleType("outflank_stage1.task.base_bof_task")
    enums_mod = types.ModuleType("outflank_stage1.task.enums")
    exceptions_mod = types.ModuleType("outflank_stage1.task.exceptions")

    implant_enums_mod.ImplantArch = StubImplantArch
    base_bof_task_mod.BaseBOFTask = StubBaseBOFTask
    enums_mod.BOFArgumentEncoding = StubBOFArgumentEncoding
    exceptions_mod.TaskInvalidArgumentsException = StubTaskInvalidArgumentsException

    sys.modules["outflank_stage1"] = outflank_stage1
    sys.modules["outflank_stage1.implant"] = implant_pkg
    sys.modules["outflank_stage1.implant.enums"] = implant_enums_mod
    sys.modules["outflank_stage1.task"] = task_pkg
    sys.modules["outflank_stage1.task.base_bof_task"] = base_bof_task_mod
    sys.modules["outflank_stage1.task.enums"] = enums_mod
    sys.modules["outflank_stage1.task.exceptions"] = exceptions_mod

    spec = importlib.util.spec_from_file_location("addtaskscheduler_bof", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, StubBOFArgumentEncoding, StubTaskInvalidArgumentsException


MODULE, BOFArgumentEncoding, TaskInvalidArgumentsException = load_module()


class AddTaskSchedulerBOFTests(unittest.TestCase):
    def setUp(self):
        self.task = MODULE.AddTaskSchedulerBOF()

    def test_startup_legacy_with_empty_placeholders(self):
        parsed = self.task._parse_arguments(
            [
                "ACOTask",
                "",
                r"C:\Windows\System32\msiexec.exe",
                r"/Z C:\Tools\payloads\implant.dll",
                "startup",
                "",
            ]
        )

        self.assertEqual(parsed.host_name, "")
        self.assertEqual(parsed.program_path, r"C:\Windows\System32\msiexec.exe")
        self.assertEqual(parsed.program_arguments, r"/Z C:\Tools\payloads\implant.dll")
        self.assertEqual(parsed.trigger_type, "startup")
        self.assertEqual(parsed.delay, "")

    def test_startup_legacy_without_empty_placeholders(self):
        parsed = self.task._parse_arguments(
            [
                "ACOTask",
                r"C:\Windows\System32\msiexec.exe",
                r"/Z C:\Tools\payloads\implant.dll",
                "startup",
            ]
        )

        self.assertEqual(parsed.host_name, "")
        self.assertEqual(parsed.program_path, r"C:\Windows\System32\msiexec.exe")
        self.assertEqual(parsed.program_arguments, r"/Z C:\Tools\payloads\implant.dll")

    def test_remote_startup_without_program_arguments(self):
        parsed = self.task._parse_arguments(
            [
                "RemoteTask",
                "DC01.example.local",
                r"C:\Windows\System32\cmd.exe",
                "startup",
                "PT5M",
            ]
        )

        self.assertEqual(parsed.host_name, "DC01.example.local")
        self.assertEqual(parsed.program_path, r"C:\Windows\System32\cmd.exe")
        self.assertEqual(parsed.program_arguments, "")
        self.assertEqual(parsed.delay, "PT5M")

    def test_lock_single_duration_token_maps_to_delay(self):
        parsed = self.task._parse_arguments(
            [
                "LockTask",
                r"C:\Windows\System32\cmd.exe",
                "lock",
                "PT5M",
            ]
        )

        self.assertEqual(parsed.user_id, "")
        self.assertEqual(parsed.delay, "PT5M")

    def test_daily_tail_tokens_can_skip_empty_placeholders(self):
        parsed = self.task._parse_arguments(
            [
                "DailyTask",
                r"C:\Windows\System32\cmd.exe",
                "daily",
                "2023-03-24T12:08:00",
                "1",
                "PT2H",
            ]
        )

        self.assertEqual(parsed.start_time, "2023-03-24T12:08:00")
        self.assertEqual(parsed.expire_time, "")
        self.assertEqual(parsed.days_interval, 1)
        self.assertEqual(parsed.delay, "PT2H")

    def test_recommended_flag_syntax(self):
        parsed = self.task._parse_arguments(
            [
                "--host",
                "DC01.example.local",
                "--program-args",
                r"/Z C:\Tools\payloads\implant.dll",
                "--delay",
                "PT5M",
                "ACOTask",
                r"C:\Windows\System32\msiexec.exe",
                "startup",
            ]
        )

        self.assertEqual(parsed.host_name, "DC01.example.local")
        self.assertEqual(parsed.program_path, r"C:\Windows\System32\msiexec.exe")
        self.assertEqual(parsed.program_arguments, r"/Z C:\Tools\payloads\implant.dll")
        self.assertEqual(parsed.delay, "PT5M")

    def test_encode_arguments_matches_startup_bof_pack(self):
        encoded = self.task._encode_arguments_bof(
            [
                "ACOTask",
                r"C:\Windows\System32\msiexec.exe",
                r"/Z C:\Tools\payloads\implant.dll",
                "startup",
            ]
        )

        self.assertEqual(
            encoded,
            [
                (BOFArgumentEncoding.WSTR, "ACOTask"),
                (BOFArgumentEncoding.WSTR, ""),
                (BOFArgumentEncoding.WSTR, r"C:\Windows\System32\msiexec.exe"),
                (BOFArgumentEncoding.WSTR, r"/Z C:\Tools\payloads\implant.dll"),
                (BOFArgumentEncoding.STR, "startup"),
                (BOFArgumentEncoding.WSTR, ""),
            ],
        )

    def test_logon_legacy_with_literal_empty_quote_placeholder(self):
        # OC2 sometimes preserves the literal two-character "" the user typed as a
        # placeholder for "no remote host". The wrapper must normalize it to ""
        # so the BOF doesn't try to Connect() to a server literally named "".
        parsed = self.task._parse_arguments(
            [
                "BootstrapUser",
                '""',
                r"C:\Windows\system32\mmc.exe",
                r"C:\Users\jsmith\appdata\roaming\bootstrap.msc",
                "logon",
                r"CORP\jsmith",
            ]
        )

        self.assertEqual(parsed.task_name, "BootstrapUser")
        self.assertEqual(parsed.host_name, "")
        self.assertEqual(parsed.program_path, r"C:\Windows\system32\mmc.exe")
        self.assertEqual(parsed.program_arguments, r"C:\Users\jsmith\appdata\roaming\bootstrap.msc")
        self.assertEqual(parsed.trigger_type, "logon")
        self.assertEqual(parsed.user_id, r"CORP\jsmith")

    def test_program_args_outer_quotes_are_stripped(self):
        # OC2's tokenizer preserves the operator-typed quotes around a single
        # token. Without stripping, msiexec ends up being launched with the
        # whole "/z C:\..." as a single quoted argv[1] and ignores the switch.
        parsed = self.task._parse_arguments(
            [
                "TestSvc",
                r"C:\Windows\system32\msiexec.exe",
                "startup",
                "--program-args",
                r'"/z C:\Users\testuser\desktop\payload.dll"',
                "--delay",
                "PT5M",
            ]
        )

        self.assertEqual(parsed.program_arguments, r"/z C:\Users\testuser\desktop\payload.dll")
        self.assertEqual(parsed.delay, "PT5M")

    def test_positional_outer_quotes_are_stripped(self):
        parsed = self.task._parse_arguments(
            [
                "BootstrapUser",
                '""',
                r"C:\Windows\system32\mmc.exe",
                r'"C:\Users\jsmith\appdata\roaming\bootstrap.msc"',
                "logon",
                r"CORP\jsmith",
            ]
        )

        self.assertEqual(parsed.host_name, "")
        self.assertEqual(parsed.program_arguments, r"C:\Users\jsmith\appdata\roaming\bootstrap.msc")

    def test_literal_empty_quotes_in_flag_value_are_normalized(self):
        parsed = self.task._parse_arguments(
            [
                "--host",
                '""',
                "--program-args",
                "''",
                "Task",
                r"C:\Windows\System32\cmd.exe",
                "startup",
            ]
        )

        self.assertEqual(parsed.host_name, "")
        self.assertEqual(parsed.program_arguments, "")

    def test_invalid_trigger_flag_is_rejected(self):
        with self.assertRaises(TaskInvalidArgumentsException):
            self.task._parse_arguments(
                [
                    "--user-id",
                    "DOMAIN\\Admin",
                    "Task",
                    r"C:\Windows\System32\cmd.exe",
                    "startup",
                ]
            )


if __name__ == "__main__":
    unittest.main()
