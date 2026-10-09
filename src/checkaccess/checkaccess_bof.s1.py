from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class CheckAccessBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("checkaccess", base_binary_name="checkaccess")

        self.parser.description = (
            "Probe directory read access for a single local or UNC path and its subdirectories. "
            "Uses FindFirstFileW directory listing probes and prints enumshares-style verdicts."
        )

        self.parser.add_argument(
            "path",
            help="Directory path to probe (UNC or local), e.g., \\\\server\\share\\dept or C:\\Users\\Public"
        )

        self.parser.add_argument(
            "--suppress-access-denied",
            "--suppress-denied",
            "-s",
            action="store_true",
            help="Suppress subdirectory lines with '[-] Access denied' verdicts"
        )

        self.parser.add_argument(
            "--recursive",
            "-r",
            action="store_true",
            help="Recursively probe all nested subdirectories (default: depth 1 only)"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  checkaccess \\\\test\\dept\n"
            "  checkaccess \\\\test\\dept -r\n"
            "  checkaccess \\\\test\\dept --suppress-access-denied\n"
            "  checkaccess \\\\test\\dept -r --suppress-access-denied\n"
            "  checkaccess \\\\fileserver\\projects\\retail\n"
            "  checkaccess C:\\Users\\Public\n\n"
            "Notes:\n"
            "  - Probes one directory path per invocation\n"
            "  - Probes depth 1 by default; use -r for full recursive traversal\n"
            "  - Read access only (directory listing probe)\n"
            "  - --suppress-access-denied affects subdirectory output only\n"
            "  - Output mirrors enumshares verdict style\n"
            "  - Primarily intended for UNC directory access checks\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        if not parser_arguments.path or parser_arguments.path.strip() == "":
            raise TaskInvalidArgumentsException("Path cannot be empty")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        suppress_access_denied = 1 if parser_arguments.suppress_access_denied else 0
        recursive = 1 if parser_arguments.recursive else 0

        # BOF expects: Zii
        # (path: wstring, suppressAccessDenied: int, recursive: int)
        # Strip surrounding quotes that OC2 may pass through for paths with spaces
        path = parser_arguments.path.strip('"').strip("'")

        return [
            (BOFArgumentEncoding.WSTR, path),
            (BOFArgumentEncoding.INT, suppress_access_denied),
            (BOFArgumentEncoding.INT, recursive),
        ]
