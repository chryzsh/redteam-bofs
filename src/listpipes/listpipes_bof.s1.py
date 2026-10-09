from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class ListPipesBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("listpipes", base_binary_name="listpipes")

        self.parser.description = (
            "Lists local named pipes via BOF using NtQueryDirectoryFile. "
            "Enumerates all named pipes from the \\\\.\\pipe\\ pseudo-directory."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  listpipes\n\n"
            "Notes:\n"
            "  - Lists all named pipes on the local system\n"
            "  - Uses NtQueryDirectoryFile for low-level enumeration\n"
            "  - Output format: one pipe per line with full path (e.g., \\\\.\\pipe\\pipename)\n"
            "  - This BOF takes no arguments\n"
        )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        # BOF expects: no arguments (go function ignores args)
        return []
