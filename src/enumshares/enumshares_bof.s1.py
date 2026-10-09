from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class EnumSharesBOF(BaseBOFTask):
    """Single-host share enumeration. Use 'enumshares-file' for multi-host file upload."""

    def __init__(self):
        super().__init__("enumshares", base_binary_name="enumshares")

        self.parser.description = (
            "List remote shares and their access level for a single host. "
            "For multi-host file upload, use enumshares-file."
        )

        self.parser.add_argument(
            "host",
            help="Hostname or IP to enumerate shares on (e.g., 'DC01', '10.100.10.1').",
        )

        self.parser.epilog = (
            "Valid hostname formats: database, database.example.local, 10.100.10.1\n\n"
            "Example usage:\n"
            "  enumshares DC01\n"
            "  enumshares 10.100.10.1\n"
        )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, parser_arguments.host),
            (BOFArgumentEncoding.BUFFER, b""),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)
        self.append_response(
            f"EnumShares BOF - Enumerating shares on {parser_arguments.host}...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return None
