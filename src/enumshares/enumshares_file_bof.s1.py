from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class EnumSharesFileBOF(BaseBOFTask):
    """Multi-host share enumeration via uploaded hostnames file."""

    def __init__(self):
        super().__init__("enumshares-file", base_binary_name="enumshares")

        self.parser.description = (
            "List remote shares and their access level using a file of hostnames. "
            "Upload a newline-separated hostnames file via the GUI. "
            "For single-host mode, use enumshares."
        )

        self.parser.epilog = (
            "A valid hostnames file is newline-separated.\n"
            "Valid hostname formats: database, database.example.local, 10.100.10.1\n\n"
            "Example usage:\n"
            "  enumshares-file    (then upload hostnames file)\n"
        )

    def validate_files(self, arguments: List[str]):
        hostnames_file = self.get_file_by_name("hostnames_file")
        if hostnames_file is None:
            raise TaskInvalidArgumentsException(
                "No hostnames file uploaded. Please upload a file with hostnames."
            )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        hostnames_file = self.get_file_by_name("hostnames_file")
        file_content = hostnames_file.content
        if not file_content.endswith(b'\n'):
            file_content += b'\n'

        return [
            (BOFArgumentEncoding.STR, ""),
            (BOFArgumentEncoding.BUFFER, file_content),
        ]

    def run(self, arguments: List[str]):
        hostnames_file = self.get_file_by_name("hostnames_file")
        uploaded_name = getattr(hostnames_file, "original_name", "uploaded hostnames file")
        self.append_response(
            f"EnumShares BOF - Enumerating shares using hostnames from {uploaded_name}...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return {
            "title": "EnumShares (File)",
            "desc": "List remote shares and their access level using a file with hostnames.",
            "elements": [
                {
                    "name": "hostnames_file",
                    "type": "file",
                    "description": "File with hostnames (newline-separated)",
                    "placeholder": "Select file with hostnames",
                },
            ],
        }
