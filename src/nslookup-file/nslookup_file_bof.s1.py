from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class NslookupFileBOF(BaseBOFTask):
    """Parallel DNS resolution of an uploaded hostnames file."""

    def __init__(self):
        super().__init__("nslookup-file", base_binary_name="nslookup-file")

        self.parser.description = (
            "Resolve every hostname in an uploaded file to IPv4 addresses. "
            "Queries run in parallel. Prints hostname<TAB>ip[,ip...] for each host that resolves."
        )

        self.parser.add_argument(
            "server",
            nargs="?",
            default="",
            help="DNS server IP to query. Defaults to the system resolver.",
        )

        self.parser.epilog = (
            "A valid hostnames file is newline-separated. Only the first word of each line is used.\n"
            "LLMNR and NetBIOS fallback are disabled. Requires Windows 8 / Server 2012 or later.\n\n"
            "Example usage:\n"
            "  nslookup-file              (then upload hostnames file)\n"
            "  nslookup-file 10.0.0.10    (query a specific DNS server)\n"
        )

    def validate_files(self, arguments: List[str]):
        hostnames_file = self.get_file_by_name("hostnames_file")
        if hostnames_file is None:
            raise TaskInvalidArgumentsException(
                "No hostnames file uploaded. Please upload a file with hostnames."
            )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        hostnames_file = self.get_file_by_name("hostnames_file")
        file_content = hostnames_file.content
        if not file_content.endswith(b'\n'):
            file_content += b'\n'

        return [
            (BOFArgumentEncoding.BUFFER, file_content),
            (BOFArgumentEncoding.STR, parser_arguments.server),
        ]

    def run(self, arguments: List[str]):
        hostnames_file = self.get_file_by_name("hostnames_file")
        uploaded_name = getattr(hostnames_file, "original_name", "uploaded hostnames file")
        self.append_response(
            f"nslookup-file BOF - Resolving hostnames from {uploaded_name}...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return {
            "title": "nslookup (File)",
            "desc": "Resolve a file of hostnames to IPv4 addresses with parallel DNS queries.",
            "elements": [
                {
                    "name": "hostnames_file",
                    "type": "file",
                    "description": "File with hostnames (newline-separated)",
                    "placeholder": "Select file with hostnames",
                },
            ],
        }
