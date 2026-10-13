from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class TcpscanFileBOF(BaseBOFTask):
    """Multi-host TCP connect scan via uploaded hosts file."""

    def __init__(self):
        super().__init__("tcpscan-file", base_binary_name="tcpscan")

        self.parser.description = (
            "TCP connect scan of every host in an uploaded file. Prints host:port for every open port. "
            "For single-host mode, use tcpscan."
        )

        self.parser.add_argument(
            "ports",
            help="Comma-separated ports, ranges allowed (e.g., '445,3389,8000-8100').",
        )
        self.parser.add_argument(
            "timeout",
            nargs="?",
            type=int,
            default=0,
            help="Connect timeout in milliseconds (default 1000).",
        )

        self.parser.epilog = (
            "Each line of the hosts file can be a hostname, an IP, or nslookup-file output (hostname<TAB>ip).\n"
            "When a line has an IP, it is used and the hostname is not resolved again.\n\n"
            "Example usage:\n"
            "  tcpscan-file 445          (then upload hosts file)\n"
            "  tcpscan-file 80,443 500\n"
        )

    def validate_files(self, arguments: List[str]):
        hosts_file = self.get_file_by_name("hosts_file")
        if hosts_file is None:
            raise TaskInvalidArgumentsException(
                "No hosts file uploaded. Please upload a file with hosts."
            )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        hosts_file = self.get_file_by_name("hosts_file")
        file_content = hosts_file.content
        if not file_content.endswith(b'\n'):
            file_content += b'\n'

        return [
            (BOFArgumentEncoding.STR, ""),
            (BOFArgumentEncoding.BUFFER, file_content),
            (BOFArgumentEncoding.STR, parser_arguments.ports),
            (BOFArgumentEncoding.INT, parser_arguments.timeout),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)
        hosts_file = self.get_file_by_name("hosts_file")
        uploaded_name = getattr(hosts_file, "original_name", "uploaded hosts file")
        self.append_response(
            f"tcpscan BOF - Scanning {parser_arguments.ports} on hosts from {uploaded_name}...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return {
            "title": "Tcpscan (File)",
            "desc": "TCP connect scan of every host in a file.",
            "elements": [
                {
                    "name": "hosts_file",
                    "type": "file",
                    "description": "File with hosts (newline-separated, nslookup-file output works)",
                    "placeholder": "Select file with hosts",
                },
            ],
        }
