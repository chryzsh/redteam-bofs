from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class TcpscanBOF(BaseBOFTask):
    """Single-host TCP connect scan. Use 'tcpscan-file' for multi-host file upload."""

    def __init__(self):
        super().__init__("tcpscan", base_binary_name="tcpscan")

        self.parser.description = (
            "TCP connect scan of a single host. Prints host:port for every open port. "
            "For multi-host file upload, use tcpscan-file."
        )

        self.parser.add_argument(
            "host",
            help="Hostname or IP to scan (e.g., 'DC01', '10.100.10.1').",
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
            "Example usage:\n"
            "  tcpscan DC01 445,3389\n"
            "  tcpscan 10.0.0.5 1-1024 500\n"
        )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, parser_arguments.host),
            (BOFArgumentEncoding.BUFFER, b""),
            (BOFArgumentEncoding.STR, parser_arguments.ports),
            (BOFArgumentEncoding.INT, parser_arguments.timeout),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)
        self.append_response(
            f"tcpscan BOF - Scanning {parser_arguments.host} on {parser_arguments.ports}...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return None
