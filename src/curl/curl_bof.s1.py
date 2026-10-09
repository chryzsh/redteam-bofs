from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class CurlBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("curl", base_binary_name="curl")

        self.parser.description = "Retrieve TLS certificate, response headers, and page title from a given URL (curl)."

        self.parser.add_argument(
            "command",
            choices=["finger", "print"],
            help="Command to execute (finger or print)",
        )
        
        self.parser.add_argument(
            "url",
            help="URL to request",
        )
        
        self.parser.add_argument(
            "--ua",
            dest="user_agent",
            default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            help="User-Agent string to use for the request",
        )

        self.parser.epilog = (
            "curl is a BOF that functions like a basic curl utility.\n\n"
            "Example usage:\n"
            "  - Retrieve headers, TLS certificate, and page title:\n"
            "    curl finger https://example.com\n"
            "  - Fetch and print the raw page content:\n"
            "    curl print https://example.com\n"
            "  - Use a custom User-Agent:\n"
            "    curl finger https://example.com --ua \"Custom User Agent\""
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        
        # Encode the arguments for the BOF
        # Using WSTR (wide string) since the BOF expects wchar_t* arguments
        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.command),
            (BOFArgumentEncoding.WSTR, parser_arguments.url),
            (BOFArgumentEncoding.WSTR, parser_arguments.user_agent)
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)
        
        # Add a simple message about what we're doing
        self.append_response(
            f"curl - Executing {parser_arguments.command} operation on {parser_arguments.url}...\n"
        )
        
        # Execute the BOF
        super().run(arguments)
