import os
from typing import List, Tuple

from outflank_stage1.implant.enums import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))

# The BOF's strtok loop stops when there is no next token, so it never checks
# the last line. This marker is that last line, so every real host is checked.
_END_MARKER = "__enumwebclient_end__"


class EnumWebClientBOF(BaseBOFTask):
    """Check hosts given on the command line for a running WebClient service."""

    def __init__(self):
        # x64-only: upstream ships an MSVC x64 .o; mingw build fails on upstream code.
        super().__init__(
            "enumwebclient",
            base_binary_name="enumwebclient",
            supported_architectures=[ImplantArch.INTEL_X64],
        )
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Find hosts with the WebClient service running. Checks for the "
            "\\\\<host>\\pipe\\DAV RPC SERVICE named pipe with WaitNamedPipeA "
            "(3 second timeout per host)."
        )

        self.parser.add_argument(
            "hosts",
            nargs="+",
            help="Hostnames or IPs, separated by spaces or commas",
        )

        self.parser.add_argument(
            "--debug",
            action="store_true",
            help="Also list hosts that were unreachable or have WebClient stopped",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  enumwebclient ws01\n"
            "  enumwebclient ws01 ws02.corp.local 10.0.0.15\n"
            "  enumwebclient ws01,ws02,ws03 --debug\n\n"
            "Notes:\n"
            "  - For a long list of hosts, use enumwebclient-file and upload a file.\n"
        )

    def _hosts(self, arguments: List[str]) -> List[str]:
        parser_arguments = self.parser.parse_args(arguments)
        hosts = []
        for item in parser_arguments.hosts:
            for host in item.split(","):
                host = host.strip()
                if host and host not in hosts:
                    hosts.append(host)
        return hosts

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        if not self._hosts(arguments):
            raise TaskInvalidArgumentsException("Give at least one hostname or IP.")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        hosts = self._hosts(arguments)

        # The BOF runs strtok on the buffer, so it must end with a null byte.
        buffer = ("\n".join(hosts) + "\n" + _END_MARKER + "\n\0").encode("utf-8")

        # BOF expects: bz (hosts buffer, "debug" or empty)
        return [
            (BOFArgumentEncoding.BUFFER, buffer),
            (BOFArgumentEncoding.STR, "debug" if parser_arguments.debug else ""),
        ]

    def run(self, arguments: List[str]):
        self.append_response(
            f"EnumWebClient BOF - Checking {len(self._hosts(arguments))} host(s)...\n"
        )
        super().run(arguments)
