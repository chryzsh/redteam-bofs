import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.implant.enums import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))

# The BOF's strtok loop stops when there is no next token, so it never checks
# the last line. This marker is that last line, so every real host is checked.
_END_MARKER = b"__enumwebclient_end__"


def _parse_hosts(content: bytes) -> List[str]:
    hosts = []
    for line in content.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line not in hosts:
            hosts.append(line)
    return hosts


class EnumWebClientFileBOF(BaseBOFTask):
    """Check an uploaded list of hosts for a running WebClient service."""

    def __init__(self):
        # x64-only: upstream ships an MSVC x64 .o; mingw build fails on upstream code.
        super().__init__(
            "enumwebclient-file",
            base_binary_name="enumwebclient",
            supported_architectures=[ImplantArch.INTEL_X64],
        )
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Find hosts with the WebClient service running, using an uploaded file of "
            "hostnames or IP addresses. Checks for the \\\\<host>\\pipe\\DAV RPC SERVICE "
            "named pipe with WaitNamedPipeA (3 second timeout per host)."
        )

        self.parser.add_argument(
            "--debug",
            action="store_true",
            help="Also list hosts that were unreachable or have WebClient stopped",
        )

        self.parser.epilog = (
            "File format: one host per line. Blank lines and lines starting with # are skipped.\n"
            "Valid host formats: database, database.example.local, 10.100.10.1\n\n"
            "Example usage:\n"
            "  enumwebclient-file           (then upload hosts file)\n"
            "  enumwebclient-file --debug   (then upload hosts file)\n\n"
            "Notes:\n"
            "  - Hosts are checked one by one from the implant. Unreachable hosts take up to 3s each.\n"
            "  - For a few hosts on the command line, use enumwebclient.\n"
        )

    def validate_files(self, arguments: List[str]):
        hosts_file = self.get_file_by_name("hosts_file")
        if hosts_file is None:
            raise TaskInvalidArgumentsException(
                "No hosts file uploaded. Upload a file with one hostname or IP per line."
            )
        if not _parse_hosts(hosts_file.content):
            raise TaskInvalidArgumentsException("The uploaded hosts file has no hosts.")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        hosts = _parse_hosts(self.get_file_by_name("hosts_file").content)

        # The BOF runs strtok on the buffer, so it must end with a null byte.
        buffer = b"\n".join(h.encode("utf-8") for h in hosts) + b"\n" + _END_MARKER + b"\n\0"

        # BOF expects: bz (hosts buffer, "debug" or empty)
        return [
            (BOFArgumentEncoding.BUFFER, buffer),
            (BOFArgumentEncoding.STR, "debug" if parser_arguments.debug else ""),
        ]

    def run(self, arguments: List[str]):
        hosts_file = self.get_file_by_name("hosts_file")
        uploaded_name = getattr(hosts_file, "original_name", "uploaded hosts file")
        count = len(_parse_hosts(hosts_file.content))
        self.append_response(
            f"EnumWebClient BOF - Checking {count} host(s) from {uploaded_name}...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return {
            "title": "EnumWebClient (File)",
            "desc": "Find hosts with the WebClient service running, from a file of hosts.",
            "elements": [
                {
                    "name": "hosts_file",
                    "type": "file",
                    "description": "File with hostnames or IPs (one per line)",
                    "placeholder": "Select file with hosts",
                },
            ],
        }
