from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class EnumCredmanagerBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("enum-credmanager", base_binary_name="enum-credmanager")

        self.parser.description = (
            "Enumerate credentials stored in Windows Credential Manager for the current user. "
            "Lists all credentials with metadata including target name, username, type, and persistence. "
            "No decryption performed (enumeration only)."
        )

        self.parser.add_argument(
            "--filter",
            "-f",
            default="",
            help="Optional filter string for credential target names (e.g., 'github.com'). Leave empty for all credentials."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  enum-credmanager                           # List all credentials\n"
            "  enum-credmanager -f github.com             # Filter by target name\n"
            "  enum-credmanager --filter domain           # Filter for domain credentials\n\n"
            "Notes:\n"
            "  - Runs in current user context (no admin required)\n"
            "  - Shows credential metadata only (no password decryption)\n"
            "  - Uses standard CredEnumerateW Windows API\n"
            "  - Read-only operation, low OPSEC footprint\n"
            "  - Lists the current user's vault only; to find which other profiles hold\n"
            "    Credential Manager blobs, run enum-stored-accounts, then steal a token\n"
            "    for that user and re-run this or decrypt-credmanager\n\n"
            "Credential Types:\n"
            "  - GENERIC: Generic credentials (cmdkey /generic)\n"
            "  - DOMAIN_PASSWORD: Domain passwords (RDP, network shares)\n"
            "  - DOMAIN_CERTIFICATE: Certificate-based domain credentials\n"
            "  - DOMAIN_VISIBLE_PASSWORD: Domain passwords with visible UI\n"
            "  - GENERIC_CERTIFICATE: Generic certificate credentials\n\n"
            "Persistence Types:\n"
            "  - SESSION: Deleted when user logs off\n"
            "  - LOCAL_MACHINE: Persists across reboots\n"
            "  - ENTERPRISE: Roaming credentials (domain-joined)\n\n"
            "OPSEC Considerations:\n"
            "  - Uses documented Windows API (CredEnumerateW)\n"
            "  - No privileged operations required\n"
            "  - Read-only, no modifications to system\n"
            "  - Low detection risk\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        # No specific validation needed - filter is optional string

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # BOF expects: z (optional string filter)
        # If no filter provided, send empty string
        filter_str = parser_arguments.filter if parser_arguments.filter else ""

        if filter_str:
            return [
                (BOFArgumentEncoding.STR, filter_str)
            ]
        else:
            # Send empty arguments if no filter
            return []
