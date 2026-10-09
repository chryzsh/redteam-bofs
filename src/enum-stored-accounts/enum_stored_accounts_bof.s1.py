"""
OC2 BOF Script for Enum Stored Accounts

Inventory of which accounts have credentials stored on the box and where,
for use right after gaining admin and before touching LSASS or DPAPI.

Sections:
  --services (0x01) - services running as a real account (LSA secret _SC_<name>)
  --tasks    (0x02) - scheduled tasks with LogonType Password
  --dpapi    (0x04) - per-profile Credential Manager blobs, masterkeys, vaults
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class EnumStoredAccountsBOF(BaseBOFTask):
    """
    Enum Stored Accounts BOF - which accounts have secrets stored on this host
    """

    def __init__(self):
        super().__init__(
            "enum-stored-accounts",
            base_binary_name="enum-stored-accounts"
        )

        self.parser.description = (
            "List accounts whose credentials are stored on the host: services "
            "running as a real account, scheduled tasks with a stored password, "
            "and user profiles holding Credential Manager blobs, DPAPI masterkeys "
            "or vault entries. Read-only. Tells you which LSA secrets, task "
            "credentials and user tokens are worth going after."
        )

        self.parser.add_argument(
            "--services",
            action="store_true",
            help="Services whose ObjectName is not LocalSystem / NT AUTHORITY / NT SERVICE"
        )

        self.parser.add_argument(
            "--tasks",
            action="store_true",
            help="Scheduled tasks whose XML has LogonType Password or InteractiveTokenOrPassword"
        )

        self.parser.add_argument(
            "--dpapi",
            action="store_true",
            help="Per-profile Credential Manager blobs, DPAPI masterkeys (SID resolved) and vault entries"
        )

        self.parser.add_argument(
            "--all",
            action="store_true",
            help="All sections (default when no section flag is given)"
        )

        self.parser.add_argument(
            "--users-root",
            default="",
            help="Profiles directory for --dpapi (default: <system drive>\\Users)"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  enum-stored-accounts                    # All sections\n"
            "  enum-stored-accounts --services         # Service accounts only\n"
            "  enum-stored-accounts --tasks            # Tasks with stored passwords only\n"
            "  enum-stored-accounts --dpapi            # Per-profile DPAPI material only\n"
            "  enum-stored-accounts --dpapi --users-root D:\\Profiles\n\n"
            "What each section tells you:\n"
            "  services: the account's password is in LSA secrets as _SC_<ServiceName>.\n"
            "            gMSA and computer accounts (ending in $) are flagged, they have\n"
            "            no password there.\n"
            "  tasks:    the task scheduler stored the account's password; it is\n"
            "            recoverable from the SYSTEM Credential Manager / DPAPI.\n"
            "  dpapi:    which users have Credential Manager blobs and masterkeys, plus\n"
            "            whether that user's hive is loaded (logged on). A loaded hive\n"
            "            means a token to steal; otherwise you need the user's password\n"
            "            or NT hash, or the domain DPAPI backup key.\n\n"
            "Notes:\n"
            "  - Needs admin for the Tasks folder and other users' profiles; without it\n"
            "    only your own profile shows\n"
            "  - Read-only: nothing is decrypted or dumped\n"
            "  - Task scan capped at 3000 files, depth 8; profile scan capped at 256\n"
            "  - Follow up with decrypt-credmanager under the right token, or with\n"
            "    OC2's LSA secret / DPAPI tooling\n\n"
            "OPSEC Considerations:\n"
            "  - Registry reads of HKLM\\SYSTEM\\CurrentControlSet\\Services and HKEY_USERS\n"
            "  - File listing under System32\\Tasks and every profile's AppData\n"
            "  - No process access, no LSASS interaction\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        """
        BOF expects: iZ
        - i: section flags (SERVICES=0x01, TASKS=0x02, DPAPI=0x04, 0 = all)
        - Z: users root (wide string, empty = auto)
        """
        parser_arguments = self.parser.parse_args(arguments)

        flags = 0
        if parser_arguments.all:
            flags = 0xFF
        else:
            if parser_arguments.services:
                flags |= 0x01
            if parser_arguments.tasks:
                flags |= 0x02
            if parser_arguments.dpapi:
                flags |= 0x04
            if flags == 0:
                flags = 0xFF

        users_root = parser_arguments.users_root.strip('"').strip("'")

        return [
            (BOFArgumentEncoding.INT, flags),
            (BOFArgumentEncoding.WSTR, users_root),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)

        sections = []
        if parser_arguments.all or not (
            parser_arguments.services or parser_arguments.tasks or parser_arguments.dpapi
        ):
            sections.append("services, tasks, dpapi")
        else:
            if parser_arguments.services:
                sections.append("services")
            if parser_arguments.tasks:
                sections.append("tasks")
            if parser_arguments.dpapi:
                sections.append("dpapi")

        self.append_response(
            f"[*] Stored Account Inventory - Sections: {', '.join(sections)}\n\n"
        )

        super().run(arguments)
