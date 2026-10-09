import os
from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))


# Valid nCmdShow values for ShowWindow.
# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
VALID_SHOW_MODES = {
    0,   # SW_HIDE
    1,   # SW_SHOWNORMAL / SW_NORMAL
    2,   # SW_SHOWMINIMIZED
    3,   # SW_SHOWMAXIMIZED / SW_MAXIMIZE
    4,   # SW_SHOWNOACTIVATE
    5,   # SW_SHOW
    6,   # SW_MINIMIZE
    7,   # SW_SHOWMINNOACTIVE
    8,   # SW_SHOWNA
    9,   # SW_RESTORE
    10,  # SW_SHOWDEFAULT
    11,  # SW_FORCEMINIMIZE
}


class LNKgeneratorBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("LNKgenerator", base_binary_name="LNKgenerator-BOF")
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Create an LNK (shortcut) file on the target for post-exploitation activities."
        )

        self.parser.add_argument(
            "targetFile",
            help="Full path of the executable the LNK will launch.",
        )
        self.parser.add_argument(
            "targetArgs",
            help='Arguments passed to the target executable. Use "" for none.',
        )
        self.parser.add_argument(
            "lnkFileLocation",
            help="Full path where the .lnk file will be written.",
        )
        self.parser.add_argument(
            "description",
            help='Comment/description set on the shortcut. Use "" for none.',
        )
        self.parser.add_argument(
            "curDir",
            help='Working directory ("Start in") for the shortcut. Use "" for none.',
        )
        self.parser.add_argument(
            "iconFile",
            help='Path to the file containing the icon resource. Use "" for none.',
        )
        self.parser.add_argument(
            "iShowmode",
            nargs="?",
            type=int,
            default=1,
            help="ShowWindow nCmdShow value (default: 1 = SW_NORMAL).",
        )
        self.parser.add_argument(
            "iIconindex",
            nargs="?",
            type=int,
            default=0,
            help="Zero-based icon index inside iconFile (default: 0).",
        )

        self.parser.epilog = (
            "Example usage:\n"
            '  LNKgenerator "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" '
            '"--remote-debugging-port=9222 --remote-allow-origins=* --user-data-dir=C:\\Users\\Public\\Documents" '
            '"C:\\Users\\defaultuser\\Desktop\\test.lnk" "Internet Access" '
            '"C:\\Program Files\\Google\\Chrome\\Application" '
            '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" 1 0\n\n'
            "Notes:\n"
            "  - All six string arguments are required. Pass \"\" for fields you want to leave blank.\n"
            "  - iShowmode follows the ShowWindow nCmdShow values (0-11).\n"
            "  - LNK Show Modes: "
            "https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        if not parser_arguments.targetFile:
            raise TaskInvalidArgumentsException("targetFile must not be empty.")

        if not parser_arguments.lnkFileLocation:
            raise TaskInvalidArgumentsException("lnkFileLocation must not be empty.")

        if parser_arguments.iShowmode not in VALID_SHOW_MODES:
            raise TaskInvalidArgumentsException(
                f"Invalid iShowmode: {parser_arguments.iShowmode}. "
                f"Must be one of {sorted(VALID_SHOW_MODES)} (ShowWindow nCmdShow values)."
            )

        if parser_arguments.iIconindex < 0:
            raise TaskInvalidArgumentsException(
                f"Invalid iIconindex: {parser_arguments.iIconindex}. Must be zero or positive."
            )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # BOF expects: ZZZZZZii
        # (targetFile, targetArgs, lnkFileLocation, description, curDir, iconFile,
        #  iShowmode, iIconindex)
        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.targetFile),
            (BOFArgumentEncoding.WSTR, parser_arguments.targetArgs),
            (BOFArgumentEncoding.WSTR, parser_arguments.lnkFileLocation),
            (BOFArgumentEncoding.WSTR, parser_arguments.description),
            (BOFArgumentEncoding.WSTR, parser_arguments.curDir),
            (BOFArgumentEncoding.WSTR, parser_arguments.iconFile),
            (BOFArgumentEncoding.INT, parser_arguments.iShowmode),
            (BOFArgumentEncoding.INT, parser_arguments.iIconindex),
        ]
