"""
OC2 BOF Script for dsreg-status

Provides a no-argument wrapper around the dsreg-status BOF, which reports the
documented portions of dsregcmd /status from user context.
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask


class DsregStatusBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "dsreg-status",
            base_binary_name="dsreg-status",
        )

        self.parser.description = (
            "Report Microsoft Entra / hybrid join status, tenant metadata, "
            "join certificate details, and proxy configuration without "
            "shelling out to dsregcmd.exe."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  dsreg-status\n\n"
            "Notes:\n"
            "  - Intended for user-context execution on Entra-joined, hybrid-joined,\n"
            "    and workplace-joined devices.\n"
            "  - Phase 1 reports documented API-backed fields only.\n"
            "  - SSO State, Diagnostic Data, and NGC prerequisite checks are\n"
            "    printed as phase-2 placeholders.\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple]:
        self.parser.parse_args(arguments)
        return []

    def run(self, arguments: List[str]):
        self.parser.parse_args(arguments)
        self.append_response("[*] Collecting dsreg join and tenant status\n\n")
        super().run(arguments)
