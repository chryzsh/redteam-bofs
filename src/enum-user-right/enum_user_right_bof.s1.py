"""OC2 wrapper for the enum-user-right BOF."""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class EnumUserRightBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("enum-user-right", base_binary_name="enum-user-right")

        self.parser.description = (
            "List accounts assigned an effective Windows user right on the local or remote LSA policy."
        )
        self.parser.add_argument(
            "--computer",
            default="",
            help="Target computer or DC (local by default; \\dc01.corp.local for remote).",
        )
        self.parser.add_argument(
            "--right",
            default="SeMachineAccountPrivilege",
            help="User-right name to query (default: SeMachineAccountPrivilege).",
        )
        self.parser.epilog = (
            "Examples:\n"
            "  enum-user-right\n"
            "  enum-user-right --computer \\\\dc01.corp.local\n"
            "  enum-user-right --computer dc01.corp.local --right SeRemoteInteractiveLogonRight\n\n"
            "Queries the target's current LSA policy, not GPO provenance. Remote access typically requires "
            "administrator-equivalent rights and reachable LSA RPC."
        )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple]:
        parsed = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.WSTR, parsed.computer.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, parsed.right.strip('"').strip("'")),
        ]

    def run(self, arguments: List[str]):
        parsed = self.parser.parse_args(arguments)
        target = parsed.computer or "local computer"
        self.append_response(f"[*] Querying {target} for {parsed.right}\n")
        super().run(arguments)
