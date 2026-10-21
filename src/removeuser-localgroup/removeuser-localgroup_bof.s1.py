from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


def _unc(computername: str) -> str:
    """
    Strip quotes and prepend a leading \\\\ to the server name if it is
    missing, so operators can type `dc01.corp.local` instead of
    `\\\\dc01.corp.local`. Empty and "." (local computer) pass through.
    """
    name = (computername or "").strip('"').strip("'")
    if name and name != "." and not name.startswith("\\\\"):
        name = "\\\\" + name
    return name


class RemoveuserLocalgroupBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "removeuser-localgroup",
            base_binary_name="removeuser-localgroup",
            base_binary_path="."
        )

        self.parser.description = (
            "Remove a user (local or domain) from a local group on a computer."
        )

        self.parser.add_argument(
            "groupname",
            help="Local group name (e.g., 'Administrators', 'Remote Desktop Users')",
        )

        self.parser.add_argument(
            "username",
            help="User to remove - can be local user (e.g., 'john') or domain user (e.g., 'DOMAIN\\john')",
        )

        self.parser.add_argument(
            "--computer",
            dest="computername",
            default="",
            help="Target computer name (e.g., 'COMPUTER01'; default: local computer). The leading \\\\ is optional. Use empty string, '.', or omit for local. Point at a DC to operate on a domain-local group.",
        )

        self.parser.epilog = (
            "removeuser-localgroup removes a user from a local group on a Windows computer.\n"
            "When --computer points at a domain controller, this operates on domain-local groups in AD.\n"
            "The leading \\\\ on the computer name is optional.\n\n"
            "Example usage:\n"
            "  - Remove local user from Administrators group:\n"
            "    removeuser-localgroup Administrators john\n\n"
            "  - Remove domain user from local group:\n"
            "    removeuser-localgroup Administrators DOMAIN\\john\n\n"
            "  - Remove user on remote computer:\n"
            "    removeuser-localgroup 'Remote Desktop Users' john --computer COMPUTER01\n\n"
            "  - Remove domain user from a domain-local group on the DC:\n"
            "    removeuser-localgroup 'Account Operators' CORP\\alice --computer dc01.corp.local"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # Encode arguments as wide strings (WSTR) for the BOF
        # Strip surrounding quotes that OC2 may pass through for args with spaces
        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.groupname.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, parser_arguments.username.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, _unc(parser_arguments.computername)),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)

        # Build informative message
        computername = _unc(parser_arguments.computername)

        if computername and computername != ".":
            target_desc = f"on {computername}"
        else:
            target_desc = "on local computer"

        self.append_response(
            f"removeuser-localgroup - Removing user '{parser_arguments.username}' "
            f"from group '{parser_arguments.groupname}' {target_desc}...\n"
        )

        # Execute the BOF
        super().run(arguments)
